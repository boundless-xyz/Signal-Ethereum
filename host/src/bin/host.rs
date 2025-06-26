// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{Context, ensure};
use clap::{Parser, ValueEnum};
use host::{
    beacon_client::BeaconClient,
    host_state_reader::HostStateReader,
    preflight_state_reader::PreflightStateReader,
    state_provider::{CacheStateProvider, PersistentApiStateProvider, StateProvider},
    test_utils::AssertStateReader,
};
use methods::{MAINNET_ELF, SEPOLIA_ELF};
use risc0_zkvm::{ExecutorEnv, default_executor};
use serde::Serialize;
use ssz_rs::HashTreeRoot;
use std::{
    fmt::{self, Display},
    fs::{self, File},
    io::Write,
    path::PathBuf,
};
use tracing::{debug, info, warn};
use url::Url;
use z_core::{
    ChainReader, Checkpoint, Config, ConsensusState, DEFAULT_CONFIG, Epoch, EthSpec, Input,
    InputBuilder, MainnetEthSpec, Slot, StateInput, StateReader, verify,
};

// all chains use the mainnet preset
type Spec = MainnetEthSpec;

/// CLI for generating and submitting ZKasper proofs
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Beacon API URL
    #[clap(long, env = "BEACON_RPC_URL")]
    beacon_api: Url,

    /// Max Beacon API requests per second (0 to disable rate limit)
    #[clap(long, short, default_value_t = 0)]
    rps: u32,

    /// Network name
    #[clap(long, short, default_value_t = Network::Sepolia)]
    network: Network,

    /// Directory to store data
    #[clap(long, short, default_value = "./data")]
    data_dir: PathBuf,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Eq, PartialEq, Debug, Clone, Copy, ValueEnum)]
enum ExecMode {
    Native,
    Ssz,
    R0vm,
}

impl Display for ExecMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecMode::Native => write!(f, "native"),
            ExecMode::Ssz => write!(f, "ssz"),
            ExecMode::R0vm => write!(f, "r0vm"),
        }
    }
}

/// Subcommands of the publisher CLI.
#[derive(Parser, Debug)]
enum Command {
    /// Runs FFG verification in R0VM Executor
    #[clap(name = "verify")]
    Verify {
        /// If true, runs in R0VM as well, otherwise runs natively
        #[clap(long, default_value_t = ExecMode::Native)]
        mode: ExecMode,
        /// Trusted epoch
        #[clap(long)]
        trusted_epoch: Epoch,
    },
    /// Attempts to sync a trusted block root to the latest state available on the Beacon API
    /// Optionally can log any places the resulting consensus state diverges from the chain for debugging
    #[clap(name = "sync")]
    Sync {
        /// If true, runs in R0VM as well, otherwise runs natively
        #[clap(long, default_value_t = ExecMode::Native)]
        mode: ExecMode,

        /// Boostrap from the consensus state that is part of the beacon state at this slot
        #[clap(long)]
        start_slot: Slot,

        /// Optional log file to write sync status to
        #[clap(long, short)]
        log_path: Option<PathBuf>,
    },
}

/// Enum for network selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Network {
    Mainnet,
    Sepolia,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Sepolia => write!(f, "sepolia"),
            Network::Mainnet => write!(f, "mainnet"),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();
    let args = Args::try_parse()?;

    let beacon_client = BeaconClient::builder(args.beacon_api)
        .with_cache(args.data_dir.join("http"))
        .with_rate_limit(args.rps)
        .build();

    let state_dir = args.data_dir.join(args.network.to_string()).join("states");
    fs::create_dir_all(&state_dir)?;

    // load the corresponding chain spec
    let spec = match args.network {
        Network::Sepolia => chainspec::sepolia_spec(),
        Network::Mainnet => chainspec::mainnet_spec(),
    };

    let provider = PersistentApiStateProvider::<Spec>::new(&state_dir, beacon_client.clone())?;
    let reader = HostStateReader::new(spec, CacheStateProvider::new(provider));

    match args.command {
        Command::Verify {
            mode,
            trusted_epoch,
        } => {
            let trusted_state =
                reader.state_at_slot(trusted_epoch.start_slot(Spec::slots_per_epoch()))?;
            let epoch_boundary_slot = trusted_state.latest_block_header().slot;
            let trusted_beacon_block = beacon_client
                .get_block(epoch_boundary_slot)
                .await?
                .with_context(|| format!("block {} not found", epoch_boundary_slot))?;
            assert_eq!(
                trusted_beacon_block.state_root(),
                trusted_state.hash_tree_root()?
            );
            let trusted_checkpoint =
                Checkpoint::new(trusted_epoch, trusted_beacon_block.hash_tree_root()?);
            info!("Trusted checkpoint: {}", trusted_checkpoint);

            let builder = InputBuilder::<Spec, _>::new(beacon_client.clone());

            let (input, _) = builder.build(trusted_checkpoint).await?;
            info!("Pre-state: {:#?}", input.consensus_state);
            debug!("Input: {:?}", input);

            let post_state =
                run_verify(args.network, mode, &DEFAULT_CONFIG, &reader, input.clone())?;
            info!("Post-state: {:#?}", post_state);
        }
        Command::Sync {
            mode,
            start_slot,
            log_path,
        } => {
            run_sync(
                reader,
                start_slot,
                &beacon_client,
                args.network,
                mode,
                log_path,
            )
            .await?;
        }
    }

    Ok(())
}

async fn run_sync<E: EthSpec + Serialize>(
    sr: HostStateReader<CacheStateProvider<PersistentApiStateProvider<E>>>,
    start_slot: Slot,
    beacon_client: &BeaconClient,
    network: Network,
    mode: ExecMode,
    log_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    info!("Running Sync in mode: {mode}");

    let logfile = match log_path {
        Some(path) => {
            if let Some(path) = path.parent() {
                fs::create_dir_all(path).context("Failed to create log directory")?;
            };
            let file = File::create(&path).context("Failed to create log file")?;
            info!("Logging sync progress to: {}", path.display());
            Some(file)
        }
        None => None,
    };

    let mut consensus_state = beacon_client.get_consensus_state(start_slot).await?;
    info!("Initial Consensus State: {:#?}", consensus_state);
    let input_builder = InputBuilder::<E, _>::new(beacon_client.clone());

    loop {
        let (input, expected_state) = input_builder
            .build(consensus_state.finalized_checkpoint)
            .await?;
        debug!("Input: {:?}", input);
        let msg = match run_verify(network, mode, &DEFAULT_CONFIG, &sr, input.clone()) {
            Ok(state) => {
                info!("Verification successful. New state: {:#?}", &state);
                if state != expected_state {
                    format!("New state mismatch: expected {expected_state:?}, got {state:?}")
                } else {
                    "Ok".to_string()
                }
            }
            Err(e) => {
                format!("Verification failed: {e}")
            }
        };
        if let Some(logfile) = &logfile {
            log_sync(logfile, &consensus_state, &expected_state, &msg);
        };

        consensus_state = expected_state;

        // uncache old states
        let provider = sr.provider().inner();
        provider.clear_states_before(consensus_state.finalized_checkpoint.epoch())?;
    }
}

fn run_verify<E: EthSpec + Serialize, R: StateReader<Spec = E> + StateProvider<Spec = E>>(
    network: Network,
    mode: ExecMode,
    cfg: &Config,
    host_reader: &R,
    input: Input<E>,
) -> anyhow::Result<ConsensusState> {
    info!("Verification mode: {mode}");

    info!("Running preflight");
    let reader = PreflightStateReader::new(host_reader, input.consensus_state.finalized_checkpoint);
    let consensus_state = verify(cfg, &reader, input.clone()).context("preflight failed")?;
    info!("Preflight succeeded");

    if mode == ExecMode::Ssz || mode == ExecMode::R0vm {
        info!("Running host verification");
        let state_input = reader.to_input();

        let state_bytes = bincode::serialize(&state_input).context("failed to serialize state")?;
        debug!(len = state_bytes.len(), "State serialized");
        let input_bytes = bincode::serialize(&input).context("failed to serialize input")?;
        debug!(len = input_bytes.len(), "Input serialized");

        let guest_input: Input<E> =
            bincode::deserialize(&input_bytes).context("failed to deserialize input")?;
        let guest_reader = {
            let state_input: StateInput =
                bincode::deserialize(&state_bytes).context("failed to deserialize state")?;
            state_input
                .into_state_reader(host_reader.chain_spec().clone(), &input.consensus_state)
                .context("failed to validate input")?
        };

        // use the AssertStateReader to detect input issues already on the host
        let host_consensus_state = verify(
            cfg,
            &AssertStateReader::new(&guest_reader, &reader),
            guest_input,
        )
        .context("host verification failed")?;
        ensure!(host_consensus_state == consensus_state);
        info!("Host verification succeeded");

        if mode == ExecMode::R0vm {
            info!("Executing guest verification");
            let journal = execute_guest_program(network, state_bytes, input_bytes)
                .context("guest verification failed")?;
            // decode the journal
            let (pre_state, post_state) = journal.split_at(ConsensusState::abi_encoded_size());
            let pre_state = ConsensusState::abi_decode(pre_state).context("invalid journal")?;
            let post_state = ConsensusState::abi_decode(post_state).context("invalid journal")?;
            ensure!(pre_state == input.consensus_state);
            ensure!(post_state == consensus_state);
            info!("Guest verification succeeded");
        }
    }

    info!("New consensus state: {:#?}", consensus_state);

    Ok(consensus_state)
}

fn execute_guest_program(
    network: Network,
    state: impl AsRef<[u8]>,
    input: impl AsRef<[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let env = ExecutorEnv::builder()
        .write_frame(state.as_ref())
        .write_frame(input.as_ref())
        .build()?;
    let elf = match network {
        Network::Mainnet => MAINNET_ELF,
        Network::Sepolia => SEPOLIA_ELF,
    };
    let session_info = default_executor().execute(env, elf)?;
    debug!(cycles = session_info.cycles(), "Session info");

    Ok(session_info.journal.bytes)
}

fn log_sync(file: &File, from: &ConsensusState, to: &ConsensusState, message: &str) {
    let mut file = file;
    writeln!(file, "{:?} -> {:?}\t{}", from, to, message).expect("Failed to write to log file");
    warn!("Sync status logged: {}", message);
}
