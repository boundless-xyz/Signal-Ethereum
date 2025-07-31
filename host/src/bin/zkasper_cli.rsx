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
    BeaconClient, CacheStateProvider, ChainReader, InputBuilder, PersistentApiStateProvider,
    StateProvider, host_state_reader::HostStateReader,
    preflight_state_reader::PreflightStateReader,
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
use tracing::{debug, info, level_filters::LevelFilter, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;
use z_core::{
    Checkpoint, Config, ConsensusState, DEFAULT_CONFIG, Epoch, EthSpec, InputReader,
    MainnetEthSpec, Slot, StateInput, abi, verify,
};

// all chains use the mainnet preset
type Spec = MainnetEthSpec;

/// CLI for generating and submitting proofs
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

    /// Log level (error, warn, info, debug, trace)
    #[clap(long, env = "LOG_LEVEL", global = true, default_value = "info")]
    log_level: LevelFilter,
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
    /// Prepares the input for the R0VM Executor for proving a state transition from a consensus state with the given finalized epoch
    BuildInput {
        /// Initial trusted finalized epoch. This is the finalized_epoch field of the pre ConsensusState
        #[clap(long)]
        finalized_epoch: Epoch,

        /// If set the inputs will be built continuously for each successive finalization
        /// and will follow the chain as new finalizations occur
        #[clap(long, short)]
        continuous: bool,

        /// How frequently to poll for new finalizations once it is detected we are at the tip
        #[clap(long, default_value_t = 60)]
        retry_interval: u64,
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
    let args = Args::try_parse()?;

    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(args.log_level.into())
                .from_env_lossy(),
        )
        .init();

    let beacon_client = BeaconClient::builder(args.beacon_api)
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
    let reader = HostStateReader::new(
        spec,
        CacheStateProvider::new(provider),
        beacon_client.clone(),
    );

    match args.command {
        Command::Verify {
            mode,
            trusted_epoch,
        } => {
            let (state_bytes, input_bytes, pre_state, _post_state, _) =
                prepare_input(trusted_epoch, &reader, &beacon_client).await?;

            let post_state = run_verify(
                pre_state,
                &state_bytes,
                &input_bytes,
                args.network,
                mode,
                &DEFAULT_CONFIG,
                &reader,
            )?;
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
        Command::BuildInput {
            mut finalized_epoch,
            continuous,
            retry_interval,
        } => loop {
            // check the chain has progressed far enough to build an input
            let chain_finalized_epoch = beacon_client
                .get_finality_checkpoints("head")
                .await?
                .finalized
                .epoch;

            // willem: We need this + 1 because the search for attestations probably looks
            // 1 epoch further ahead than it needs to in most cases and will go past the end of the chain
            if chain_finalized_epoch < finalized_epoch.as_u64() + 1 {
                warn!(
                    "Chain finalized epoch {} is less than the requested finalized epoch {}. Waiting for chain to progress.",
                    chain_finalized_epoch, finalized_epoch
                );
                tokio::time::sleep(std::time::Duration::from_secs(retry_interval)).await;
                continue;
            }

            let (state_bytes, input_bytes, pre_state, post_state, finalized_slot) =
                prepare_input(finalized_epoch, &reader, &beacon_client).await?;

            let encoded_input = encode_input_stdin(&state_bytes, &input_bytes)
                .context("failed to prepare input")?;

            let inputs_dir = args.data_dir.join(args.network.to_string()).join("inputs");
            fs::create_dir_all(&inputs_dir).context("failed to create encoded inputs directory")?;
            let mut input_file =
                File::create(inputs_dir.join(format!("{finalized_epoch}_stdin.bin")))
                    .context("failed to create encoded input file")?;

            let journals_dir = args
                .data_dir
                .join(args.network.to_string())
                .join("journals");
            fs::create_dir_all(&journals_dir).context("failed to create journals directory")?;
            let mut journal_file =
                File::create(journals_dir.join(format!("{finalized_epoch}_journal.bin")))
                    .context("failed to create journal file")?;

            input_file
                .write_all(&encoded_input)
                .context("failed to write input to file")?;
            info!("Input written to {:?}", input_file);

            let journal = abi::Journal::new(&pre_state, &post_state, finalized_slot);

            journal_file
                .write_all(&journal.encode())
                .context("failed to write journal to file")?;

            info!("Journal written to {:?}", journal_file);

            // update for next iteration
            finalized_epoch = post_state.finalized_checkpoint().epoch();

            if !continuous {
                break;
            }
        },
    }

    Ok(())
}

async fn run_sync<E: EthSpec + Serialize, CR: ChainReader>(
    sr: HostStateReader<E, CacheStateProvider<PersistentApiStateProvider<E>>, CR>,
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

    loop {
        let (state_bytes, input_bytes, pre_state, expected_state, _) = prepare_input(
            consensus_state.finalized_checkpoint().epoch(),
            &sr,
            beacon_client,
        )
        .await?;

        let msg = match run_verify(
            pre_state,
            state_bytes,
            input_bytes,
            network,
            mode,
            &DEFAULT_CONFIG,
            &sr,
        ) {
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
        provider.clear_states_before(consensus_state.finalized_checkpoint().epoch())?;
    }
}

async fn prepare_input<E: EthSpec + Serialize, S: InputReader<Spec = E> + StateProvider<Spec = E>>(
    finalized_epoch: Epoch,
    reader: &S,
    beacon_client: &BeaconClient,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, ConsensusState, ConsensusState, u64)>
where
    <S as InputReader>::Error: Sync + Send + 'static,
{
    let trusted_state = reader.state_at_epoch_boundary(finalized_epoch)?;
    let epoch_boundary_slot = trusted_state.latest_block_header().slot;
    let trusted_beacon_block = beacon_client
        .get_block(epoch_boundary_slot)
        .await?
        .with_context(|| format!("block {epoch_boundary_slot} not found"))?;
    assert_eq!(
        trusted_beacon_block.state_root(),
        trusted_state.hash_tree_root()?
    );
    let trusted_checkpoint =
        Checkpoint::new(finalized_epoch, trusted_beacon_block.hash_tree_root()?);
    info!("Trusted checkpoint: {}", trusted_checkpoint);

    let builder = InputBuilder::<E, _>::new(beacon_client.clone());

    let (input, _) = builder.build(trusted_checkpoint).await?;

    info!("Running preflight");
    let reader = PreflightStateReader::new(reader, input.consensus_state.finalized_checkpoint());
    let post_state = verify(&DEFAULT_CONFIG, &reader).context("preflight failed")?;
    info!("Preflight succeeded");

    let state_input = reader.to_input()?;

    let state_bytes = bincode::serialize(&state_input).context("failed to serialize state")?;
    debug!(len = state_bytes.len(), "State serialized");
    let input_bytes = bincode::serialize(&input).context("failed to serialize input")?;

    Ok((
        state_bytes,
        input_bytes,
        input.consensus_state,
        post_state,
        input.finalized_block.slot,
    ))
}

fn run_verify<E: EthSpec + Serialize, R: InputReader<Spec = E> + StateProvider<Spec = E>>(
    pre_state: ConsensusState,
    state_bytes: impl AsRef<[u8]>,
    input_bytes: impl AsRef<[u8]>,
    network: Network,
    mode: ExecMode,
    cfg: &Config,
    host_reader: &R,
) -> anyhow::Result<ConsensusState> {
    let guest_reader = {
        let state_input: StateInput<E> =
            bincode::deserialize(state_bytes.as_ref()).context("failed to deserialize state")?;
        state_input
            .into_state_reader(host_reader.chain_spec().clone())
            .context("failed to validate input")?
    };

    // use the AssertStateReader to detect input issues already on the host
    let post_state = verify(cfg, &guest_reader).context("host verification failed")?;

    info!("Host verification succeeded");

    if mode == ExecMode::R0vm {
        info!("Executing guest verification");
        let journal = execute_guest_program(network, state_bytes, input_bytes)
            .context("guest verification failed")?;
        // decode the journal
        let (guest_pre_state, guest_post_state) =
            journal.split_at(ConsensusState::abi_encoded_size());
        let guest_pre_state =
            ConsensusState::abi_decode(guest_pre_state).context("invalid journal")?;
        let guest_post_state =
            ConsensusState::abi_decode(guest_post_state).context("invalid journal")?;
        ensure!(guest_post_state == post_state);
        ensure!(guest_pre_state == pre_state);
        info!("Guest verification succeeded");
    }

    info!("New consensus state: {:#?}", post_state);

    Ok(post_state)
}

/// Produce the full stdin stream expected by the consensus client.
fn encode_input_stdin(
    state_bytes: impl AsRef<[u8]>,
    input_bytes: impl AsRef<[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let mut buffer = vec![];

    fn write_frame(buffer: &mut Vec<u8>, state_bytes: impl AsRef<[u8]>) -> anyhow::Result<()> {
        use std::io::Write;
        let data = state_bytes.as_ref();
        let len = data.len() as u32;
        buffer.write_all(&len.to_le_bytes())?;
        buffer.write_all(data.as_ref())?;
        Ok(())
    }

    write_frame(&mut buffer, state_bytes)?;
    write_frame(&mut buffer, input_bytes)?;

    Ok(buffer)
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
    writeln!(file, "{from:?} -> {to:?}\t{message}").expect("Failed to write to log file");
    warn!("Sync status logged: {}", message);
}
