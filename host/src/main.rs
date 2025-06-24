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

use beacon_types::EthSpec;
use clap::{Parser, ValueEnum};
use methods::BEACON_GUEST_ELF;
use risc0_zkvm::{ExecutorEnv, default_executor};
use serde::Serialize;
use ssz_rs::prelude::*;
use std::{
    fmt::{self, Display},
    fs::{self, File},
    io::Write,
    path::PathBuf,
};
use tracing::{info, warn};
use url::Url;
use z_core::{
    CacheStateProvider, ChainReader, Checkpoint, ConsensusState, Epoch, HostStateReader, Input,
    InputBuilder, MainnetEthSpec, PreflightStateReader, Slot, StateInput, StateProvider,
    StateReader, verify,
};
use z_core_test_utils::AssertStateReader;

pub mod beacon_client;

pub mod state_provider;

use crate::{beacon_client::BeaconClient, state_provider::PersistentApiStateProvider};

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
        /// Number of iterations to run
        #[clap(short('i'), long, default_value_t = 1)]
        iterations: u64,
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
    Sepolia,
    Mainnet,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Sepolia => write!(f, "sepolia"),
            Network::Mainnet => write!(f, "mainnet"),
        }
    }
}

type Spec = MainnetEthSpec;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    let beacon_client = BeaconClient::builder(args.beacon_api)
        .with_cache(args.data_dir.join("http"))
        .with_rate_limit(args.rps)
        .build();

    let state_dir = args.data_dir.join(args.network.to_string()).join("states");
    fs::create_dir_all(&state_dir)?;

    let provider = PersistentApiStateProvider::<Spec>::new(&state_dir, beacon_client.clone())?;

    let reader = HostStateReader::new(CacheStateProvider::new(provider.clone()));

    match args.command {
        Command::Verify {
            mode,
            iterations,
            trusted_epoch,
        } => {
            let trusted_state =
                reader.state_at_slot(trusted_epoch.start_slot(Spec::slots_per_epoch()))?;
            let epoch_boundary_slot = trusted_state.latest_block_header().slot;
            let trusted_beacon_block = beacon_client.get_block(epoch_boundary_slot).await?.unwrap();
            assert_eq!(
                trusted_beacon_block.state_root(),
                trusted_state.hash_tree_root().unwrap()
            );
            let mut trusted_checkpoint =
                Checkpoint::new(trusted_epoch, trusted_beacon_block.hash_tree_root()?);
            info!("Trusted checkpoint: {}", trusted_checkpoint);

            let builder = InputBuilder::<Spec, _>::new(beacon_client.clone());

            for i in 0..iterations {
                tracing::info!("Iteration: {}", i);
                let (input, _) = builder.build(trusted_checkpoint).await?;
                tracing::debug!("Input: {:?}", input);

                let consensus_state = run_verify(mode, &reader, input.clone())?; // will panic if verification fails
                trusted_checkpoint = consensus_state.finalized_checkpoint;
            }
        }
        Command::Sync {
            mode,
            start_slot,
            log_path,
        } => {
            run_sync::<Spec>(&provider, start_slot, &beacon_client, mode, log_path).await?;
        }
    }

    Ok(())
}

async fn run_sync<E: EthSpec + Serialize>(
    provider: &PersistentApiStateProvider<E>,
    start_slot: Slot,
    beacon_client: &BeaconClient,
    mode: ExecMode,
    log_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    info!("Running Sync in mode: {mode}");

    let logfile = log_path.map(|path| {
        fs::create_dir_all(path.parent().unwrap()).expect("Failed to create log directory");
        let file = File::create(&path).expect("Failed to create log file");
        info!("Logging sync progress to: {}", path.display());
        file
    });

    let mut consensus_state = beacon_client.get_consensus_state(start_slot).await?;
    info!("Initial Consensus State: {:#?}", consensus_state);
    let sr = HostStateReader::<PersistentApiStateProvider<E>>::new(provider.clone());

    let input_builder = InputBuilder::new(beacon_client.clone());

    loop {
        let (input, expected_state) = input_builder
            .build(consensus_state.finalized_checkpoint)
            .await?;
        tracing::debug!("Input: {:?}", input);
        let msg = match run_verify(mode, &sr, input.clone()) {
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
        provider.clear_states_before(consensus_state.finalized_checkpoint.epoch())?;
    }
}

fn run_verify<E: EthSpec + Serialize, R: StateReader<Spec = E> + StateProvider<Spec = E>>(
    mode: ExecMode,
    host_reader: &R,
    input: Input<E>,
) -> anyhow::Result<ConsensusState> {
    info!("Running Verification in mode: {mode}");

    let reader = PreflightStateReader::new(host_reader, input.consensus_state.finalized_checkpoint);
    let consensus_state = verify(&reader, input.clone()).unwrap(); // will panic if verification fails
    info!("Native Verification Success!");

    if mode == ExecMode::Ssz || mode == ExecMode::R0vm {
        let state_input = reader.to_input();
        let ssz_reader = state_input
            .clone()
            .into_state_reader(&input.consensus_state)?;
        let ssz_consensus_state =
            verify(&AssertStateReader::new(&ssz_reader, &reader), input.clone()).unwrap(); // will panic if verification fails
        info!("Ssz Verification Success!");
        assert_eq!(
            ssz_consensus_state, consensus_state,
            "Native and Ssz output mismatch"
        );

        if mode == ExecMode::R0vm {
            let journal = execute_guest_program(state_input, input);
            info!("Journal: {:?}", journal);
        }
    }

    tracing::info!("Consensus state: {:#?}", consensus_state);

    Ok(consensus_state)
}

fn execute_guest_program<E: EthSpec + Serialize>(
    state_input: StateInput,
    input: Input<E>,
) -> Vec<u8> {
    info!("Executing guest program");
    let state_input = bincode::serialize(&state_input).unwrap();
    info!("Serialized SszStateReader: {} bytes", state_input.len());
    let input = bincode::serialize(&input).unwrap();
    info!("Serialized Input: {} bytes", input.len());
    info!("Total Input: {} bytes", state_input.len() + input.len());
    let env = ExecutorEnv::builder()
        .write_frame(&state_input)
        .write_frame(&input)
        .build()
        .unwrap();
    let executor = default_executor();
    let session_info = executor
        .execute(env, BEACON_GUEST_ELF)
        .expect("failed to execute guest program");
    info!("{} user cycles executed.", session_info.cycles());
    session_info.journal.bytes
}

fn log_sync(file: &File, from: &ConsensusState, to: &ConsensusState, message: &str) {
    let mut file = file;
    writeln!(file, "{:?} -> {:?}\t{}", from, to, message).expect("Failed to write to log file");
    warn!("Sync status logged: {}", message);
}
