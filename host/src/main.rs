use beacon_api_client::{BlockId, StateId};
use clap::{Parser, ValueEnum};
use ethereum_consensus::electra::{Context, Epoch};
use methods::BEACON_GUEST_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};
use ssz_rs::prelude::*;
use std::{
    fmt::{self, Display},
    fs,
    path::PathBuf,
};
use tracing::{info, warn};
use url::Url;
use z_core::{
    build_input, verify, ChainReader, ConsensusState, GuestContext, HostReaderBuilder, Input,
    PreflightStateReader, Root, StateInput,
};
use z_core_test_utils::AssertStateReader;

pub mod beacon_client;

pub mod state_provider;

use crate::{beacon_client::BeaconClient, state_provider::PersistentApiStateProvider};

/// CLI for generating and submitting ZKasper proofs
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Trusted epoch
    #[clap(long)]
    trusted_epoch: Epoch,

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
        /// Number of iterations to run
        #[clap(short('i'), long, default_value_t = 1)]
        iterations: u64,
        /// If the provided trusted epoch does not have its state cached, use this block root to find the state
        #[clap(long)]
        trusted_block_root: Option<Root>,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    // Note: The part of the context we use for mainnet and sepolia is the same.
    let context = Context::for_mainnet();

    let beacon_client = BeaconClient::builder(args.beacon_api)
        .with_cache(args.data_dir.join("http"))
        .with_rate_limit(args.rps)
        .build();

    let state_dir = args.data_dir.join(args.network.to_string()).join("states");
    fs::create_dir_all(&state_dir)?;

    let provider = PersistentApiStateProvider::new(
        &state_dir,
        beacon_client.clone(),
        &context.clone().into(),
    )?;

    let reader = HostReaderBuilder::new(provider.clone().into(), context.clone().into());

    match args.command {
        Command::Verify {
            mode,
            iterations,
            trusted_block_root,
        } => {
            let trusted_state = match reader.get_beacon_state_by_epoch(args.trusted_epoch) {
                Ok(state) => state,
                Err(_) => {
                    let block = if let Some(root) = trusted_block_root {
                        warn!(
                            "No state found for epoch {}, trying to fetch via trusted block root: {}",
                            args.trusted_epoch, root
                        );

                        beacon_client.get_block(BlockId::Root(root)).await?
                    } else {
                        return Err(anyhow::anyhow!(
                            "No state found for epoch {}, and no trusted block root provided",
                            args.trusted_epoch
                        ));
                    };

                    provider.cache_state_at(StateId::Root(block.state_root()))?;

                    // TODO(ec2): We should check if the state corresponds to the trusted epoch
                    reader
                        .get_beacon_state_by_epoch(args.trusted_epoch)
                        .expect("Failed to establish trusted state")
                }
            };

            // Find the first ConsensusState in which the trusted epoch is the finalized checkpoint
            // This will be our initial consensus state
            let mut consensus_state = ConsensusState::default();
            let trusted_state_slot = trusted_state.slot();
            for i in (trusted_state_slot + context.slots_per_epoch
                ..=trusted_state_slot + context.slots_per_epoch * 3)
                .step_by(context.slots_per_epoch as usize)
            {
                let curr_state = beacon_client.get_consensus_state(StateId::Slot(i)).await?;
                if curr_state.finalized_checkpoint.epoch == args.trusted_epoch {
                    consensus_state = curr_state;
                    break;
                }
            }
            assert!(
                consensus_state != ConsensusState::default(),
                "No consensus state found for trusted epoch"
            );
            info!(
                "Trusted Beacon State slot: {}, root: {}",
                trusted_state.slot(),
                trusted_state.hash_tree_root().unwrap()
            );

            for i in 0..iterations {
                tracing::info!("Iteration: {}", i);
                let input = build_input(&beacon_client, consensus_state.clone()).await?;
                tracing::debug!("Input: {:?}", input);

                consensus_state = run_verify(mode, &reader, input.clone())?; // will panic if verification fails
            }
        }
    }

    Ok(())
}

fn run_verify(
    mode: ExecMode,
    host_reader: &HostReaderBuilder,
    input: Input,
) -> anyhow::Result<ConsensusState> {
    info!("Running Verification in mode: {mode}");

    info!("Performing the pre-flight");
    let epoch_reader = host_reader.build_at_epoch(input.consensus_state.finalized_checkpoint.epoch);
    let reader = PreflightStateReader::new(&epoch_reader);
    let consensus_state = verify(&reader, input.clone()).unwrap(); // will panic if verification fails
    info!("pre-flight and native verification success!");

    if mode == ExecMode::Ssz || mode == ExecMode::R0vm {
        let state_input = reader.to_input(host_reader)?;
        let ssz_reader = state_input
            .clone()
            .into_state_reader(Some(input.trusted_checkpoint_state_root), &GuestContext)?;
        let ssz_consensus_state =
            verify(&AssertStateReader::new(&ssz_reader, &reader), input.clone()).unwrap(); // will panic if verification fails
        info!("Ssz Verification Success!");
        assert_eq!(
            ssz_consensus_state, consensus_state,
            "Native and Ssz output mismatch"
        );

        if mode == ExecMode::R0vm {
            let journal = execute_guest_program(&state_input, input);
            info!("Journal: {:?}", journal);
        }
    }

    tracing::info!("Consensus state: {:#?}", consensus_state);

    Ok(consensus_state)
}

fn execute_guest_program(state_input: &StateInput, input: Input) -> Vec<u8> {
    info!("Executing guest program");
    let ssz_reader = bincode::serialize(&state_input).unwrap();
    info!("Serialized SszStateReader: {} bytes", ssz_reader.len());
    let input = bincode::serialize(&input).unwrap();
    info!("Serialized Input: {} bytes", input.len());
    info!("Total Input: {} bytes", ssz_reader.len() + input.len());
    let env = ExecutorEnv::builder()
        .write_frame(&ssz_reader)
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
