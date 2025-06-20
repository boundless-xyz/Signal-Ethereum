use clap::{Parser, ValueEnum};
use ethereum_consensus::electra;
use methods::BEACON_GUEST_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};
use ssz_rs::prelude::*;
use std::{
    fmt::{self, Display},
    fs,
    path::PathBuf,
};
use tracing::info;
use url::Url;
use z_core::{
    verify, CacheStateProvider, Checkpoint, ConsensusState, Ctx, Epoch, GuestContext, HostContext,
    HostStateReader, Input, InputBuilder, PreflightStateReader, StateInput, StateProvider,
    StateReader,
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
    let context: HostContext = electra::Context::for_mainnet().into();

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

    let reader = HostStateReader::new(CacheStateProvider::new(provider));

    match args.command {
        Command::Verify { mode, iterations } => {
            let trusted_state =
                reader.state_at_slot(context.compute_start_slot_at_epoch(args.trusted_epoch))?;
            let epoch_boundary_slot = trusted_state.latest_block_header().slot;
            let trusted_beacon_block = beacon_client.get_block(epoch_boundary_slot).await?.unwrap();
            assert_eq!(
                trusted_beacon_block.state_root(),
                trusted_state.hash_tree_root().unwrap()
            );
            let mut trusted_checkpoint = Checkpoint {
                epoch: args.trusted_epoch,
                root: trusted_beacon_block.hash_tree_root()?,
            };
            info!("Trusted checkpoint: {}", trusted_checkpoint);

            let builder = InputBuilder::new(context, beacon_client.clone());

            for i in 0..iterations {
                tracing::info!("Iteration: {}", i);
                let input = builder.build(trusted_checkpoint).await?;
                tracing::debug!("Input: {:?}", input);

                let consensus_state = run_verify(mode, &reader, input.clone())?; // will panic if verification fails
                trusted_checkpoint = consensus_state.finalized_checkpoint;
            }
        }
    }

    Ok(())
}

fn run_verify<R: StateReader + StateProvider>(
    mode: ExecMode,
    host_reader: &R,
    input: Input,
) -> anyhow::Result<ConsensusState> {
    info!("Running Verification in mode: {mode}");

    let reader = PreflightStateReader::new(host_reader, input.state.finalized_checkpoint);
    let consensus_state = verify(&reader, input.clone()).unwrap(); // will panic if verification fails
    info!("Native Verification Success!");

    if mode == ExecMode::Ssz || mode == ExecMode::R0vm {
        let state_input = reader.to_input();
        let ssz_reader = state_input
            .clone()
            .into_state_reader(&GuestContext, input.state.finalized_checkpoint)?;
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

fn execute_guest_program(state_input: StateInput, input: Input) -> Vec<u8> {
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
