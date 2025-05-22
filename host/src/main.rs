use beacon_api_client::{BlockId, StateId};
use clap::{Parser, ValueEnum};
use ethereum_consensus::electra::{Checkpoint, Context, Epoch};
use futures::StreamExt;
use methods::BEACON_GUEST_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};
use ssz_rs::prelude::*;
use std::{fmt, fs, path::PathBuf};
use tracing::{debug, error, info, warn};
use url::Url;
use z_core::{
    mainnet::BeaconState, verify, AssertStateReader, ConsensusState, Ctx, GuestContext,
    HostStateReader, Input, Link, StateInput, StateReader,
};

mod beacon_client;

use crate::beacon_client::{BeaconClient, EventKind, EventTopic};

/// CLI for generating and submitting ZKasper proofs
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Trusted epoch
    #[clap(long)]
    trusted_epoch: Option<Epoch>,

    /// Beacon API URL
    #[clap(long)]
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

/// Subcommands of the publisher CLI.
#[derive(Parser, Debug)]
enum Command {
    /// Runs FFG verification in R0VM Executor
    #[clap(name = "exec")]
    Exec,
    /// Runs FFG verification in the host
    #[clap(name = "native-exec")]
    NativeExec,
    #[clap(name = "daemon")]
    Daemon,
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

    match args.command {
        Command::Exec => {
            let reader = HostStateReader::new_with_dir(&state_dir, context.into())?;
            let trusted_epoch = args.trusted_epoch.expect("trusted_epoch is required");
            let trusted_checkpoint = Checkpoint {
                epoch: trusted_epoch,
                // TODO(ec2): this should be the root of the block at the trusted checkpoint
                root: Default::default(),
            };

            let input = compute_next_candidate(&beacon_client, trusted_checkpoint, &reader).await;

            let reader = reader.track(input.state.finalized_checkpoint.epoch);
            verify(&reader, input.clone()); // will panic if verification fails

            let state_input = reader.to_input();
            let ssz_reader = state_input
                .clone()
                .into_state_reader(input.trusted_checkpoint_state_root, &GuestContext);

            verify(&AssertStateReader::new(&ssz_reader, &reader), input.clone()); // will panic if verification fails

            info!("Running FFG Verification in R0VM");
            let journal = execute_guest_program(state_input, input, GuestContext);
            info!("Journal: {:?}", journal);
        }
        Command::NativeExec => {
            let reader = HostStateReader::new_with_dir(&state_dir, context.into())?;
            let trusted_epoch = args.trusted_epoch.expect("trusted_epoch is required");
            let trusted_checkpoint = Checkpoint {
                epoch: trusted_epoch,
                // TODO(ec2): this should be the root of the block at the trusted checkpoint
                root: Default::default(),
            };

            let input = compute_next_candidate(&beacon_client, trusted_checkpoint, &reader).await;

            let reader = reader.track(input.state.finalized_checkpoint.epoch);
            verify(&reader, input.clone()); // will panic if verification fails

            let state_input = reader.to_input();
            let ssz_reader =
                state_input.into_state_reader(input.trusted_checkpoint_state_root, &GuestContext);

            verify(&AssertStateReader::new(&ssz_reader, &reader), input.clone());
            // will panic if verification fails
        }
        Command::Daemon => {
            daemon(state_dir, &beacon_client).await?;
        }
    }

    Ok(())
}

fn execute_guest_program(state_input: StateInput, input: Input, context: GuestContext) -> Vec<u8> {
    info!("Executing guest program");
    let ssz_reader = bincode::serialize(&state_input).unwrap();
    info!("Serialized SszStateReader: {} bytes", ssz_reader.len());
    let input = bincode::serialize(&input).unwrap();
    info!("Serialized Input: {} bytes", input.len());
    let context = bincode::serialize(&context).unwrap();
    info!("Serialized Context: {} bytes", context.len());
    info!(
        "Total Input: {} bytes",
        ssz_reader.len() + input.len() + context.len()
    );
    let env = ExecutorEnv::builder()
        .write_frame(&ssz_reader)
        .write_frame(&input)
        .write_frame(&context)
        .build()
        .unwrap();
    let executor = default_executor();
    let session_info = executor
        .execute(env, BEACON_GUEST_ELF)
        .expect("failed to execute guest program");
    info!("{} user cycles executed.", session_info.cycles());
    session_info.journal.bytes
}

async fn compute_next_candidate(
    beacon_client: &beacon_client::BeaconClient,
    trusted_checkpoint: Checkpoint,
    reader: &HostStateReader,
) -> Input {
    // 1. Start with trusted checkpoint (CP_T)
    let trusted_state = reader
        .get_beacon_state_by_epoch(trusted_checkpoint.epoch)
        .expect("trusted state should exist");
    info!(
        "Trusted State epoch: {}, slot: {}",
        trusted_checkpoint.epoch,
        trusted_state.slot()
    );

    // 2. Find the next_state where CP_T == next_state.finalized_checkpoint
    // We know this must exist and must be at most 3? epochs ahead because of finalization rules
    let mut next_state: Option<&BeaconState> = None;
    for epoch in trusted_checkpoint.epoch + 1..trusted_checkpoint.epoch + 3 {
        let state = reader.get_beacon_state_by_epoch(epoch).unwrap();
        debug!(
            r#"
            State {epoch} Previous Justified: {:?}
            State {epoch} Current Justified: {:?}
            State {epoch} Current Finalized: {:?}
            "#,
            state.previous_justified_checkpoint(),
            state.current_justified_checkpoint(),
            state.finalized_checkpoint(),
        );
        // TODO(ec2): We really should be checking the root as well
        if state.finalized_checkpoint().epoch == trusted_checkpoint.epoch {
            next_state = Some(state);
            break;
        }
    }
    let next_state = next_state.expect("Next state should exist");
    info!(
        r#"
        Trusted State was finalized Checkpoint at epoch: {}
            Previous Justified: {:?} (should be trusted checkpoint)
            Current Justified: {:?} (new source checkpoint)
            Current Finalized: {:?} (should be trusted checkpoint)
        "#,
        reader.context().compute_epoch_at_slot(next_state.slot()),
        next_state.previous_justified_checkpoint(),
        next_state.current_justified_checkpoint(),
        next_state.finalized_checkpoint(),
    );

    // Link(source)
    let new_previous_justified_checkpoint: Checkpoint =
        next_state.current_justified_checkpoint().clone();

    // 3. Find the state where new_previous_justified_checkpoint is justified a second time
    // In times of inactivity, this can be quite far
    let mut next_next_state: Option<&BeaconState> = None;
    for epoch in new_previous_justified_checkpoint.epoch + 1.. {
        let state = reader.get_beacon_state_by_epoch(epoch).unwrap();
        debug!(
            r#"
            State {epoch} Previous Justified: {:?}
            State {epoch} Current Justified: {:?}
            State {epoch} Current Finalized: {:?}
            "#,
            state.previous_justified_checkpoint(),
            state.current_justified_checkpoint(),
            state.finalized_checkpoint(),
        );
        if state.previous_justified_checkpoint() == &new_previous_justified_checkpoint {
            next_next_state = Some(state);
            break;
        }
    }
    let next_next_state = next_next_state.expect("Next next state should exist");
    info!(
        r#"
        Next State was justified Checkpoint at epoch: {}
            Previous Justified: {:?}
            Current Justified: {:?}
            Current Finalized: {:?}
        "#,
        reader
            .context()
            .compute_epoch_at_slot(next_next_state.slot()),
        next_next_state.previous_justified_checkpoint(),
        next_next_state.current_justified_checkpoint(),
        next_next_state.finalized_checkpoint(),
    );

    let link = Link {
        source: new_previous_justified_checkpoint.into(),
        target: next_next_state
            .current_justified_checkpoint()
            .clone()
            .into(),
    };

    info!("Get all blocks from trusted checkpoint to where candidate checkpoint gets finalized");

    let mut blocks = Vec::new();
    for slot in trusted_state.slot()..=next_next_state.slot() {
        let block = beacon_client.get_block(BlockId::Slot(slot)).await;
        match block {
            Ok(block) => blocks.push(block),
            Err(e) => warn!("Failed to get block {}: {}", slot, e),
        }
    }

    let attestations = blocks
        .iter()
        .flat_map(|b| match b.body() {
            ethereum_consensus::types::BeaconBlockBodyRef::Electra(body) => {
                body.attestations.iter().cloned().collect::<Vec<_>>()
            }
            _ => unimplemented!("Electra Only!"),
        })
        .filter(|a| {
            // TODO(ec2): (this is only 1 finality)
            a.data.target.epoch == link.target.epoch
                && a.data.source.epoch == link.source.epoch
                && a.data.target.root == link.target.root
                && a.data.source.root == link.source.root
        })
        .collect::<Vec<_>>();

    info!("Got {} attestations", attestations.len());

    // TODO(willem): This is hard-coded for one-finality. Need to add extra conditions for building inputs for the other cases
    Input {
        state: ConsensusState {
            finalized_checkpoint: next_state.finalized_checkpoint().clone().into(),
            current_justified_checkpoint: next_state.current_justified_checkpoint().clone().into(),
            previous_justified_checkpoint: next_state
                .previous_justified_checkpoint()
                .clone()
                .into(),
        },
        link,
        attestations: attestations.into_iter().map(Into::into).collect(),
        trusted_checkpoint_state_root: trusted_state.hash_tree_root().unwrap(),
    }
}

async fn daemon(
    data_dir: impl Into<PathBuf>,
    beacon_client: &beacon_client::BeaconClient,
) -> anyhow::Result<()> {
    let data_dir = data_dir.into();

    let head = beacon_client.get_block(BlockId::Head).await?;
    info!("Current Chain Head Block: {:?}", head.slot());

    let cp = beacon_client
        .get_finality_checkpoints(StateId::Head)
        .await?;
    info!(
        r#"Previous Justified Checkpoint: {:?}
   Current Justified Checkpoint: {:?}
   Current Finalize Checkpoint: {:?}"#,
        cp.previous_justified, cp.current_justified, cp.finalized
    );

    let mut event_stream = beacon_client
        .get_events(&[EventTopic::Head, EventTopic::FinalizedCheckpoint])
        .await
        .unwrap();

    info!("event stream started");
    while let Some(event) = event_stream.next().await {
        match event {
            Ok(EventKind::Head(h)) => {
                info!(
                    "New Head at slot: {}, state: {}, epoch_transition {}",
                    h.slot, h.state, h.epoch_transition
                );
            }
            Ok(EventKind::FinalizedCheckpoint(cp)) => {
                info!(
                    "New finalized cp epoch: {}, block: {}, state: {}",
                    cp.epoch, cp.block, cp.state
                );
                let s = beacon_client
                    .get_beacon_state_ssz(StateId::Root(cp.state))
                    .await?;
                let file_name = data_dir.join(format!("{}_beacon_state.ssz", cp.epoch));
                debug!("Writing state to: {}", file_name.display());
                fs::write(file_name, &ssz_rs::serialize(&s)?)?;
            }
            Err(e) => {
                warn!("Error: {:?}", e);
            }
            _ => {
                warn!("Unknown event: {:?}", event);
            }
        }
    }

    Ok(())
}
