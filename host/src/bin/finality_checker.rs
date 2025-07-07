use anyhow::{bail, ensure};
use clap::Parser;
use host::BeaconClient;
use std::collections::HashSet;
use std::fs::File;
use std::path::PathBuf;
use tracing::{debug, trace, warn};
use url::Url;
use z_core::{Checkpoint, ConsensusError, ConsensusState, Epoch};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Beacon API URL
    #[clap(long, env = "BEACON_RPC_URL")]
    beacon_api: Url,

    /// The starting epoch to check finality for.
    #[arg(short, long)]
    start_epoch: u64,

    /// Directory to store data
    #[clap(long, short, default_value = "./data")]
    data_dir: PathBuf,

    /// Rate limit for API requests in requests per second.
    #[arg(short, long, default_value = "10")]
    rate_limit: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();
    let args = Args::try_parse()?;

    let beacon_client = BeaconClient::builder(args.beacon_api)
        .with_cache(args.data_dir.join("http"))
        .with_rate_limit(args.rate_limit)
        .build();

    let mut transitions = Transitions::new()?;

    let mut pre_state: Option<ConsensusState> = None;
    for epoch in args.start_epoch.. {
        let finalized = tokio::select! {
            response = beacon_client.get_finality_checkpoints(epoch * 32) => {
                response?
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        };
        let state = ConsensusState::new(
            finalized.current_justified.into(),
            finalized.finalized.into(),
        );
        let current_epoch = epoch - 1;

        debug!(
            current = state.current_justified_checkpoint().to_string(),
            finalized = state.finalized_checkpoint().to_string(),
            "State after epoch {}",
            current_epoch
        );

        pre_state = Some(match pre_state.clone() {
            None => state,
            Some(pre_state) => {
                transitions.add(&pre_state, &state);

                match pre_state.transition_link(&state) {
                    Ok(None) => {
                        assert_eq!(pre_state, state);
                        pre_state
                    }
                    Ok(Some(link)) => {
                        trace!("Derived ZKasper transition: {}", link);
                        let post_state = pre_state.state_transition(&link)?;
                        trace!(
                            current = post_state.current_justified_checkpoint().to_string(),
                            finalized = post_state.finalized_checkpoint().to_string(),
                            "Derived ZKasper state"
                        );
                        ensure!(
                            post_state == state,
                            "Derived state does not match state for {}",
                            current_epoch
                        );
                        post_state
                    }
                    Err(ConsensusError::TwoFinality) => {
                        warn!("2-finality in epoch {}", current_epoch);
                        state
                    }
                    Err(e) => bail!(e),
                }
            }
        });
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct Transitions(HashSet<(ConsensusState, ConsensusState)>);

impl Transitions {
    fn new() -> anyhow::Result<Self> {
        match File::open("transitions.json") {
            Ok(file) => Ok(Self(serde_json::from_reader(file)?)),
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self(HashSet::new())),
            Err(e) => bail!(e),
        }
    }

    fn add(&mut self, a: &ConsensusState, b: &ConsensusState) {
        if a == b {
            return;
        }
        if a.finalized_checkpoint().epoch() == 0 {
            self.0.insert((
                ConsensusState::new(
                    from_epoch_or_genesis(a.current_justified_checkpoint()),
                    from_epoch_or_genesis(a.finalized_checkpoint()),
                ),
                ConsensusState::new(
                    from_epoch_or_genesis(b.current_justified_checkpoint()),
                    from_epoch_or_genesis(b.finalized_checkpoint()),
                ),
            ));
        } else {
            let offset = a.finalized_checkpoint().epoch() - 1;
            self.0.insert((
                ConsensusState::new(
                    cp(a.current_justified_checkpoint().epoch() - offset),
                    cp(a.finalized_checkpoint().epoch() - offset),
                ),
                ConsensusState::new(
                    cp(b.current_justified_checkpoint().epoch() - offset),
                    cp(b.finalized_checkpoint().epoch() - offset),
                ),
            ));
        }
    }
}

fn cp(epoch: Epoch) -> Checkpoint {
    Checkpoint::new(epoch, Default::default())
}

fn from_epoch_or_genesis(a: Checkpoint) -> Checkpoint {
    if a.epoch() == 0 { a } else { cp(a.epoch()) }
}

impl Drop for Transitions {
    fn drop(&mut self) {
        let file = File::create("transitions.json").unwrap();
        serde_json::to_writer(file, &self.0).unwrap();
    }
}
