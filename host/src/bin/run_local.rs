use clap::Parser;
use ethereum_consensus::{deneb::Context, phase0::mainnet::SLOTS_PER_EPOCH};
use host::beacon_client::BeaconClient;
use host::input_builder::build_input;
use std::fs;
use url::Url;
use z_core::{verify, ConsensusState, HostStateReader};

/// Run a ZKasper client locally and process a number of updates from the bootstrap state
/// Useful for testing the clients ability to follow the chain
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Use the beacon state for this epoch to bootstrap the consensus state
    #[clap(long)]
    bootstrap_from_epoch: u64,

    /// Number of times to loop and update the consensus state
    #[clap(long, default_value_t = 1)]
    iterations: u64,

    /// Beacon API URL
    #[clap(long, env = "BEACON_RPC_URL")]
    beacon_api: Url,

    /// Directory to store data
    #[clap(long, env = "BEACON_CACHE_DIR", default_value = ".cache")]
    cache_dir: std::path::PathBuf,

    /// Max Beacon API requests per second (0 to disable rate limit)
    #[clap(long, short, default_value_t = 0)]
    rps: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let beacon_client = BeaconClient::builder(args.beacon_api)
        .with_cache(args.cache_dir.join("http"))
        .with_rate_limit(args.rps)
        .build();

    let state_dir = args.cache_dir.join("sepolia").join("states");
    fs::create_dir_all(&state_dir)?;

    let s = beacon_client
        .get_beacon_state(args.bootstrap_from_epoch * SLOTS_PER_EPOCH)
        .await?;

    // set the initial consensus state from the beacon state at `from_epoch`
    let mut consensus_state = ConsensusState {
        finalized_checkpoint: s.finalized_checkpoint().clone().into(),
        current_justified_checkpoint: s.current_justified_checkpoint().clone().into(),
        previous_justified_checkpoint: s.previous_justified_checkpoint().clone().into(),
    };
    tracing::info!("Initial consensus state: {:#?}", consensus_state);

    for i in 0..args.iterations {
        tracing::info!("Iteration: {}", i);

        let input = build_input(&beacon_client, consensus_state.clone()).await?;

        for epoch in input.consensus_state.finalized_checkpoint.epoch
            ..=input.consensus_state.finalized_checkpoint.epoch + 3
        {
            tracing::debug!("Caching beacon state for epoch: {}", epoch);
            cache_beacon_state(&beacon_client, epoch, &state_dir).await?;
        }
        let reader = HostStateReader::new_with_dir(&state_dir, Context::for_mainnet().into())?;
        let reader = reader.track(consensus_state.finalized_checkpoint.epoch);
        consensus_state = verify(&reader, input.clone()); // will panic if verification fails
        tracing::info!("Verification Success!");
        tracing::info!("Consensus state: {:#?}", consensus_state);
    }

    Ok(())
}

async fn cache_beacon_state(
    beacon_client: &BeaconClient,
    epoch: u64,
    cache_dir: &std::path::Path,
) -> anyhow::Result<()> {
    let s = beacon_client
        .get_beacon_state(epoch * SLOTS_PER_EPOCH)
        .await?;
    let file_name = cache_dir.join(format!("{}_beacon_state.ssz", epoch));
    tracing::debug!("Writing state to: {}", file_name.display());
    fs::write(file_name, &ssz_rs::serialize(&s)?)?;
    Ok(())
}
