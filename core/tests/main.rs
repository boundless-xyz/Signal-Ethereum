use std::sync::LazyLock;

use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
use beacon_types::Keypair;
use tempfile::TempDir;
use test_utils::{consensus_state_from_state, get_harness, get_spec, get_store};
use z_core::{HarnessStateReader, build_input, verify};

pub const VALIDATOR_COUNT: usize = 16;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| beacon_types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

/// This test builds a chain that is just long enough to finalize an epoch
/// given 100% validator participation
#[tokio::test]
// #[tracing_test::traced_test]
async fn simple_finalize_epoch() {
    // If you drop the temp_dir or store then the harness will break FYI
    let spec = get_spec();
    let temp_dir = TempDir::new().expect("temp dir should create");
    let store = get_store(&temp_dir, spec.clone());
    let harness = get_harness(KEYPAIRS[..].to_vec(), store.clone(), spec).await;

    println!(
        "historic state limits: {:?}",
        store.get_historic_state_limits()
    );

    // Grab our bootstrap consensus state from there
    let head_state = harness.chain.head_beacon_state_cloned();
    let consensus_state = consensus_state_from_state(&head_state);
    println!("Current slot: {}", head_state.slot());
    println!("Pre consensus state: {:?}", consensus_state);

    // progress the chain 3 epochs past our last state so there are attestations to process
    // WILLEM: For some reason progressing 3 epochs makes the historical state unavailable
    // even though I have set the cache to be very large ...
    // The -1 is a workaround which seems to make it work just fine
    harness.advance_slot();
    harness
        .extend_chain(
            (harness.slots_per_epoch() * 3 - 1) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators, // this is where we can mess around with partial validator participation, forks etc
        )
        .await;

    println!(
        "historic state limits: {:?}",
        store.get_historic_state_limits()
    );

    let state_reader = HarnessStateReader::from(harness);
    let input = build_input(&state_reader, consensus_state)
        .await
        .expect("should build input");

    let next_state = verify(&state_reader, input);
    println!("Post consensus state: {:?}", next_state);
}
