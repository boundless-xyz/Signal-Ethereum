use std::sync::LazyLock;

use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
use beacon_types::Keypair;
use test_utils::{AssertStateReader, HarnessStateReader};
use test_utils::{TestHarness, consensus_state_from_state, get_harness, get_spec};
use z_core::{
    ConsensusState, GuestContext, PreflightStateReader, VerifyError, build_input, threshold, verify,
};

pub const VALIDATOR_COUNT: u64 = 48;
const ETH_PER_VALIDATOR: u64 = 32;
const GWEI_PER_ETH: u64 = 10_u64.pow(9);

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> = LazyLock::new(|| {
    beacon_types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT as usize)
});

/// Given a test harness and an initial consensus state, this function will
/// attempt to sync the consensus state as far as possible and then checks
/// that the finalized and justified checkpoints match the head state of the chain.
async fn test_zkasper_sync(
    harness: &TestHarness,
    initial_consensus_state: ConsensusState,
) -> Result<ConsensusState, VerifyError> {
    let head_state = harness.chain.head_beacon_state_cloned();

    let mut consensus_state = initial_consensus_state;

    println!("Pre consensus state: {:?}", consensus_state);

    loop {
        let state_reader = HarnessStateReader::from(harness);
        let preflight_state_reader =
            PreflightStateReader::new(&state_reader, consensus_state.finalized_checkpoint.epoch);

        // Build the input and verify it
        match build_input(&state_reader, consensus_state.clone()).await {
            Ok(input) => {
                // Perform a preflight verification to record the state reads
                let trusted_state_root = input.trusted_checkpoint_state_root;
                _ = verify(&preflight_state_reader, input.clone())?;

                // build a self contained SSZ reader
                let ssz_state_reader = preflight_state_reader
                    .to_input(&state_reader)
                    .into_state_reader(trusted_state_root, &GuestContext)
                    .expect("Failed to convert to SSZ state reader");
                // Merge into a single AssertStateReader that ensures identical data returned for each read
                let assert_sr = AssertStateReader::new(&state_reader, &ssz_state_reader);
                // Verify again
                consensus_state = verify(&assert_sr, input)?;

                println!("consensus state: {:?}", &consensus_state);
            }
            Err(e) => {
                eprintln!("Error building input: {}", e);
                eprintln!("Could not build more inputs so assuming sync complete");
                break;
            }
        }
    }

    assert_eq!(
        consensus_state.finalized_checkpoint.epoch,
        head_state.finalized_checkpoint().epoch.as_u64(),
        "finalized checkpoint should match"
    );

    assert_eq!(
        consensus_state.current_justified_checkpoint.epoch,
        head_state.current_justified_checkpoint().epoch.as_u64(),
        "current justified checkpoint should match"
    );

    Ok(consensus_state)
}

/// This test builds a chain that is just long enough to finalize an epoch
/// given 100% validator participation
#[tokio::test]
async fn simple_finalize_epoch() {
    let spec = get_spec();
    let harness = get_harness(KEYPAIRS[..].to_vec(), spec).await;

    // Grab our bootstrap consensus state from there
    let head_state = harness.chain.head_beacon_state_cloned();
    let consensus_state = consensus_state_from_state(&head_state);
    println!("Current slot: {}", head_state.slot());
    println!("Pre consensus state: {:?}", consensus_state);

    // progress the chain 3 epochs past our last state so there are attestations to process
    harness
        .extend_chain(
            (harness.slots_per_epoch() * 3) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators, // this is where we can mess around with partial validator participation, forks etc
        )
        .await;

    test_zkasper_sync(&harness, consensus_state).await.unwrap();
}

#[tokio::test]
async fn finalizes_with_threshold_participation() {
    let spec = get_spec();
    let harness = get_harness(KEYPAIRS[..].to_vec(), spec).await;
    let num_blocks_produced = harness.slots_per_epoch() * 3;

    let required_threshold = threshold(3, VALIDATOR_COUNT * ETH_PER_VALIDATOR * GWEI_PER_ETH);

    let required_validators =
        required_threshold.div_ceil(ETH_PER_VALIDATOR * GWEI_PER_ETH) as usize;
    let attesters = (0..required_validators).collect();

    let initial_state = harness.chain.head_beacon_state_cloned();

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(attesters),
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;

    assert_eq!(
        state.slot(),
        initial_state.slot() + num_blocks_produced,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        (initial_state.slot().as_u64() + num_blocks_produced) / harness.slots_per_epoch(),
        "head should be at the expected epoch"
    );

    // Note: the 2/3rds tests are not justifying the immediately prior epochs because the
    // `MIN_ATTESTATION_INCLUSION_DELAY` is preventing an adequate number of attestations being
    // included in blocks during that epoch.

    assert_eq!(
        state.current_justified_checkpoint().epoch,
        state.current_epoch() - 2,
        "the head should be justified two behind the current epoch"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        state.current_epoch() - 3,
        "the head should be finalized three behind the current epoch"
    );

    test_zkasper_sync(&harness, consensus_state_from_state(&initial_state))
        .await
        .unwrap();
}

// Both the chain and ZKasper should fail to finalize when there is less than 2/3rds participation
#[tokio::test]
async fn does_not_finalize_with_less_than_two_thirds_participation() {
    let spec = get_spec();
    let harness = get_harness(KEYPAIRS[..].to_vec(), spec).await;
    let num_blocks_produced = harness.slots_per_epoch() * 5;

    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let less_than_two_thirds = (two_thirds - 1) as usize;
    let attesters = (0..less_than_two_thirds).collect();

    let initial_state = harness.chain.head_beacon_state_cloned();

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(attesters),
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;

    assert_eq!(
        state.slot(),
        initial_state.slot() + num_blocks_produced,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        (initial_state.slot().as_u64() + num_blocks_produced) / harness.slots_per_epoch(),
        "head should be at the expected epoch"
    );
    // Note despite no attestations being included in the blocks the chain will still finalize/justify
    // one step due to the attestations that were included in prior blocks
    assert_eq!(
        state.current_justified_checkpoint().epoch,
        initial_state.current_justified_checkpoint().epoch + 1,
        "only 1 epoch should have been justified from prior attestations"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        initial_state.finalized_checkpoint().epoch + 1,
        "only 1 epoch should have been finalized from prior attestations"
    );

    assert_eq!(
        test_zkasper_sync(&harness, consensus_state_from_state(&initial_state)).await,
        Err(VerifyError::ThresholdNotMet {
            lookahead: 3,
            attesting_balance: 1024000000000,
            threshold: 1024140625000,
        }),
        "Expected threshold not met error, but got a different result"
    );
}

#[tokio::test]
async fn finalize_after_one_empty_epoch() {
    let spec = get_spec();
    let harness = get_harness(KEYPAIRS[..].to_vec(), spec).await;

    // Grab our bootstrap consensus state from there
    let head_state = harness.chain.head_beacon_state_cloned();
    let consensus_state = consensus_state_from_state(&head_state);
    println!("Current slot: {}", head_state.slot());

    // Advances 33 slots to get a whole empty epoch
    for _ in 0..harness.slots_per_epoch() + 1 {
        harness.advance_slot();
    }
    assert_eq!(
        consensus_state,
        consensus_state_from_state(&harness.get_current_state()),
        "Consensus state should not have updated after advancing 33 empty slots because there are no attestations"
    );
    // progress the chain 2 epochs past the empty epoch
    harness
        .extend_chain(
            (harness.slots_per_epoch() * 2) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators, // this is where we can mess around with partial validator participation, forks etc
        )
        .await;
    let new_consensus_state = consensus_state_from_state(&harness.get_current_state());
    assert!(
        consensus_state.finalized_checkpoint.epoch < new_consensus_state.finalized_checkpoint.epoch,
        "Consensus state should have finalized after extending the chain with attestations"
    );
    assert!(
        consensus_state.previous_justified_checkpoint.epoch
            < new_consensus_state.previous_justified_checkpoint.epoch,
        "Consensus state should have new previous justified after extending the chain with attestations"
    );
    assert!(
        consensus_state.current_justified_checkpoint.epoch
            < new_consensus_state.current_justified_checkpoint.epoch,
        "Consensus state should have new current justified after extending the chain with attestations"
    );
    test_zkasper_sync(&harness, consensus_state).await.unwrap();
}

#[tokio::test]
async fn finalize_after_inactivity_leak() {
    let spec = get_spec();
    let harness = get_harness(KEYPAIRS[..].to_vec(), spec.clone()).await;

    // Grab our bootstrap consensus state from there
    let head_state = harness.chain.head_beacon_state_cloned();
    let consensus_state = consensus_state_from_state(&head_state);
    let current_epoch = head_state.current_epoch();

    println!("Current slot: {}", head_state.slot());

    let two_thirds = (VALIDATOR_COUNT as usize / 3) * 2;
    let less_than_two_thirds = two_thirds - 2;
    let attesters = (0..less_than_two_thirds).collect();

    // Where we get into leak
    let target_epoch =
        harness.get_current_state().current_epoch() + spec.min_epochs_to_inactivity_penalty + 1;

    println!("Current epoch: {}", head_state.current_epoch());
    println!("Target epoch: {}", target_epoch);

    // progress the chain with less than 2/3rds participation
    // this should result in an inactivity leak
    harness
        .extend_chain(
            (((target_epoch - current_epoch) * harness.slots_per_epoch()) - 1).into(),
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(attesters),
        )
        .await;

    assert!(
        harness
            .get_current_state()
            .is_in_inactivity_leak((target_epoch).into(), &spec)
            .unwrap(),
        "we should be in an inactivity leak"
    );

    // get out of inactivity leak
    // first justification occurs here
    harness
        .extend_slots(harness.slots_per_epoch() as usize + 1)
        .await;

    assert_eq!(
        target_epoch,
        harness
            .get_current_state()
            .current_justified_checkpoint()
            .epoch
            .as_u64()
    );

    // first finalization occurs here
    harness
        .extend_slots((harness.slots_per_epoch()) as usize)
        .await;

    assert!(
        !harness
            .get_current_state()
            .is_in_inactivity_leak((target_epoch).into(), &spec)
            .unwrap(),
        "we be should out of inactivity leak after finalization"
    );

    assert_eq!(
        target_epoch,
        harness
            .get_current_state()
            .previous_justified_checkpoint()
            .epoch
            .as_u64()
    );

    assert_eq!(
        target_epoch,
        harness
            .get_current_state()
            .finalized_checkpoint()
            .epoch
            .as_u64()
    );

    test_zkasper_sync(&harness, consensus_state).await.unwrap();
}

/// This test case has (2/3 stake) < attesting_balance < threshold
/// The result should be a beacon chain that finalizes and a ZKasper instance that doesn't
/// This is a liveness failure case
#[tokio::test]
async fn chain_finalizes_but_zkcasper_does_not() {
    let spec = get_spec();
    let harness = get_harness(KEYPAIRS[..].to_vec(), spec).await;
    let num_blocks_produced = harness.slots_per_epoch() * 3;

    let required_threshold = threshold(3, VALIDATOR_COUNT * ETH_PER_VALIDATOR * GWEI_PER_ETH);

    let required_validators =
        required_threshold.div_ceil(ETH_PER_VALIDATOR * GWEI_PER_ETH) as usize;
    let less_than_required_validators = required_validators - 1;
    let attesters = (0..less_than_required_validators).collect();

    let initial_state = harness.chain.head_beacon_state_cloned();

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(attesters),
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;

    assert_eq!(
        state.slot(),
        initial_state.slot() + num_blocks_produced,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        (initial_state.slot().as_u64() + num_blocks_produced) / harness.slots_per_epoch(),
        "head should be at the expected epoch"
    );

    // Note: the 2/3rds tests are not justifying the immediately prior epochs because the
    // `MIN_ATTESTATION_INCLUSION_DELAY` is preventing an adequate number of attestations being
    // included in blocks during that epoch.

    assert_eq!(
        state.current_justified_checkpoint().epoch,
        state.current_epoch() - 2,
        "the head should be justified two behind the current epoch"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        state.current_epoch() - 3,
        "the head should be finalized three behind the current epoch"
    );

    assert_eq!(
        test_zkasper_sync(&harness, consensus_state_from_state(&initial_state)).await,
        Err(VerifyError::ThresholdNotMet {
            lookahead: 3,
            attesting_balance: 1024000000000,
            threshold: 1024140625000,
        }),
        "Expected threshold not met error, but got a different result"
    );
}
