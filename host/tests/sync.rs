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

//! Tests the ability of ZKasper to sync with a beacon chain through various scenarios.
//!
//! The basic breakdown of each of these tests is to create a test harness and call various functions to create a chain that
//! has experienced certain events (e.g. finalization, validator exits, etc) that are valid in a beacon chain.
//! The function `test_zkasper_sync` is then called to check if the ZKasper input building and state transition process is able
//! to handle these scenarios correctly.

use std::{
    io,
    sync::{Arc, LazyLock},
};

use anyhow::{Context, anyhow};
use beacon_chain::BlockError;
use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
use beacon_types::{
    AttesterSlashingElectra, Domain, IndexedAttestationElectra, SignedRoot,
    test_utils::generate_deterministic_keypair,
};
use beacon_types::{
    BlobsList, Checkpoint, DepositData, DepositRequest, Epoch, EthSpec, ForkName, Hash256, Keypair,
    KzgProofs, MainnetEthSpec, PublicKeyBytes, SignatureBytes, SignedBeaconBlock, Slot,
    VariableList,
};
use bls::{AggregateSignature, FixedBytesExtended, get_withdrawal_credentials};
use chainspec::{ChainSpec, Config as ChainSpecConfig};
use ethereum_consensus::deneb::FAR_FUTURE_EPOCH;
use host::{
    AssertStateReader, HostStateReader, InputBuilder, PreflightStateReader, TestHarness,
    consensus_state_from_state, get_harness,
};
use methods::TEST_HARNESS_ELF;
use risc0_zkvm::{ExecutorEnv, default_executor};
use state_processing::{
    per_block_processing::is_valid_deposit_signature, state_advance::complete_state_advance,
};
use test_log::test;
use z_core::{
    AttestationData, Config, ConsensusState, Input, StateInput, StateReader, VerifyError, verify,
};

const VALIDATOR_COUNT: u64 = 48;
const ETH_PER_VALIDATOR: u64 = 32;
const GWEI_PER_ETH: u64 = 10_u64.pow(9);
static CONFIG: Config = Config {
    min_version: ForkName::Electra,
    max_version: ForkName::Electra,
    epoch_lookahead_limit: Epoch::new(100),
    justification_threshold_factor: 65545,
    justification_threshold_quotient: 98304,
};
static CHAINSPEC: LazyLock<(ChainSpecConfig, ChainSpec)> = LazyLock::new(|| {
    let mut config = ChainSpecConfig::default();
    config.altair_fork_epoch = serde_json::from_str("0").unwrap();
    config.bellatrix_fork_epoch = serde_json::from_str("1").unwrap();
    config.capella_fork_epoch = serde_json::from_str("2").unwrap();
    config.deneb_fork_epoch = serde_json::from_str("3").unwrap();
    config.electra_fork_epoch = serde_json::from_str("4").unwrap();
    config.fulu_fork_epoch = None;

    let spec = ChainSpec::from_config::<MainnetEthSpec>(&config).unwrap();

    (config, spec)
});

pub type SignedBlockContentsTuple<E> = (
    Arc<SignedBeaconBlock<E>>,
    Option<(KzgProofs<E>, BlobsList<E>)>,
);

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> = LazyLock::new(|| {
    beacon_types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT as usize)
});

/// Given a test harness and an initial consensus state, this function will
/// attempt to sync the consensus state as far as possible and then checks
/// that the finalized and justified checkpoints match the head state of the chain.
async fn test_zkasper_sync(
    cfg: &Config,
    harness: &TestHarness,
    initial_consensus_state: ConsensusState,
) -> Result<ConsensusState, VerifyError> {
    let head_state = harness.chain.head_beacon_state_cloned();

    let mut consensus_state = initial_consensus_state;

    println!("Pre consensus state: {:?}", consensus_state);

    loop {
        let state_reader = HostStateReader::new((*harness.spec).clone(), harness);
        let preflight_state_reader =
            PreflightStateReader::new(&state_reader, consensus_state.finalized_checkpoint);
        println!(
            "n validators: {}",
            state_reader
                .active_validators(consensus_state.finalized_checkpoint.epoch())
                .unwrap()
                .count()
        );

        // Build the input and verify it
        let builder = InputBuilder::new(harness);
        match builder.build(consensus_state.finalized_checkpoint).await {
            Ok((input, _)) => {
                dbg!(&input);

                // Perform a preflight verification to record the state reads
                _ = verify(cfg, &preflight_state_reader, input.clone())?;

                // build a self-contained SSZ reader
                let state_input = preflight_state_reader.to_input();
                let ssz_state_reader = state_input
                    .clone()
                    .into_state_reader(
                        preflight_state_reader.chain_spec().clone(),
                        &consensus_state,
                    )
                    .expect("Failed to convert to SSZ state reader");
                // Merge into a single AssertStateReader that ensures identical data returned for each read
                let assert_sr = AssertStateReader::new(&state_reader, &ssz_state_reader);

                // Verify again
                consensus_state = verify(cfg, &assert_sr, input.clone())?;

                // Finally, if that succeeded, also verify in the R0VM
                let (_, vm_consensus_state) =
                    vm_verify(&CHAINSPEC.0, &cfg, &state_input, &input).unwrap();
                assert_eq!(
                    consensus_state, vm_consensus_state,
                    "local and vm computed new state should match"
                );

                println!("consensus state: {:?}", &consensus_state);
            }
            Err(e) => {
                eprintln!("Error building input: {:#}", anyhow!(e));
                eprintln!("Could not build more inputs so assuming sync complete");
                break;
            }
        }
    }

    assert_eq!(
        consensus_state.finalized_checkpoint.epoch(),
        head_state.finalized_checkpoint().epoch.as_u64(),
        "finalized checkpoint should match"
    );

    assert_eq!(
        consensus_state.current_justified_checkpoint.epoch(),
        head_state.current_justified_checkpoint().epoch.as_u64(),
        "current justified checkpoint should match"
    );

    Ok(consensus_state)
}

/// This test builds a chain that is just long enough to finalize an epoch
/// given 100% validator participation
#[test(tokio::test)]
async fn simple_finalize_epoch() {
    let harness = get_harness(KEYPAIRS[..].to_vec(), &CHAINSPEC.1, Slot::new(224)).await;

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

    test_zkasper_sync(&CONFIG, &harness, consensus_state)
        .await
        .unwrap();
}

#[test(tokio::test)]
async fn finalizes_with_threshold_participation() {
    let harness = get_harness(KEYPAIRS[..].to_vec(), &CHAINSPEC.1, Slot::new(224)).await;
    let num_blocks_produced = harness.slots_per_epoch() * 3;

    let total_active_balance = VALIDATOR_COUNT * ETH_PER_VALIDATOR * GWEI_PER_ETH;
    let required_threshold = total_active_balance * CONFIG.justification_threshold_factor
        / CONFIG.justification_threshold_quotient;

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

    test_zkasper_sync(
        &CONFIG,
        &harness,
        consensus_state_from_state(&initial_state),
    )
    .await
    .unwrap();
}

// Both the chain and ZKasper should fail to finalize beyond the point where there is less than 2/3rds (in this case) participation
#[test(tokio::test)]
async fn does_not_finalize_with_less_than_threshold_participation() {
    let config = {
        let mut config = CONFIG.clone();
        config.justification_threshold_factor = 2;
        config.justification_threshold_quotient = 3;
        config
    };
    let harness = get_harness(KEYPAIRS[..].to_vec(), &CHAINSPEC.1, Slot::new(224)).await;
    let num_blocks_produced = harness.slots_per_epoch() * 10;

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
    let last_finalized_state =
        consensus_state_from_state(&harness.chain.head_beacon_state_cloned());

    assert_eq!(
        test_zkasper_sync(
            &config,
            &harness,
            consensus_state_from_state(&initial_state)
        )
        .await
        .unwrap()
        .finalized_checkpoint,
        last_finalized_state.finalized_checkpoint,
        "Expected threshold not met error, but got a different result"
    );
}

// When a validator is slashed bringing the participation below the threshold
// neither ZKasper or the chain should finalize
#[test(tokio::test)]
async fn does_not_finalize_after_slashing_reduces_total_active_balance_below_threshold() {
    let config = {
        let mut config = CONFIG.clone();
        config.justification_threshold_factor = 2;
        config.justification_threshold_quotient = 3;
        config
    };
    let harness = get_harness(KEYPAIRS[..].to_vec(), &CHAINSPEC.1, Slot::new(224)).await;
    let num_blocks_produced = harness.slots_per_epoch() * 10;

    let two_thirds = ((VALIDATOR_COUNT / 3) * 2) as usize;
    let attesters: Vec<_> = (0..two_thirds).collect();
    let slash_validator: usize = 0; // slashing the first validator

    let initial_state = harness.chain.head_beacon_state_cloned();

    harness.advance_slot();
    let slot = harness.get_current_slot();
    let (block, _) = harness
        .make_block_with_modifier(harness.get_current_state(), slot, |block| {
            let slashing = build_attester_slashing_with_epochs(
                &harness,
                vec![slash_validator as u64],
                None,
                None,
                None,
                None,
            );

            block
                .body_mut()
                .attester_slashings_electra_mut()
                .unwrap()
                .push(slashing)
                .expect("failed to add attester slashing to block");
        })
        .await;
    process_block(&harness, block).await.unwrap();
    harness.advance_slot();

    assert!(
        harness
            .chain
            .head_beacon_state_cloned()
            .validators()
            .get(slash_validator)
            .unwrap()
            .slashed,
        "Validator should have been slashed"
    );

    // extend the chain but ensure to skip any blocks where the slashed validator
    // is the proposer as these are invalid post-electra

    // Build a chain with some skip slots.
    while harness.get_current_state().slot().as_u64()
        < initial_state.slot().as_u64() + num_blocks_produced
    {
        let target_slot = harness.get_current_slot();
        let mut state = harness.get_current_state().clone();

        complete_state_advance(&mut state, None, target_slot, &harness.spec)
            .expect("should be able to advance state to slot");
        let proposer = state
            .get_beacon_proposer_index(target_slot, &harness.spec)
            .unwrap();

        if proposer != slash_validator {
            harness
                .extend_chain(
                    1,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::SomeValidators(attesters.clone()),
                )
                .await;
        } else {
            println!("Skipping slot {} as proposer {} is slashed", slot, proposer);
        }

        harness.advance_slot();
    }

    assert!(
        harness
            .chain
            .head_beacon_state_cloned()
            .validators()
            .get(0)
            .unwrap()
            .slashed,
        "Validator 0 should have been slashed"
    );

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
        initial_state.current_justified_checkpoint().epoch,
        "No epochs should have justified since slashing"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        initial_state.finalized_checkpoint().epoch,
        "No epochs should have been finalized since slashing"
    );
    let last_finalized_state =
        consensus_state_from_state(&harness.chain.head_beacon_state_cloned());

    assert_eq!(
        test_zkasper_sync(
            &config,
            &harness,
            consensus_state_from_state(&initial_state)
        )
        .await
        .unwrap()
        .finalized_checkpoint,
        last_finalized_state.finalized_checkpoint,
        "Expected threshold not met error, but got a different result"
    );
}

#[test(tokio::test)]
async fn finalize_after_one_empty_epoch() {
    let harness = get_harness(KEYPAIRS[..].to_vec(), &CHAINSPEC.1, Slot::new(224)).await;

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
        consensus_state.finalized_checkpoint.epoch()
            < new_consensus_state.finalized_checkpoint.epoch(),
        "Consensus state should have finalized after extending the chain with attestations"
    );
    assert!(
        consensus_state.previous_justified_checkpoint.epoch()
            < new_consensus_state.previous_justified_checkpoint.epoch(),
        "Consensus state should have new previous justified after extending the chain with attestations"
    );
    assert!(
        consensus_state.current_justified_checkpoint.epoch()
            < new_consensus_state.current_justified_checkpoint.epoch(),
        "Consensus state should have new current justified after extending the chain with attestations"
    );
    test_zkasper_sync(&CONFIG, &harness, consensus_state)
        .await
        .unwrap();
}

#[test(tokio::test)]
async fn finalize_after_inactivity_leak() {
    let harness = get_harness(KEYPAIRS[..].to_vec(), &CHAINSPEC.1, Slot::new(224)).await;

    // Grab our bootstrap consensus state from there
    let head_state = harness.chain.head_beacon_state_cloned();
    let consensus_state = consensus_state_from_state(&head_state);
    let current_epoch = head_state.current_epoch();

    println!("Current slot: {}", head_state.slot());

    // Where we get into leak
    let target_epoch = harness.get_current_state().current_epoch()
        + CHAINSPEC.1.min_epochs_to_inactivity_penalty
        + 1;

    println!("Current epoch: {}", head_state.current_epoch());
    println!("Target epoch: {}", target_epoch);

    // progress the chain with less than 2/3rds participation
    // this should result in an inactivity leak
    advance_non_finalizing(
        &harness,
        AdvanceBy::Epochs(target_epoch.as_u64() - current_epoch.as_u64()),
    )
    .await
    .unwrap();

    assert!(
        harness
            .get_current_state()
            .is_in_inactivity_leak(target_epoch, &CHAINSPEC.1)
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
            .is_in_inactivity_leak(target_epoch, &CHAINSPEC.1)
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

    test_zkasper_sync(&CONFIG, &harness, consensus_state)
        .await
        .unwrap();
}

/// This test case has (2/3 stake) < attesting_balance < threshold
/// The result should be a beacon chain that finalizes and a ZKasper instance that doesn't
/// This is a liveness failure case
#[test(tokio::test)]
async fn chain_finalizes_but_zkcasper_does_not() {
    let harness = get_harness(KEYPAIRS[..].to_vec(), &CHAINSPEC.1, Slot::new(224)).await;
    let num_blocks_produced = harness.slots_per_epoch() * 3;

    let total_active_balance = VALIDATOR_COUNT * ETH_PER_VALIDATOR * GWEI_PER_ETH;
    let required_threshold = total_active_balance * CONFIG.justification_threshold_factor
        / CONFIG.justification_threshold_quotient;

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
        test_zkasper_sync(
            &CONFIG,
            &harness,
            consensus_state_from_state(&initial_state)
        )
        .await,
        Err(VerifyError::ThresholdNotMet {
            attesting_balance: 1024000000000,
            threshold: 1024140625000,
        }),
        "Expected threshold not met error, but got a different result"
    );
}

/// Have one validator exit occur during sync and still be able to finalize
///
/// Note this does NOT test the lookahead functionality as the lookahead to finalize is smaller than the difference between
/// when the exit epoch is set and the epoch it is set to (1 + MAX_SEED_LOOKAHEAD).
#[test(tokio::test)]
async fn finalize_when_validator_exits() {
    let mut harness = get_harness(
        KEYPAIRS[..].to_vec(),
        &CHAINSPEC.1,
        (256u64 * MainnetEthSpec::slots_per_epoch()).into(), // need to start past epoch 256 or else exits are not allowed. Sorry this makes the test slow
    )
    .await;

    let consensus_state = consensus_state_from_state(&harness.get_current_state());

    let validator_to_exit = 0;

    // build a block with an exit and process it
    harness.advance_slot();
    let state = harness.get_current_state();
    let slot = harness.get_current_slot();
    let exit_valid_at = state.current_epoch() - 1;

    let (block, _) = harness
        .make_block_with_modifier(harness.get_current_state(), slot, |block| {
            harness.add_voluntary_exit(block, validator_to_exit, exit_valid_at);
        })
        .await;
    process_block(&harness, block).await.unwrap();

    let expected_exit_epoch = Epoch::new(261); // validator will be exited at this epoch (current_epoch + 1 + MAX_SEED_LOOKAHEAD)
    // Verify exit was processed correctly
    assert_eq!(
        harness
            .get_current_state()
            .validators()
            .get(validator_to_exit as usize)
            .unwrap()
            .exit_epoch,
        expected_exit_epoch
    );

    // Run until the exit epoch plus a few more so post-exit attestations are processed
    advance_finalizing(&mut harness, AdvanceBy::Epochs(8))
        .await
        .unwrap();
    assert_eq!(
        harness.get_current_state().current_epoch(),
        expected_exit_epoch.as_u64() + 3,
        "consensus state should be one epoch before the new validator stops participating"
    );

    test_zkasper_sync(&CONFIG, &harness, consensus_state)
        .await
        .unwrap();
}

/// Have one validator deposit, activate and then start attesting to new blocks
///
/// Note this does NOT test lookahead as the validator is added to the validator set
/// and its activation epoch value is set ahead of time.
/// As long as the lookahead to finalize is smaller than the difference between when the activation epoch is set and the value it is set to
/// ZKasper will be able to handle it correctly.
#[tokio::test]
async fn finalize_when_validator_activates() {
    let mut harness = get_harness(KEYPAIRS[..].to_vec(), &CHAINSPEC.1, Slot::new(224)).await;

    let consensus_state = consensus_state_from_state(&harness.get_current_state());

    // build a block with a deposit (this will be the first Electra style deposit)
    let new_keypair = generate_deterministic_keypair(VALIDATOR_COUNT as usize);
    let deposit_index = 0;
    let deposit_request = build_signed_deposit_request(deposit_index, &new_keypair, &CHAINSPEC.1);

    harness.advance_slot();
    let slot = harness.get_current_slot();
    let (block, _) = harness
        .make_block_with_modifier(harness.get_current_state(), slot, |block| {
            block.body_mut().execution_requests_mut().unwrap().deposits =
                VariableList::new(vec![deposit_request]).unwrap();
        })
        .await;

    process_block(&harness, block).await.unwrap();

    assert_eq!(
        harness.get_current_state().deposit_requests_start_index(),
        Ok(deposit_index),
        "deposit_requests_start_index should be set by first electra deposit"
    );
    assert_eq!(
        harness
            .get_current_state()
            .pending_deposits()
            .unwrap()
            .len(),
        1,
        "There should be one pending deposit"
    );

    // continue until just before the deposit is processed
    advance_finalizing(
        &mut harness,
        AdvanceBy::Slots(MainnetEthSpec::slots_per_epoch() * 2 - 1),
    )
    .await
    .unwrap();
    assert_eq!(
        harness.get_current_state().validators().len() as u64,
        VALIDATOR_COUNT,
        "There should be no new validators yet"
    );

    // Validator should be present in the set but its activation epoch should be set to FAR_FUTURE_EPOCH
    advance_finalizing(&mut harness, AdvanceBy::Epochs(1))
        .await
        .unwrap();

    assert_eq!(
        harness.get_current_state().validators().len() as u64,
        VALIDATOR_COUNT + 1,
        "New validator added to the set"
    );
    assert_eq!(
        harness
            .get_current_state()
            .validators()
            .get(VALIDATOR_COUNT as usize)
            .expect("New validator should be present")
            .activation_epoch,
        FAR_FUTURE_EPOCH
    );

    // Run epochs until validator activation epoch is set
    advance_finalizing(&mut harness, AdvanceBy::Epochs(7))
        .await
        .unwrap();

    assert_eq!(
        harness
            .get_current_state()
            .validators()
            .get(VALIDATOR_COUNT as usize)
            .expect("New validator should be present")
            .activation_epoch,
        Epoch::new(17),
    );

    // Add the new validator to the harness signers
    harness.validator_keypairs.push(new_keypair.clone());

    // add extra epochs so there are attestations using the new validator to be processed
    advance_finalizing(&mut harness, AdvanceBy::Epochs(5))
        .await
        .unwrap();

    test_zkasper_sync(&CONFIG, &harness, consensus_state)
        .await
        .unwrap();
}

/// Have a validator activate during a period of non-finalization due to an earlier deposit
/// This requires a lookahead for ZKasper spanning the epoch where the validators
/// activation epoch being set and the activation epoch itself
#[tokio::test]
async fn finalize_with_validator_activation_and_delayed_finality() {
    let mut harness = get_harness(KEYPAIRS[..].to_vec(), &CHAINSPEC.1, Slot::new(224)).await;

    let consensus_state = consensus_state_from_state(&harness.get_current_state());

    // build a block with a deposit (this will be the first Electra style deposit)
    let new_keypair = generate_deterministic_keypair(VALIDATOR_COUNT as usize);
    let deposit_index = 0;
    let deposit_request = build_signed_deposit_request(deposit_index, &new_keypair, &CHAINSPEC.1);

    harness.advance_slot();
    let slot = harness.get_current_slot();
    let (block, _) = harness
        .make_block_with_modifier(harness.get_current_state(), slot, |block| {
            block.body_mut().execution_requests_mut().unwrap().deposits =
                VariableList::new(vec![deposit_request]).unwrap();
        })
        .await;
    process_block(&harness, block).await.unwrap();

    assert_eq!(
        harness.get_current_state().deposit_requests_start_index(),
        Ok(deposit_index),
        "deposit_requests_start_index should be set by first electra deposit"
    );
    assert_eq!(
        harness
            .get_current_state()
            .pending_deposits()
            .unwrap()
            .len(),
        1,
        "There should be one pending deposit"
    );

    // continue until just before the deposit is processed
    advance_finalizing(
        &mut harness,
        AdvanceBy::Slots(MainnetEthSpec::slots_per_epoch() * 2 - 1),
    )
    .await
    .unwrap();

    assert_eq!(
        harness.get_current_state().validators().len() as u64,
        VALIDATOR_COUNT,
        "There should be no new validators yet"
    );

    // Validator should be present in the set but its activation epoch should be set to FAR_FUTURE_EPOCH
    advance_finalizing(&mut harness, AdvanceBy::Epochs(1))
        .await
        .unwrap();
    assert_eq!(
        harness.get_current_state().validators().len() as u64,
        VALIDATOR_COUNT + 1,
        "New validator added to the set"
    );
    assert_eq!(
        harness
            .get_current_state()
            .validators()
            .get(VALIDATOR_COUNT as usize)
            .expect("New validator should be present")
            .activation_epoch,
        FAR_FUTURE_EPOCH
    );

    // Run epochs until validator activation epoch is just set.
    // NOTE: this is set once the activation_eligibility_epoch has finalized
    advance_finalizing(&mut harness, AdvanceBy::Epochs(3))
        .await
        .unwrap();

    assert_eq!(
        harness
            .get_current_state()
            .validators()
            .get(VALIDATOR_COUNT as usize)
            .expect("New validator should be present")
            .activation_epoch,
        Epoch::new(17),
    );
    // Add the new validator to the harness signers
    harness.validator_keypairs.push(new_keypair.clone());

    // From here we want to experience a number of epochs without finalization
    advance_non_finalizing(&harness, AdvanceBy::Epochs(8))
        .await
        .unwrap();

    // Then start finalizing again
    advance_finalizing(&mut harness, AdvanceBy::Epochs(3))
        .await
        .unwrap();

    test_zkasper_sync(&CONFIG, &harness, consensus_state)
        .await
        .unwrap();
}

/// This test builds a chain that is just long enough to finalize an epoch
/// given 100% validator participation
#[tokio::test]
async fn handle_skipped_first_slot_of_epoch() {
    let harness = get_harness(KEYPAIRS[..].to_vec(), &CHAINSPEC.1, Slot::new(224)).await;

    // Grab our bootstrap consensus state from there
    let head_state = harness.chain.head_beacon_state_cloned();
    let consensus_state = consensus_state_from_state(&head_state);
    println!("Current slot: {}", head_state.slot());
    println!("Pre consensus state: {:?}", consensus_state);

    let target_chain_length = harness.get_current_slot().as_u64() + harness.slots_per_epoch() * 3;

    let skipped_slots = [256];

    // Build a chain with some skip slots.
    while harness.get_current_slot().as_u64() < target_chain_length {
        let slot = harness.chain.slot().unwrap().as_u64();

        if !skipped_slots.contains(&slot) {
            harness
                .extend_chain(
                    1,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;
        } else {
            println!("Skipping slot: {}", slot);
        }

        harness.advance_slot();
    }

    test_zkasper_sync(&CONFIG, &harness, consensus_state)
        .await
        .unwrap();
}

/// A minimal sink that prints every complete line it receives through `Write`.
/// This is used to "captures" the output of R0VM tests.
#[derive(Default)]
struct LinePrinter {
    buffer: Vec<u8>,
}

impl io::Write for LinePrinter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for &byte in buf {
            if byte == b'\n' {
                println!("{}", String::from_utf8_lossy(&self.buffer));
                self.buffer.clear();
            } else {
                self.buffer.push(byte);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn vm_verify(
    spec: &ChainSpecConfig,
    config: &Config,
    state_input: &StateInput,
    input: &Input<MainnetEthSpec>,
) -> anyhow::Result<(ConsensusState, ConsensusState)> {
    let mut stdout = LinePrinter::default();
    let env = ExecutorEnv::builder()
        .write_frame(&serde_cbor::to_vec(spec)?)
        .write(config)?
        .write_frame(&bincode::serialize(state_input)?)
        .write_frame(&bincode::serialize(input)?)
        .stdout(&mut stdout)
        .build()?;

    let journal = default_executor().execute(env, TEST_HARNESS_ELF)?.journal;
    // decode the journal
    let (pre_state, post_state) = journal.bytes.split_at(ConsensusState::abi_encoded_size());
    let pre_state = ConsensusState::abi_decode(pre_state).context("invalid journal")?;
    let post_state = ConsensusState::abi_decode(post_state).context("invalid journal")?;

    Ok((pre_state, post_state))
}

async fn process_block(
    harness: &TestHarness,
    mut block: SignedBlockContentsTuple<MainnetEthSpec>,
) -> Result<(), BlockError> {
    // From Lighthouse test: depending on the block, on first try the state root might mismatch due to our modification
    // thankfully, the correct state root is reported back, so we just take that one :^)
    // there probably is a better way...
    if let Err(BlockError::StateRootMismatch { local, .. }) =
        harness.process_block_result(block.clone()).await
    {
        let mut new_block = block.0.message_electra().unwrap().clone();
        new_block.state_root = local;
        block.0 =
            Arc::new(harness.sign_beacon_block(new_block.into(), &harness.get_current_state()));
        harness.process_block_result(block).await?;
    }

    Ok(())
}

fn build_signed_deposit_request(
    deposit_index: u64,
    keypair: &Keypair,
    spec: &ChainSpec,
) -> DepositRequest {
    let mut deposit_data = DepositData {
        pubkey: PublicKeyBytes::from(keypair.pk.clone()),
        withdrawal_credentials: Hash256::from_slice(
            &get_withdrawal_credentials(&keypair.pk, spec.bls_withdrawal_prefix_byte)[..],
        ),
        amount: 32 * GWEI_PER_ETH,
        signature: SignatureBytes::empty(),
    };
    deposit_data.signature = deposit_data.create_signature(&keypair.sk, spec);
    assert!(
        is_valid_deposit_signature(&deposit_data, spec).is_ok(),
        "Deposit signature should be valid"
    );

    DepositRequest {
        pubkey: deposit_data.pubkey,
        withdrawal_credentials: deposit_data.withdrawal_credentials,
        amount: deposit_data.amount,
        signature: deposit_data.signature,
        index: deposit_index,
    }
}

pub fn build_attester_slashing_with_epochs(
    harness: &TestHarness,
    validator_indices: Vec<u64>,
    source1: Option<Epoch>,
    target1: Option<Epoch>,
    source2: Option<Epoch>,
    target2: Option<Epoch>,
) -> AttesterSlashingElectra<MainnetEthSpec> {
    let fork = harness.chain.canonical_head.cached_head().head_fork();

    let data = AttestationData {
        slot: Slot::new(0),
        index: 0,
        beacon_block_root: Hash256::zero(),
        target: Checkpoint {
            root: Hash256::zero(),
            epoch: target1.unwrap_or(fork.epoch),
        },
        source: Checkpoint {
            root: Hash256::zero(),
            epoch: source1.unwrap_or(Epoch::new(0)),
        },
    };
    let mut attestation_1 = IndexedAttestationElectra {
        attesting_indices: VariableList::new(validator_indices).unwrap(),
        data,
        signature: AggregateSignature::infinity(),
    };

    let mut attestation_2 = attestation_1.clone();
    attestation_2.data.index += 1;
    attestation_2.data.source.epoch = source2.unwrap_or(Epoch::new(0));
    attestation_2.data.target.epoch = target2.unwrap_or(fork.epoch);

    for attestation in &mut [&mut attestation_1, &mut attestation_2] {
        for i in attestation.attesting_indices.iter() {
            let sk = &harness.validator_keypairs[*i as usize].sk;

            let genesis_validators_root = harness.chain.genesis_validators_root;

            let domain = harness.chain.spec.get_domain(
                attestation.data.target.epoch,
                Domain::BeaconAttester,
                &fork,
                genesis_validators_root,
            );
            let message = attestation.data.signing_root(domain);

            attestation.signature.add_assign(&sk.sign(message));
        }
    }

    AttesterSlashingElectra {
        attestation_1: attestation_1,
        attestation_2: attestation_2,
    }
}

enum AdvanceBy {
    Epochs(u64),
    Slots(u64),
}

async fn advance_finalizing(harness: &mut TestHarness, by: AdvanceBy) -> Result<(), BlockError> {
    let slots = match by {
        AdvanceBy::Epochs(e) => e * harness.slots_per_epoch(),
        AdvanceBy::Slots(s) => s,
    };
    harness.extend_slots(slots as usize).await;
    Ok(())
}

async fn advance_non_finalizing(harness: &TestHarness, by: AdvanceBy) -> Result<(), BlockError> {
    let slots = match by {
        AdvanceBy::Epochs(e) => e * harness.slots_per_epoch(),
        AdvanceBy::Slots(s) => s,
    };

    let two_thirds = (harness.validator_keypairs.len() / 3) * 2;
    let less_than_two_thirds = two_thirds - 2;
    let attesters = (0..less_than_two_thirds).collect();

    if harness.chain.slot()? == harness.chain.canonical_head.cached_head().head_slot() {
        harness.advance_slot();
    }
    harness
        .extend_chain(
            slots as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(attesters),
        )
        .await;
    Ok(())
}
