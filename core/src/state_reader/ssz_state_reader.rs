use super::StateReader;
use crate::{
    BEACON_STATE_TREE_DEPTH, Ctx, Epoch, GuestContext, PublicKey, Slot, StatePatch,
    VALIDATOR_LIST_TREE_DEPTH, VALIDATOR_TREE_DEPTH, ValidatorIndex, ValidatorInfo, Version,
};
use alloy_primitives::B256;
use integer_sqrt::IntegerSquareRoot;
use serde::{Deserialize, Serialize};
use ssz_multiproofs::Multiproof;
use std::cmp::{max, min};
use std::collections::BTreeMap;
use tracing::{debug, info};

#[derive(Clone, Deserialize, Serialize)]
pub struct StateInput<'a> {
    /// Used fields of the BeaconState plus their inclusion proof against the state root.
    #[serde(borrow)]
    pub beacon_state: Multiproof<'a>,
    /// Number of included elements of the `randao_mixes` vector.
    pub num_randao: u32,
    /// Used fields of the active validators plus their inclusion proof against the validator root.
    #[serde(borrow)]
    pub active_validators: Multiproof<'a>,
    /// Public keys of all active validators.
    pub public_keys: Vec<PublicKey>,

    pub patches: BTreeMap<Epoch, StatePatch>,
}

pub struct SszStateReader<'a> {
    context: &'a GuestContext,
    genesis_validators_root: B256,
    fork_current_version: Version,
    epoch: Epoch,
    validators: BTreeMap<ValidatorIndex, ValidatorInfo>,
    randao: BTreeMap<usize, B256>,

    patches: BTreeMap<Epoch, StatePatch>,
}

impl StateInput<'_> {
    pub fn into_state_reader(self, root: B256, context: &GuestContext) -> SszStateReader {
        let mut beacon_state = self.beacon_state.values();

        // TODO: verify generalized indices
        let (_, genesis_validators_root) = beacon_state.next().unwrap();
        let (_, slot) = beacon_state.next().unwrap();
        let (_, fork_current_version) = beacon_state.next().unwrap();
        let (_, validators_root) = beacon_state.next().unwrap();

        // the remaining values of the beacon state correspond to RANDAO
        let randao_gindex_base: u64 = ((1 << BEACON_STATE_TREE_DEPTH) + 13)
            * context.epochs_per_historical_vector().next_power_of_two();
        let randao = (0..self.num_randao)
            .map(|_| beacon_state.next().unwrap())
            .map(|(gindex, randao)| {
                // 0 <= index <= EPOCHS_PER_HISTORICAL_VECTOR
                assert!(gindex >= randao_gindex_base);
                assert!(gindex <= randao_gindex_base + context.epochs_per_historical_vector());

                let index = (gindex - randao_gindex_base).try_into().unwrap();
                (index, B256::from(randao))
            })
            .collect();

        let (_, deposit_balance_to_consume) = beacon_state.next().unwrap();
        let (_, exit_balance_to_consume) = beacon_state.next().unwrap();
        let (_, earliest_exit_epoch) = beacon_state.next().unwrap();
        // TODO: handle consolidations
        let (_, consolidation_balance_to_consume) = beacon_state.next().unwrap();
        let (_, earliest_consolidation_epoch) = beacon_state.next().unwrap();

        self.beacon_state
            .verify(&root)
            .expect("Beacon state root mismatch");
        info!("Beacon state root verified");

        let state_epoch = context.compute_epoch_at_slot(u64_from_chunk(slot));

        // deposits can be arbitrarily large
        let mut deposit_balance_to_consume = u64_from_chunk(deposit_balance_to_consume);

        let mut exit_balance_to_consume = u64_from_chunk(exit_balance_to_consume);
        let mut earliest_exit_epoch: Epoch = u64_from_chunk(earliest_exit_epoch);

        let mut consolidation_balance_to_consume = u64_from_chunk(consolidation_balance_to_consume);
        let mut earliest_consolidation_epoch: Epoch = u64_from_chunk(earliest_consolidation_epoch);

        // perform sanity checks on the churn limits; these bounds are crucial for the security proof

        // As we are only comparing effective balances, so it is perfectly fine to cap the deposit_balance_to_consume
        // Even though technically deposits can be arbitrarily big.
        // This means that an attacker cannot fraudulently deposit more than 8 epochs worth of churn
        if deposit_balance_to_consume > context.max_effective_balance() {
            deposit_balance_to_consume = context.max_effective_balance();
        }

        // the earliest new exit can only happen in the first patch epoch
        // thus, it is fine to reset exit_balance_to_consume
        // otherwise earliest_exit_epoch will always be less than per_epoch_churn and the bound that at most per_epoch_churn balances exist hold
        // See https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#new-compute_exit_epoch_and_update_churn
        if earliest_exit_epoch <= state_epoch {
            exit_balance_to_consume = 0;
            earliest_exit_epoch = state_epoch;
        }

        // See https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#new-compute_consolidation_epoch_and_update_churn
        if earliest_consolidation_epoch <= state_epoch {
            consolidation_balance_to_consume = 0;
            earliest_consolidation_epoch = state_epoch;
        }

        self.active_validators
            .verify(validators_root)
            .expect("Validators root mismatch");
        info!("Validators root verified");

        let mut values = self.active_validators.values();
        let validator_cache = self
            .public_keys
            .into_iter()
            .map(|pubkey| {
                // TODO: verify generalized indices
                let pk_compressed = {
                    let (_, part_1) = values.next().unwrap();
                    let (_, part_2) = values.next().unwrap();
                    (part_1, part_2)
                };
                assert!(pubkey.has_compressed_chunks(pk_compressed.0, pk_compressed.1));

                let (_, effective_balance) = values.next().unwrap();
                let effective_balance = u64_from_chunk(effective_balance);

                let (_, activation_epoch) = values.next().unwrap();
                let activation_epoch = u64_from_chunk(activation_epoch);

                let (exit_epoch_gindex, exit_epoch) = values.next().unwrap();
                let exit_epoch = u64_from_chunk(exit_epoch);

                // We are calculating the validator index from the gindex.
                let validator_index =
                    (exit_epoch_gindex >> VALIDATOR_TREE_DEPTH) - (1 << VALIDATOR_LIST_TREE_DEPTH);
                let validator_index = usize::try_from(validator_index).unwrap();

                (
                    validator_index,
                    ValidatorInfo {
                        pubkey,
                        effective_balance,
                        activation_epoch,
                        exit_epoch,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert!(values.next().is_none());
        info!("Active validators verified");

        let state_reader = SszStateReader {
            context,
            genesis_validators_root: genesis_validators_root.into(),
            fork_current_version: fork_current_version[0..4].try_into().unwrap(),
            epoch: state_epoch,
            validators: validator_cache,
            randao,
            patches: self.patches,
        };

        let default_validator = ValidatorInfo::default();

        let final_patch_epoch = state_reader
            .patches
            .last_key_value()
            .map(|(&epoch, _)| epoch)
            .unwrap_or(state_epoch);

        for patch_epoch in state_epoch + 1..=final_patch_epoch {
            info!(
                "Validating patch {} with {} validators",
                patch_epoch,
                state_reader
                    .patches
                    .get(&patch_epoch)
                    .map_or(0, |p| p.validators.len())
            );

            let total_active_balance = state_reader
                .active_validators(patch_epoch - 1, patch_epoch - 1)
                .unwrap()
                .map(|(_, validator)| validator.effective_balance)
                .try_fold(0u64, |acc, x| acc.checked_add(x))
                .unwrap();

            // in process_pending_deposits, the churn is updated for each epoch, here churn only accumulates if the churn limit has been hit
            // We always accumulate which is an acceptable upper bound.
            // See: https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#new-process_pending_deposits
            deposit_balance_to_consume +=
                get_activation_exit_churn_limit(total_active_balance, context);

            // if the state patch is empty there is nothing to validate
            let Some(patch) = state_reader.patches.get(&patch_epoch) else {
                continue;
            };

            let is_in_inactivity_leak =
                (patch_epoch - state_epoch) >= context.min_epochs_to_inactivity_penalty();
            // TODO: add support of inactivity leak penalties
            assert!(!is_in_inactivity_leak);

            let base_reward_per_increment = (context.effective_balance_increment()
                * context.base_reward_factor())
                / total_active_balance.integer_sqrt();
            // will always be at least `unslashed_participating_increments`
            let total_active_increments =
                total_active_balance / context.effective_balance_increment();
            let total_base_rewards = total_active_increments * base_reward_per_increment;

            for (&validator_index, validator) in &patch.validators {
                let prev_validator = state_reader
                    .validator(patch_epoch - 1, validator_index)
                    .unwrap_or(&default_validator);

                // pubkey must never change
                assert_eq!(prev_validator.pubkey, validator.pubkey);

                // validate validator activation
                if prev_validator.activation_epoch != validator.activation_epoch {
                    debug!(
                        "Validator {} changes at epoch {}: activation_epoch={}->{}",
                        validator_index,
                        patch_epoch,
                        prev_validator.activation_epoch,
                        validator.activation_epoch
                    );

                    // activation_epoch must only change once
                    assert_eq!(prev_validator.activation_epoch, u64::MAX);
                    // effective balance must be at least MIN_ACTIVATION_BALANCE
                    assert!(validator.effective_balance >= context.min_activation_balance());
                    // activation epoch must be in the future
                    // the only situation where activation_epoch is set is during process_registry_updates, and it is always set to the exact value
                    // See https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#modified-process_registry_updates
                    assert_eq!(
                        validator.activation_epoch,
                        patch_epoch + context.max_seed_lookahead()
                    );

                    // there is no need to check the balance against some limits here, this check happened when the validator was created (deposit)
                }

                // validate validator exit
                if prev_validator.exit_epoch != validator.exit_epoch {
                    debug!(
                        "Validator {} changes at epoch {}: exit_epoch={}->{}",
                        validator_index,
                        patch_epoch,
                        prev_validator.exit_epoch,
                        validator.exit_epoch
                    );

                    // exit_epoch must only change once
                    assert_eq!(prev_validator.exit_epoch, u64::MAX);
                    // exit epoch must be in the future
                    assert!(validator.exit_epoch >= patch_epoch + context.max_seed_lookahead());

                    // in compute_exit_epoch_and_update_churn the future exit epoch is computed wrt to the churn limit of the current balances
                    // this happens as soon as initiate_validator_exit is called; there are no pending exits without an exit_epoch
                    // similar to activations, churn only accumulates if the churn limit has been hit, and we always accumulate which is an acceptable upper bound.
                    // See https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#new-compute_exit_epoch_and_update_churn
                    for _ in earliest_exit_epoch + 1..=validator.exit_epoch {
                        exit_balance_to_consume +=
                            get_activation_exit_churn_limit(total_active_balance, context);
                    }
                    earliest_exit_epoch = validator.exit_epoch;

                    assert!(exit_balance_to_consume >= validator.effective_balance);
                    exit_balance_to_consume -= validator.effective_balance;
                }

                // validate balance change
                if prev_validator.effective_balance != validator.effective_balance {
                    debug!(
                        "Validator {} changes at epoch {}: effective_balance={}->{}",
                        validator_index,
                        patch_epoch,
                        prev_validator.effective_balance,
                        validator.effective_balance
                    );

                    let ebi = context.effective_balance_increment();

                    // effective_balance must be a multiple of EBI
                    assert_eq!(validator.effective_balance % ebi, 0);
                    // effective_balance must not exceed MAX_EFFECTIVE_BALANCE
                    assert!(validator.effective_balance <= context.max_effective_balance());
                    // if the effective_balance is less than EJECTION_BALANCE, validator must be exiting
                    if validator.effective_balance < context.ejection_balance() {
                        assert_ne!(validator.exit_epoch, u64::MAX);
                    }

                    let increments = prev_validator.effective_balance / ebi;
                    let base_reward = increments * base_reward_per_increment;

                    //// compute an upper bound for the participation reward ////
                    // https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#get_flag_index_deltas

                    let max_participation_reward = (base_reward
                        * (<GuestContext as Ctx>::TIMELY_SOURCE_WEIGHT
                            + <GuestContext as Ctx>::TIMELY_TARGET_WEIGHT
                            + <GuestContext as Ctx>::TIMELY_HEAD_WEIGHT)
                        * total_active_increments)
                        / (total_active_increments * <GuestContext as Ctx>::WEIGHT_DENOMINATOR);

                    //// compute an upper bound for the proposer reward ////
                    // https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#modified-process_attestation

                    // Sum of get_base_reward(state, index) over all attesting indices
                    // for one slot there can be at most num_active_validators(state) / 32 validators
                    // thus Sum get_base_reward(state, index) <= num_active_validators(state) / 32 * (MAX_EFFECTIVE_BALANCE / EFFECTIVE_BALANCE_INCREMENT * get_base_reward_per_increment(state)
                    // TODO: Nice to have; Compute the actual proposer index and only use it there

                    let proposer_reward_numerator = total_active_increments
                        / context.slots_per_epoch()
                        * base_reward_per_increment
                        * (<GuestContext as Ctx>::TIMELY_SOURCE_WEIGHT
                            + <GuestContext as Ctx>::TIMELY_TARGET_WEIGHT
                            + <GuestContext as Ctx>::TIMELY_HEAD_WEIGHT);

                    let proposer_reward_denominator = (<GuestContext as Ctx>::WEIGHT_DENOMINATOR
                        - <GuestContext as Ctx>::PROPOSER_WEIGHT)
                        * <GuestContext as Ctx>::WEIGHT_DENOMINATOR
                        / <GuestContext as Ctx>::PROPOSER_WEIGHT;

                    // Proposer are able to include up to MAX_ATTESTATIONS slots of attestations.
                    // assume this validator proposed one slot with full attestations
                    let max_proposer_reward = (proposer_reward_numerator
                        / proposer_reward_denominator)
                        * (context.max_attestations() as u64);

                    //// compute an upper bound for the sync committee reward ////
                    // https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#sync-aggregate-processing

                    let (max_sync_participant_reward, max_sync_proposer_reward) = {
                        // Calculate the total reward pool for sync committee per slot
                        let max_participant_rewards_pool_per_slot = total_base_rewards
                            * <GuestContext as Ctx>::SYNC_REWARD_WEIGHT
                            / <GuestContext as Ctx>::WEIGHT_DENOMINATOR
                            / context.slots_per_epoch();

                        // Calculate the reward per participant per slot
                        let participant_reward_per_slot = max_participant_rewards_pool_per_slot
                            / (context.sync_committee_size() as u64);

                        // Calculate the reward the proposer gets per included participant
                        let proposer_reward_per_participant = participant_reward_per_slot
                            * <GuestContext as Ctx>::PROPOSER_WEIGHT
                            / (<GuestContext as Ctx>::WEIGHT_DENOMINATOR
                                - <GuestContext as Ctx>::PROPOSER_WEIGHT); // This is participant_reward_per_slot / 7

                        // Max reward *if* this validator is a participant (participates all slots)
                        let max_reward_as_participant =
                            participant_reward_per_slot * context.slots_per_epoch();

                        // Max reward *if* this validator proposes (includes all 512 participants)
                        let max_reward_as_proposer =
                            proposer_reward_per_participant * context.sync_committee_size() as u64;

                        (max_reward_as_participant, max_reward_as_proposer)
                    };

                    let max_reward = max_participation_reward
                        + max_proposer_reward
                        + max_sync_participant_reward
                        + max_sync_proposer_reward;
                    // due to the Hysteresis, even a small reward could lead to an increase of EBI
                    let max_effective_reward = max_reward.next_multiple_of(ebi);

                    if prev_validator.effective_balance + max_effective_reward
                        < validator.effective_balance
                    {
                        // This is the additional *effective balance increase* that deposits need to account for.
                        // It's guaranteed to be a multiple of ebi because both terms are.
                        let effective_increase = validator.effective_balance
                            - (prev_validator.effective_balance + max_effective_reward);

                        // Only consume the churn if the balance will become active
                        if validator.exit_epoch < patch_epoch {
                            assert!(deposit_balance_to_consume >= effective_increase);
                            deposit_balance_to_consume -= effective_increase;
                        }
                    }

                    //// compute an upper bound for the participation penalty ////
                    let max_participation_penalty = base_reward
                        * (<GuestContext as Ctx>::TIMELY_SOURCE_WEIGHT
                            + <GuestContext as Ctx>::TIMELY_TARGET_WEIGHT)
                        / <GuestContext as Ctx>::WEIGHT_DENOMINATOR;
                    let max_sync_participation_penalty = max_sync_participant_reward;

                    let max_penality = max_participation_penalty + max_sync_participation_penalty;
                    // due to the Hysteresis, even a small reward could lead to an increase of EBI
                    let max_effective_penality = max_penality.next_multiple_of(ebi);

                    // if the balance change exceeds the maximum penality it must be a full withdrawal
                    if prev_validator
                        .effective_balance
                        .saturating_sub(max_effective_penality)
                        > validator.effective_balance
                    {
                        // it is only ever possible to withdraw the entire balance
                        assert_eq!(validator.effective_balance, 0);
                        // it is only possible to withdraw after the withdrawable_epoch, which we don't have so we have to estimate
                        assert!(
                            patch_epoch
                                >= validator.exit_epoch
                                    + context.min_validator_withdrawability_delay()
                        );
                    }
                }
            }
        }

        state_reader
    }
}

impl StateReader for SszStateReader<'_> {
    type Error = ();
    type Context = GuestContext;

    fn context(&self) -> &Self::Context {
        self.context
    }

    fn genesis_validators_root(&self) -> B256 {
        self.genesis_validators_root
    }

    fn fork_current_version(&self, _epoch: Epoch) -> Result<Version, Self::Error> {
        Ok(self.fork_current_version)
    }

    fn active_validators(
        &self,
        state_epoch: Epoch,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        assert!(state_epoch >= epoch, "Only historical epochs supported");

        let (&last_idx, _) = self.validators.last_key_value().unwrap();
        let patch = self.patches.get(&state_epoch);

        static EMPTY_VALIDATORS: BTreeMap<ValidatorIndex, ValidatorInfo> = BTreeMap::new();
        let patch_val = patch
            .map(|patch| &patch.validators)
            .unwrap_or(&EMPTY_VALIDATORS);

        let iter = self
            .validators
            .iter()
            .chain(patch_val.range(last_idx + 1..))
            .map(|(idx, validator)| (*idx, patch_val.get(idx).unwrap_or(validator)));

        Ok(iter.filter(move |(_, validator)| is_active_validator(validator, epoch)))
    }

    fn randao_mix(&self, epoch: Epoch, index: usize) -> Result<Option<B256>, Self::Error> {
        let randao = if self.epoch == epoch {
            self.randao.get(&index)
        } else {
            self.patches
                .get(&epoch)
                .expect("Missing state patch")
                .randao_mixes
                .get(&index)
        };

        Ok(randao.cloned())
    }
}

impl SszStateReader<'_> {
    /// Returns the validator info for epoch.
    fn validator(&self, epoch: Epoch, index: ValidatorIndex) -> Option<&ValidatorInfo> {
        for patch_epoch in (self.epoch + 1..=epoch).rev() {
            if let Some(validator) = self
                .patches
                .get(&patch_epoch)
                .and_then(|patch| patch.validators.get(&index))
            {
                return Some(validator);
            }
        }
        self.validators.get(&index)
    }
}

#[derive(Clone, Debug)]
struct DepositInfo {
    pubkey: PublicKey,
    amount: u64,
    slot: Slot,
}

/// Extracts an u64 from a 32-byte SSZ chunk.
fn u64_from_chunk(node: &[u8; 32]) -> u64 {
    assert!(node[8..].iter().all(|&b| b == 0));
    u64::from_le_bytes(node[..8].try_into().unwrap())
}

/// Check if `validator` is active.
fn is_active_validator(validator: &ValidatorInfo, epoch: Epoch) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch
}

fn get_balance_churn_limit(total_active_balance: u64, context: &impl Ctx) -> u64 {
    let churn = max(
        context.min_per_epoch_churn_limit(),
        total_active_balance / context.churn_limit_quotient(),
    );
    churn - churn % context.effective_balance_increment()
}

fn get_activation_exit_churn_limit(total_active_balance: u64, context: &impl Ctx) -> u64 {
    min(
        context.max_per_epoch_activation_exit_churn_limit(),
        get_balance_churn_limit(total_active_balance, context),
    )
}
