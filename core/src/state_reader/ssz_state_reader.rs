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

use super::StateReader;
use crate::{
    Checkpoint, ConsensusState, Epoch, PublicKey, RandaoMixIndex, Root, Slot, StatePatch,
    ValidatorIndex, ValidatorInfo, get_total_balance,
    guest_gindices::{
        activation_eligibility_epoch_gindex, activation_epoch_gindex,
        earliest_consolidation_epoch_gindex, earliest_exit_epoch_gindex, effective_balance_gindex,
        exit_epoch_gindex, finalized_checkpoint_epoch_gindex, fork_current_version_gindex,
        fork_epoch_gindex, fork_previous_version_gindex, genesis_validators_root_gindex,
        public_key_0_gindex, public_key_1_gindex, slashed_gindex, slot_gindex, state_root_gindex,
        validators_gindex,
    },
    has_compressed_chunks, serde_utils,
};
use alloy_primitives::B256;
use beacon_types::{ChainSpec, EthSpec, Fork};
use itertools::Itertools;
use safe_arith::{ArithError, SafeArith};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use ssz_multiproofs::Multiproof;
use std::{collections::BTreeMap, marker::PhantomData, mem};
use tracing::{debug, trace};

#[serde_as]
#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct StateInput<'a> {
    /// Used fields of the beacon block plus their inclusion proof against the block root.
    #[serde(borrow)]
    pub beacon_block: Multiproof<'a>,

    /// Used fields of the beacon state plus their inclusion proof against the state root.
    #[serde(borrow)]
    pub beacon_state: Multiproof<'a>,

    /// Used fields of the active validators plus their inclusion proof against the validator root.
    #[serde(borrow)]
    pub active_validators: Multiproof<'a>,

    /// Public keys of all active validators.
    #[serde_as(as = "Vec<serde_utils::UncompressedPublicKey>")]
    pub public_keys: Vec<PublicKey>,

    /// State patches to "look ahead" to future states.
    #[serde_as(as = "BTreeMap<serde_utils::U64, _>")]
    pub patches: BTreeMap<Epoch, StatePatch>,
}

pub struct SszStateReader<E: EthSpec> {
    spec: ChainSpec,

    // verified beacon state fields
    genesis_validators_root: B256,
    fork: Fork,
    validators: BTreeMap<ValidatorIndex, ValidatorInfo>,

    // additional unverified data
    patches: BTreeMap<Epoch, StatePatch>,

    _phantom: PhantomData<E>,
}

/// Subset of the beacon state that is relevant for the verification.
#[derive(Clone, Debug)]
struct StateInfo {
    genesis_validators_root: B256,
    slot: Slot,
    fork: Fork,
    validators_root: B256,
    finalized_checkpoint_epoch: Epoch,
    earliest_exit_epoch: Epoch,
    earliest_consolidation_epoch: Epoch,
}

#[derive(thiserror::Error, Debug)]
pub enum SszReaderError {
    #[error("{msg}: Ssz multiproof error: {source}")]
    SszMultiproof {
        msg: &'static str,
        #[source]
        source: ssz_multiproofs::Error,
    },
    #[error("Missing state patch: {0}")]
    MissingStatePatch(Epoch),
    #[error("Arithmetic error: {0:?}")]
    ArithError(ArithError),
}

impl From<ArithError> for SszReaderError {
    fn from(e: ArithError) -> Self {
        SszReaderError::ArithError(e)
    }
}

trait WithContext<T> {
    fn context(self, msg: &'static str) -> Result<T, SszReaderError>;
}

impl<T> WithContext<T> for Result<T, ssz_multiproofs::Error> {
    fn context(self, msg: &'static str) -> Result<T, SszReaderError> {
        self.map_err(|e| SszReaderError::SszMultiproof { msg, source: e })
    }
}

impl StateInput<'_> {
    pub fn into_state_reader<E: EthSpec>(
        mut self,
        consensus_state: &ConsensusState,
    ) -> Result<SszStateReader<E>, SszReaderError> {
        // always use the default spec
        let spec = E::default_spec();

        // the finalized checkpoint is the only state we can trust
        let trusted_checkpoint = consensus_state.finalized_checkpoint;

        // check that the beacon block proofs correspond to the finalized epoch boundary
        self.beacon_block
            .verify(&trusted_checkpoint.root())
            .context("Beacon block root mismatch")?;
        // extract the proven state root from the beacon block
        let state_root = extract_beacon_block_multiproof(&self.beacon_block)
            .context("Failed to extract beacon block proof")?;

        // check that the beacon state proofs correspond to the state of the beacon block
        self.beacon_state
            .verify(&state_root)
            .context("Beacon state root mismatch")?;
        let state = extract_beacon_state_multiproof(&self.beacon_state)
            .context("Failed to extract beacon block proof")?;

        // check that the validator proofs correspond to the validators root of the beacon state
        self.active_validators
            .verify(&state.validators_root)
            .context("Validators root mismatch")?;
        // validator list inclusion proofs
        let mut validators = extract_validators_multiproof(
            &self.active_validators,
            mem::take(&mut self.public_keys),
            trusted_checkpoint.epoch(),
        )
        .context("Failed to extract validators proof")?;

        let state_epoch = state.slot.epoch(E::slots_per_epoch());
        let current_justified_epoch = consensus_state.current_justified_checkpoint.epoch();

        // Our trusted state is from `slot`, but our consensus state is at
        // `current_justified_checkpoint`. This means that we have missed all the state changes
        // introduced by the intermediate `state_transition()` calls. From the trusted state, we
        // only use the validator registry, so it boils down to the process_registry_updates().
        for epoch in state_epoch.as_u64()..=current_justified_epoch.as_u64() {
            let epoch = Epoch::from(epoch);
            // By definition, we know that the next finalization will happen at the
            // `current_justified_checkpoint`.
            let finalized_checkpoint_epoch = if epoch < current_justified_epoch {
                state.finalized_checkpoint_epoch
            } else {
                trusted_checkpoint.epoch()
            };

            process_registry_updates(&spec, &mut validators, finalized_checkpoint_epoch, epoch);
        }

        // the state patches are unverified, but we have to perform some plausibility checks
        self.validate_state_patches(&spec, &trusted_checkpoint, &state, &validators)?;

        Ok(SszStateReader {
            spec,
            genesis_validators_root: state.genesis_validators_root,
            fork: state.fork,
            validators,
            patches: self.patches,
            _phantom: PhantomData,
        })
    }

    fn validate_state_patches(
        &self,
        spec: &ChainSpec,
        trusted_checkpoint: &Checkpoint,
        state: &StateInfo,
        validators: &BTreeMap<ValidatorIndex, ValidatorInfo>,
    ) -> Result<(), SszReaderError> {
        // get the total active balance at the trusted checkpoint
        let active_validators = validators
            .iter()
            .filter_map(|(_, v)| v.is_active_at(trusted_checkpoint.epoch()).then_some(v));
        let total_active_balance: u64 = get_total_balance(spec, active_validators)?;

        // exit_epoch changes can happen due to consolidations and exits
        // get_balance_churn_limit() = get_activation_exit_churn_limit() + get_consolidation_churn_limit()
        // twice the churn limit seams reasonable ¯\_(ツ)_/¯
        let churn = get_balance_churn_limit(spec, total_active_balance)?.safe_mul(2)?;

        // we cannot distinguish between exits and consolidations, so we have to take the minimum
        let earliest_exit_epoch = std::cmp::min(
            state.earliest_exit_epoch,
            state.earliest_consolidation_epoch,
        );

        // New exits (consolidations) can only occur with a new block. The earliest this can happen
        // is during the trusted epoch after the boundary block of the epoch.
        let mut earliest_exit_epoch = std::cmp::max(
            earliest_exit_epoch,
            spec.compute_activation_exit_epoch(trusted_checkpoint.epoch())?,
        );

        // validate the state patched
        for (&patch_epoch, patch) in &self.patches {
            debug!("Validating state patch: {}", patch_epoch);

            // State patches account for changes introduced by blocks after our trusted checkpoint.
            // Therefore, no new epochs from earlier times must be patched.
            assert!(patch_epoch >= trusted_checkpoint.epoch());

            // even at the earliest_exit_epoch additional exits can happen
            // we could subtract state.exit_balance_to_consume and
            // state.consolidation_balance_to_consume to make this more exact
            let mut exit_balance_to_consume = churn;

            // validate the patched exit epochs, this needs to be sorted by epoch
            for (idx, &exit_epoch) in patch
                .validator_exits
                .iter()
                .sorted_unstable_by_key(|v| v.1.as_u64())
            {
                trace!("Validator {idx} exiting at: {exit_epoch}");

                let validator = validators
                    .get(idx)
                    .expect("patched exit_epoch for missing validator");
                let &prev_exit_epoch = self
                    .patches
                    .get(&(patch_epoch - 1))
                    .and_then(|p| p.validator_exits.get(idx))
                    .unwrap_or(&validator.exit_epoch);

                // ignore not changing patches
                if prev_exit_epoch == exit_epoch {
                    continue;
                }

                // exit_epoch must only change once
                assert_eq!(prev_exit_epoch, spec.far_future_epoch);

                // exit epoch must be in the future
                assert!(exit_epoch >= earliest_exit_epoch);
                exit_balance_to_consume += (exit_epoch - earliest_exit_epoch).as_u64() * churn;
                earliest_exit_epoch = exit_epoch;

                // churn limit must be respected
                assert!(exit_balance_to_consume >= validator.effective_balance);
                exit_balance_to_consume -= validator.effective_balance;
            }
        }

        Ok(())
    }
}

impl<E: EthSpec> StateReader for SszStateReader<E> {
    type Error = SszReaderError;
    type Spec = E;

    fn chain_spec(&self) -> &ChainSpec {
        &self.spec
    }

    fn genesis_validators_root(&self) -> Result<Root, Self::Error> {
        Ok(self.genesis_validators_root)
    }

    fn fork(&self, _epoch: Epoch) -> Result<Fork, Self::Error> {
        Ok(self.fork)
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        let patch = self
            .patches
            .get(&epoch)
            .ok_or(SszReaderError::MissingStatePatch(epoch))?;

        Ok(self
            .validators
            .iter()
            .map(|(idx, validator)| (*idx, validator))
            .filter(move |(idx, validator)| patch.is_active_validator(idx, validator, epoch)))
    }

    fn randao_mix(&self, epoch: Epoch, index: RandaoMixIndex) -> Result<Option<B256>, Self::Error> {
        let randao = self
            .patches
            .get(&epoch)
            .ok_or(Self::Error::MissingStatePatch(epoch))?
            .randao_mixes
            .get(&index);

        Ok(randao.cloned())
    }
}

/// Extracts the relevant fields from the beacon block [Multiproof].
///
/// Currently, includes:
/// - state_root
fn extract_beacon_block_multiproof(
    beacon_block: &Multiproof<'_>,
) -> Result<B256, ssz_multiproofs::Error> {
    let mut values = beacon_block.values();

    let state_root: &[u8; 32] = values.next_assert_gindex(state_root_gindex())?;

    assert!(values.next().is_none());

    Ok(state_root.into())
}

/// Extracts the [StateInfo] from the beacon state [Multiproof].
fn extract_beacon_state_multiproof(
    beacon_state: &Multiproof<'_>,
) -> Result<StateInfo, ssz_multiproofs::Error> {
    let mut values = beacon_state.values();

    let genesis_validators_root = values.next_assert_gindex(genesis_validators_root_gindex())?;
    let slot = values.next_assert_gindex(slot_gindex())?;
    let fork_previous_version = values.next_assert_gindex(fork_previous_version_gindex())?;
    let fork_current_version = values.next_assert_gindex(fork_current_version_gindex())?;
    let fork_epoch = values.next_assert_gindex(fork_epoch_gindex())?;
    let fork = Fork {
        previous_version: fork_previous_version[0..4].try_into().unwrap(),
        current_version: fork_current_version[0..4].try_into().unwrap(),
        epoch: u64_from_chunk(fork_epoch).into(),
    };
    let validators_root = values.next_assert_gindex(validators_gindex())?;
    let finalized_checkpoint_epoch =
        values.next_assert_gindex(finalized_checkpoint_epoch_gindex())?;
    let earliest_exit_epoch = values.next_assert_gindex(earliest_exit_epoch_gindex())?;
    let earliest_consolidation_epoch =
        values.next_assert_gindex(earliest_consolidation_epoch_gindex())?;

    assert!(values.next().is_none());

    Ok(StateInfo {
        genesis_validators_root: genesis_validators_root.into(),
        slot: u64_from_chunk(slot).into(),
        fork,
        validators_root: validators_root.into(),
        finalized_checkpoint_epoch: u64_from_chunk(finalized_checkpoint_epoch).into(),
        earliest_exit_epoch: u64_from_chunk(earliest_exit_epoch).into(),
        earliest_consolidation_epoch: u64_from_chunk(earliest_consolidation_epoch).into(),
    })
}

/// Extracts the not-exited validators from the validators [Multiproof].
///
/// The proof contains the compressed public key which is checked against the public key in the
/// `public_keys` vector which is in the uncompressed form.
/// It contains the `ValidatorInfo` of non-exited validators and only the `exit_epoch` for exited.
fn extract_validators_multiproof(
    validators: &Multiproof<'_>,
    public_keys: Vec<PublicKey>,
    current_epoch: Epoch,
) -> Result<BTreeMap<ValidatorIndex, ValidatorInfo>, ssz_multiproofs::Error> {
    let mut values = validators.values().peekable();
    let mut pubkeys = public_keys.into_iter();

    let mut validator_cache: BTreeMap<ValidatorIndex, ValidatorInfo> = BTreeMap::new();
    let mut validator_index: ValidatorIndex = 0;

    loop {
        let (gindex, _) = values.peek().ok_or(ssz_multiproofs::Error::MissingValue)?;
        // This is the generalized index for the validator list length, which means we are done.
        if gindex == &3 {
            break;
        }

        if gindex == &exit_epoch_gindex(validator_index) {
            let (_, exit_epoch) = values.next().unwrap();
            let exit_epoch = u64_from_chunk(exit_epoch);

            assert!(exit_epoch <= current_epoch.into());
        } else {
            let pubkey = pubkeys.next().unwrap();

            let pk_compressed = {
                let (gindex, part_1) = values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
                assert_eq!(gindex, public_key_0_gindex(validator_index));
                let (gindex, part_2) = values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
                assert_eq!(gindex, public_key_1_gindex(validator_index));
                (part_1, part_2)
            };

            // Check if the public key matches the compressed chunks.
            assert!(has_compressed_chunks(
                &pubkey,
                pk_compressed.0,
                pk_compressed.1
            ));

            let (gindex, effective_balance) =
                values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
            assert_eq!(gindex, effective_balance_gindex(validator_index));
            let effective_balance = u64_from_chunk(effective_balance);

            let (gindex, slashed) = values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
            assert_eq!(gindex, slashed_gindex(validator_index));
            let slashed = bool_from_chunk(slashed);

            let (gindex, activation_eligibility_epoch) =
                values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
            assert_eq!(gindex, activation_eligibility_epoch_gindex(validator_index));
            let activation_eligibility_epoch = u64_from_chunk(activation_eligibility_epoch);

            let (gindex, activation_epoch) =
                values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
            assert_eq!(gindex, activation_epoch_gindex(validator_index));
            let activation_epoch = u64_from_chunk(activation_epoch);

            let (gindex, exit_epoch) = values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
            assert_eq!(gindex, exit_epoch_gindex(validator_index));
            let exit_epoch = u64_from_chunk(exit_epoch);

            let validator_info = ValidatorInfo {
                pubkey,
                effective_balance,
                slashed,
                activation_eligibility_epoch: activation_eligibility_epoch.into(),
                activation_epoch: activation_epoch.into(),
                exit_epoch: exit_epoch.into(),
            };
            validator_cache.insert(validator_index, validator_info);
        }

        validator_index += 1;
    }

    let (_, length) = values.next().unwrap();
    let length = u64_from_chunk(length);
    assert_eq!(validator_index as u64, length);

    assert!(values.next().is_none());

    Ok(validator_cache)
}

/// Updates the `Registry`, i.e. the part of the beacon state that stores validator records. This is called during epoch processing.
///
/// See: https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#modified-process_registry_updates
fn process_registry_updates(
    spec: &ChainSpec,
    registry: &mut BTreeMap<ValidatorIndex, ValidatorInfo>,
    finalized_checkpoint_epoch: Epoch,
    current_epoch: Epoch,
) {
    let activation_epoch = spec.compute_activation_exit_epoch(current_epoch).unwrap();

    for validator in registry.values_mut() {
        // process activation eligibility:
        if validator.is_eligible_for_activation_queue(spec) {
            validator.activation_eligibility_epoch = current_epoch + 1;
        }
        // process activations:
        if validator.is_eligible_for_activation(spec, finalized_checkpoint_epoch) {
            validator.activation_epoch = activation_epoch;
        }
    }
}

fn get_balance_churn_limit(spec: &ChainSpec, total_active_balance: u64) -> Result<u64, ArithError> {
    let churn = std::cmp::max(
        spec.min_per_epoch_churn_limit_electra,
        total_active_balance.safe_div(spec.churn_limit_quotient)?,
    );

    churn.safe_sub(churn.safe_rem(spec.effective_balance_increment)?)
}

/// Extracts an u64 from a 32-byte SSZ chunk.
fn u64_from_chunk(node: &[u8; 32]) -> u64 {
    assert!(node[8..].iter().all(|&b| b == 0));
    u64::from_le_bytes(node[..8].try_into().unwrap())
}

/// Extracts a bool from a 32-byte SSZ chunk.
fn bool_from_chunk(node: &[u8; 32]) -> bool {
    assert!(node[1..].iter().all(|&b| b == 0));
    match node[0] {
        0 => false,
        1 => true,
        _ => panic!("Invalid boolean value: {}", node[0]),
    }
}

#[cfg(test)]
mod tests {
    mod state_input {
        use crate::{Epoch, RandaoMixIndex, StateInput, StatePatch, ValidatorIndex};
        use alloy_primitives::B256;
        use bls::SecretKey;
        use std::collections::BTreeMap;

        #[test]
        fn bincode() {
            let input = StateInput {
                beacon_block: Default::default(),
                beacon_state: Default::default(),
                active_validators: Default::default(),
                public_keys: vec![
                    SecretKey::random().public_key(),
                    SecretKey::random().public_key(),
                ],
                patches: BTreeMap::from([(
                    Epoch::new(1),
                    StatePatch {
                        randao_mixes: BTreeMap::from([(RandaoMixIndex::MAX, B256::ZERO)]),
                        validator_exits: BTreeMap::from([(ValidatorIndex::MAX, Epoch::new(1))]),
                    },
                )]),
            };

            let bytes = bincode::serialize(&input).unwrap();
            let de = bincode::deserialize::<StateInput>(&bytes).unwrap();
            assert!(input == de);
        }
    }
}
