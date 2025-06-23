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
use crate::serde_utils::{U64, UncompressedPublicKey};
use crate::{
    Checkpoint, Epoch, PublicKey, RandaoMixIndex, Root, Slot, StatePatch,
    VALIDATOR_LIST_TREE_DEPTH, VALIDATOR_TREE_DEPTH, ValidatorIndex, ValidatorInfo,
    guest_gindices::{
        fork_current_version_gindex, fork_epoch_gindex, fork_previous_version_gindex,
        genesis_validators_root_gindex, randao_mixes_0_gindex, slot_gindex, validators_gindex,
    },
    has_compressed_chunks,
};
use alloy_primitives::B256;
use beacon_types::{EthSpec, Fork};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use ssz_multiproofs::Multiproof;
use std::collections::BTreeMap;

#[serde_as]
#[derive(Clone, Deserialize, Serialize)]
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
    #[serde_as(as = "Vec<UncompressedPublicKey>")]
    pub public_keys: Vec<PublicKey>,

    /// State patches to "look ahead" to future states.
    #[serde_as(as = "BTreeMap<U64, _>")]
    pub patches: BTreeMap<Epoch, StatePatch>,
}

pub struct SszStateReader<E: EthSpec> {
    // beacon state fields
    genesis_validators_root: B256,
    slot: Slot,
    fork: Fork,
    validators: BTreeMap<ValidatorIndex, ValidatorInfo>,
    randao: BTreeMap<RandaoMixIndex, B256>,

    // additional unverified data
    patches: BTreeMap<Epoch, StatePatch>,
    _spec: std::marker::PhantomData<E>,
}

#[derive(thiserror::Error, Debug)]
pub enum SszReaderError {
    #[error("{msg}: Ssz multiproof error: {source}")]
    SszMultiproof {
        msg: String,
        #[source]
        source: ssz_multiproofs::Error,
    },

    #[error("{msg}: Ssz verify error: {source}")]
    SszVerify {
        msg: String,
        #[source]
        source: ssz_multiproofs::Error,
    },
    #[error("Missing state patch: {0}")]
    MissingStatePatch(Epoch),
}

trait WithContext<T> {
    fn context(self, msg: &'static str) -> Result<T, SszReaderError>;
}

impl<T> WithContext<T> for Result<T, ssz_multiproofs::Error> {
    fn context(self, msg: &'static str) -> Result<T, SszReaderError> {
        self.map_err(|e| SszReaderError::SszMultiproof {
            msg: msg.to_string(),
            source: e.into(),
        })
    }
}

impl StateInput<'_> {
    pub fn into_state_reader<E: EthSpec>(
        self,
        checkpoint: Checkpoint,
    ) -> Result<SszStateReader<E>, SszReaderError> {
        // beacon block inclusion proofs
        self.beacon_block
            .verify(&checkpoint.root())
            .context("Beacon block root mismatch")?;

        let (epoch_boundary_slot, state_root) = extract_beacon_block_multiproof(&self.beacon_block)
            .context("Failed to extract beacon block multiproof")?;

        // beacon state inclusion proofs
        self.beacon_state
            .verify(&state_root)
            .context("Beacon state root mismatch")?;

        let (genesis_validators_root, slot, fork, validators_root, randao) =
            extract_beacon_state_multiproof::<E>(&self.beacon_state)
                .context("Failed to extract beacon block multiproof")?;
        assert_eq!(epoch_boundary_slot, slot);

        // validator list inclusion proofs
        let validators = extract_validators_multiproof(
            &self.active_validators,
            self.public_keys,
            checkpoint.epoch(),
        )
        .context("Failed to extract validators multiproof")?;

        self.active_validators
            .verify(&validators_root)
            .context("Validators root mismatch")?;

        // make sure that the state actually corresponds to the state of the checkpoint epoch
        for _epoch in
            epoch_boundary_slot.epoch(E::slots_per_epoch()).as_u64()..checkpoint.epoch().as_u64()
        {
            // TODO: process_epoch
            // update the slot
            // update the validators
            // update RANDAO?
            unimplemented!("process_epoch()")
        }

        Ok(SszStateReader {
            slot,
            genesis_validators_root,
            fork,
            validators,
            randao,
            patches: self.patches,
            _spec: std::marker::PhantomData,
        })
    }
}

impl<E: EthSpec> StateReader for SszStateReader<E> {
    type Error = SszReaderError;
    type Spec = E;

    fn genesis_validators_root(&self) -> Result<Root, Self::Error> {
        Ok(self.genesis_validators_root)
    }

    fn fork(&self, _epoch: Epoch) -> Result<beacon_types::Fork, Self::Error> {
        Ok(self.fork.clone())
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        let latest_finalized = self.slot.epoch(E::slots_per_epoch());
        Ok(self
            .validators
            .iter()
            .map(|(idx, validator)| (*idx, validator))
            .filter(move |(_, validator)| validator.is_active_at(latest_finalized, epoch)))
    }

    fn randao_mix(&self, epoch: Epoch, index: RandaoMixIndex) -> Result<Option<B256>, Self::Error> {
        let randao = if self.slot.epoch(E::slots_per_epoch()) == epoch {
            self.randao.get(&index)
        } else {
            self.patches
                .get(&epoch)
                .ok_or(Self::Error::MissingStatePatch(epoch))?
                .randao_mixes
                .get(&index)
        };

        Ok(randao.cloned())
    }
}

fn extract_beacon_block_multiproof(
    beacon_block: &Multiproof<'_>,
) -> Result<(Slot, B256), ssz_multiproofs::Error> {
    let mut values = beacon_block.values();
    // TODO: Make indices constant
    let slot: &[u8; 32] = values.next_assert_gindex(8)?;
    let state_root: &[u8; 32] = values.next_assert_gindex(11)?;

    assert!(values.next().is_none());

    Ok((u64_from_chunk(slot).into(), state_root.into()))
}

/// Extracts the relevant fields from the multiproof of the BeaconState.
/// Currently, includes:
/// - genesis_validators_root
/// - slot
/// - fork
/// - validators_root
/// - randao_mixes (only the ones used)
fn extract_beacon_state_multiproof<E: EthSpec>(
    beacon_state: &Multiproof<'_>,
) -> Result<(B256, Slot, Fork, B256, BTreeMap<u64, B256>), ssz_multiproofs::Error> {
    let mut beacon_state_iter = beacon_state.values();
    let genesis_validators_root =
        beacon_state_iter.next_assert_gindex(genesis_validators_root_gindex())?;
    let slot = beacon_state_iter.next_assert_gindex(slot_gindex())?;
    let fork_previous_version =
        beacon_state_iter.next_assert_gindex(fork_previous_version_gindex())?;
    let fork_current_version =
        beacon_state_iter.next_assert_gindex(fork_current_version_gindex())?;
    let fork_epoch = beacon_state_iter.next_assert_gindex(fork_epoch_gindex())?;
    let fork = Fork {
        previous_version: fork_previous_version[0..4].try_into().unwrap(),
        current_version: fork_current_version[0..4].try_into().unwrap(),
        epoch: u64_from_chunk(fork_epoch).into(),
    };
    let validators_root = beacon_state_iter.next_assert_gindex(validators_gindex())?;

    // the remaining values of the beacon state correspond to RANDAO
    let randao_gindex_base = randao_mixes_0_gindex();
    let randao = beacon_state_iter
        .map(|(gindex, randao)| {
            // 0 <= index <= EPOCHS_PER_HISTORICAL_VECTOR
            assert!(gindex >= randao_gindex_base);
            assert!(gindex <= randao_gindex_base + E::epochs_per_historical_vector() as u64);

            let index = gindex - randao_gindex_base;
            (index, B256::from(randao))
        })
        .collect();

    Ok((
        genesis_validators_root.into(),
        u64_from_chunk(slot.into()).into(),
        fork,
        validators_root.into(),
        randao,
    ))
}

/// Extracts the not-exited validators from the multiproof of the Validators.
///
/// The multiproof contains the compressed public key which is checked against the public key in the
/// `public_keys` vector which is in the uncompressed form.
/// It contains the `ValidatorInfo` of non-exited validators and only the exit_epoch for exited.
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

        let validator_base_index: u64 = ((1 << VALIDATOR_LIST_TREE_DEPTH)
            + (validator_index as u64))
            * (1 << VALIDATOR_TREE_DEPTH);
        let exit_epoch_gindex: u64 = validator_base_index + 6;

        if gindex == &exit_epoch_gindex {
            let (_, exit_epoch) = values.next().unwrap();
            let exit_epoch = u64_from_chunk(exit_epoch);

            assert!(exit_epoch <= current_epoch.into());
        } else {
            let pubkey = pubkeys.next().unwrap();

            let pk_compressed = {
                let (_, part_1) = values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
                let (_, part_2) = values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
                (part_1, part_2)
            };

            // Check if the public key matches the compressed chunks.
            assert!(has_compressed_chunks(
                &pubkey,
                pk_compressed.0,
                pk_compressed.1
            ));

            let (_, effective_balance) =
                values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
            let effective_balance = u64_from_chunk(effective_balance);

            let (_, activation_eligibility_epoch) =
                values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
            let activation_eligibility_epoch = u64_from_chunk(activation_eligibility_epoch);

            let (_, activation_epoch) =
                values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
            let activation_epoch = u64_from_chunk(activation_epoch);

            let (_, exit_epoch) = values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
            let exit_epoch = u64_from_chunk(exit_epoch);

            let validator_info = ValidatorInfo {
                pubkey,
                effective_balance,
                activation_eligibility_epoch,
                activation_epoch,
                exit_epoch,
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

/// Extracts an u64 from a 32-byte SSZ chunk.
fn u64_from_chunk(node: &[u8; 32]) -> u64 {
    assert!(node[8..].iter().all(|&b| b == 0));
    u64::from_le_bytes(node[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    mod state_input {
        use crate::state_reader::ssz_state_reader::BTreeMap;
        use crate::{Epoch, RandaoMixIndex, StateInput, StatePatch};
        use alloy_primitives::B256;

        #[test]
        fn bincode() {
            let input = StateInput {
                beacon_block: Default::default(),
                beacon_state: Default::default(),
                active_validators: Default::default(),
                public_keys: vec![],
                patches: BTreeMap::from([(
                    Epoch::new(1),
                    StatePatch {
                        randao_mixes: BTreeMap::from([(RandaoMixIndex::MAX, B256::ZERO)]),
                    },
                )]),
            };

            let bytes = bincode::serialize(&input).unwrap();
            let de = bincode::deserialize::<StateInput>(&bytes).unwrap();
            assert_eq!(de.patches, input.patches);
        }
    }
}
