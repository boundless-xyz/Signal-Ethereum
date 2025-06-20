use super::StateReader;
use crate::{
    Checkpoint, Epoch, PublicKey, RandaoMixIndex, Root, Slot, StatePatch,
    VALIDATOR_LIST_TREE_DEPTH, VALIDATOR_TREE_DEPTH, ValidatorIndex, ValidatorInfo,
    guest_context::{
        fork_current_version_gindex, fork_epoch_gindex, fork_previous_version_gindex,
        genesis_validators_root_gindex, randao_mixes_0_gindex, slot_gindex, validators_gindex,
    },
};
use alloy_primitives::B256;
use beacon_types::{EthSpec, Fork};
use serde::{Deserialize, Serialize};
use ssz_multiproofs::Multiproof;
use std::collections::BTreeMap;

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
    pub public_keys: Vec<PublicKey>,

    /// State patches to "look ahead" to future states.
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

impl StateInput<'_> {
    pub fn into_state_reader<E: EthSpec>(
        self,
        checkpoint: Checkpoint,
    ) -> Result<SszStateReader<E>, SszReaderError> {
        // beacon block inclusion proofs
        self.beacon_block
            .verify(&checkpoint.root())
            .map_err(|e| SszReaderError::SszVerify {
                msg: "Beacon block root mismatch".to_string(),
                source: e,
            })?;
        let (epoch_boundary_slot, state_root) = extract_beacon_block_multiproof(&self.beacon_block)
            .map_err(|e| SszReaderError::SszMultiproof {
                msg: "Failed to extract beacon block multiproof".to_string(),
                source: e,
            })?;

        // beacon state inclusion proofs
        self.beacon_state
            .verify(&state_root)
            .map_err(|e| SszReaderError::SszVerify {
                msg: "Beacon state root mismatch".to_string(),
                source: e,
            })?;
        let (genesis_validators_root, slot, fork, validators_root, randao) =
            extract_beacon_state_multiproof::<E>(&self.beacon_state).map_err(|e| {
                SszReaderError::SszMultiproof {
                    msg: "Failed to extract beacon state multiproof".to_string(),
                    source: e,
                }
            })?;
        assert_eq!(epoch_boundary_slot, slot);

        // validator list inclusion proofs
        let validators = extract_validators_multiproof(self.public_keys, &self.active_validators)
            .map_err(|e| SszReaderError::SszMultiproof {
            msg: "Failed to extract active validators multiproof".to_string(),
            source: e,
        })?;
        self.active_validators
            .verify(&validators_root)
            .map_err(|e| SszReaderError::SszVerify {
                msg: "Validators root mismatch".to_string(),
                source: e,
            })?;

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
        Ok(self
            .validators
            .iter()
            .map(|(idx, validator)| (*idx, validator))
            .filter(move |(_, validator)| validator.is_active_at(epoch)))
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

/// Extracts the active validators from its multiproof. The multiproof contains the compressed public key which is checked
/// against the public key in the `public_keys` vector which is in the uncompressed form.
/// The multiproof contains the following fields:
/// - public key (compressed)
/// - effective balance
/// - activation epoch
/// - exit epoch
fn extract_validators_multiproof(
    public_keys: Vec<PublicKey>,
    validators: &Multiproof<'_>,
) -> Result<BTreeMap<ValidatorIndex, ValidatorInfo>, ssz_multiproofs::Error> {
    let mut values = validators.values();

    let validator_cache = public_keys
        .into_iter()
        .map(|pubkey| {
            // Note: We do not have to verify the gindices here. This is because the root of the Validators
            // list is verified against the root which is in the top level BeaconState and this is a homogeneous
            // collection. We are also using the exit_epoch_gindex to calculate the validator index.
            let pk_compressed = {
                let (_, part_1) = values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
                let (_, part_2) = values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
                (part_1, part_2)
            };

            // Check if the public key matches the compressed chunks.
            assert!(pubkey.has_compressed_chunks(pk_compressed.0, pk_compressed.1));

            let (_, effective_balance) =
                values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
            let effective_balance = u64_from_chunk(effective_balance);

            let (_, activation_epoch) =
                values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
            let activation_epoch = u64_from_chunk(activation_epoch);

            let (exit_epoch_gindex, exit_epoch) =
                values.next().ok_or(ssz_multiproofs::Error::MissingValue)?;
            let exit_epoch = u64_from_chunk(exit_epoch);

            // We are calculating the validator index from the gindex.
            let validator_index =
                (exit_epoch_gindex >> VALIDATOR_TREE_DEPTH) - (1 << VALIDATOR_LIST_TREE_DEPTH);
            // NOTE: This should not fail until there are more than 2^32 validators.
            let validator_index = usize::try_from(validator_index).unwrap();

            Ok((
                validator_index,
                ValidatorInfo {
                    pubkey,
                    effective_balance,
                    activation_epoch,
                    exit_epoch,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>, ssz_multiproofs::Error>>()?;
    assert!(values.next().is_none());
    Ok(validator_cache)
}

/// Extracts an u64 from a 32-byte SSZ chunk.
fn u64_from_chunk(node: &[u8; 32]) -> u64 {
    assert!(node[8..].iter().all(|&b| b == 0));
    u64::from_le_bytes(node[..8].try_into().unwrap())
}
