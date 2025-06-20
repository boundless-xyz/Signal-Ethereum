use super::StateReader;
use crate::{
    ConsensusState, Ctx, Epoch, GuestContext, PublicKey, RandaoMixIndex, Root, Slot, StatePatch,
    VALIDATOR_LIST_TREE_DEPTH, VALIDATOR_TREE_DEPTH, ValidatorIndex, ValidatorInfo, Version,
};
use alloy_primitives::B256;
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

pub struct SszStateReader<'a> {
    context: &'a GuestContext,

    // beacon state fields
    genesis_validators_root: B256,
    fork_current_version: Version,
    validators: BTreeMap<ValidatorIndex, ValidatorInfo>,

    // additional unverified data
    patches: BTreeMap<Epoch, StatePatch>,
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
    pub fn into_state_reader<'a>(
        self,
        context: &'a GuestContext,
        consensus_state: &ConsensusState,
    ) -> Result<SszStateReader<'a>, SszReaderError> {
        // check that the beacon block proofs correspond to the finalized epoch boundary block
        self.beacon_block
            .verify(&consensus_state.finalized_checkpoint.root)
            .map_err(|e| SszReaderError::SszVerify {
                msg: "Beacon block root mismatch".to_string(),
                source: e,
            })?;
        // extract the proven state root from the beacon block
        let state_root =
            extract_beacon_block_multiproof(context, &self.beacon_block).map_err(|e| {
                SszReaderError::SszMultiproof {
                    msg: "Invalid beacon block proof".to_string(),
                    source: e,
                }
            })?;

        // check that the beacon state proofs correspond to the state of the beacon block
        self.beacon_state
            .verify(&state_root)
            .map_err(|e| SszReaderError::SszVerify {
                msg: "Beacon state root mismatch".to_string(),
                source: e,
            })?;
        let (
            genesis_validators_root,
            slot,
            fork_current_version,
            validators_root,
            finalized_checkpoint_epoch,
        ) = extract_beacon_state_multiproof(context, &self.beacon_state).map_err(|e| {
            SszReaderError::SszMultiproof {
                msg: "Invalid beacon state proof".to_string(),
                source: e,
            }
        })?;

        // check that the validator proofs correspond to the validators root of the beacon state
        self.active_validators
            .verify(&validators_root)
            .map_err(|e| SszReaderError::SszVerify {
                msg: "Validators root mismatch".to_string(),
                source: e,
            })?;
        let mut validators = extract_validators_multiproof(
            &self.active_validators,
            self.public_keys,
            consensus_state.finalized_checkpoint.epoch,
        )
        .map_err(|e| SszReaderError::SszMultiproof {
            msg: "Invalid validators proof".to_string(),
            source: e,
        })?;

        let state_epoch = context.compute_epoch_at_slot(slot);

        // Our trusted state is from `slot`, but our consensus state is at
        // `current_justified_checkpoint`. This means that we have missed all the state changes
        // introduced by the intermediate `state_transition()` calls. From the trusted state, we
        // only use the validator registry, so it boils down to the process_registry_updates().
        for epoch in state_epoch..=consensus_state.current_justified_checkpoint.epoch {
            // By definition, we know that the next finalization will happen at the
            // `current_justified_checkpoint`.
            let finalized_checkpoint_epoch =
                if epoch < consensus_state.current_justified_checkpoint.epoch {
                    finalized_checkpoint_epoch
                } else {
                    consensus_state.finalized_checkpoint.epoch
                };

            process_registry_updates(context, &mut validators, finalized_checkpoint_epoch, epoch);
        }

        // state patches must only be used for future epochs
        if let Some((epoch, _)) = self.patches.first_key_value() {
            assert!(epoch > &state_epoch);
        }

        Ok(SszStateReader {
            context,
            genesis_validators_root,
            fork_current_version,
            validators,
            patches: self.patches,
        })
    }
}

impl StateReader for SszStateReader<'_> {
    type Error = SszReaderError;
    type Context = GuestContext;

    fn context(&self) -> &Self::Context {
        self.context
    }

    fn genesis_validators_root(&self) -> Result<Root, Self::Error> {
        Ok(self.genesis_validators_root)
    }

    fn fork_current_version(&self, _epoch: Epoch) -> Result<Version, Self::Error> {
        // TODO: the fork current version might change
        Ok(self.fork_current_version)
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
        let randao = self
            .patches
            .get(&epoch)
            .ok_or(Self::Error::MissingStatePatch(epoch))?
            .randao_mixes
            .get(&index);

        Ok(randao.cloned())
    }
}

/// Extracts the relevant fields from the inclusion proof of the beacon block.
///
/// Currently, includes:
/// - state_root
fn extract_beacon_block_multiproof(
    _ctx: &GuestContext,
    beacon_block: &Multiproof<'_>,
) -> Result<B256, ssz_multiproofs::Error> {
    let mut values = beacon_block.values();
    // TODO: Make index constant
    let state_root: &[u8; 32] = values.next_assert_gindex(11)?;

    assert!(values.next().is_none());

    Ok(state_root.into())
}

/// Extracts the relevant fields from the multiproof of the BeaconState.
///
/// Currently, includes:
/// - genesis_validators_root
/// - slot
/// - fork_current_version
/// - validators_root
/// - finalized_checkpoint.epoch
fn extract_beacon_state_multiproof(
    ctx: &GuestContext,
    beacon_state: &Multiproof<'_>,
) -> Result<(B256, Slot, [u8; 4], B256, Epoch), ssz_multiproofs::Error> {
    let mut values = beacon_state.values();
    let genesis_validators_root =
        values.next_assert_gindex(ctx.genesis_validators_root_gindex())?;
    let slot = values.next_assert_gindex(ctx.slot_gindex())?;
    let fork_current_version = values.next_assert_gindex(ctx.fork_current_version_gindex())?;
    let validators_root = values.next_assert_gindex(ctx.validators_gindex())?;
    let finalized_checkpoint_epoch =
        values.next_assert_gindex(ctx.finalized_checkpoint_epoch_gindex())?;

    assert!(values.next().is_none());

    Ok((
        genesis_validators_root.into(),
        u64_from_chunk(slot),
        fork_current_version[0..4].try_into().unwrap(),
        validators_root.into(),
        u64_from_chunk(finalized_checkpoint_epoch),
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

            assert!(exit_epoch <= current_epoch);
        } else {
            let pubkey = pubkeys.next().unwrap();

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

/// Updates the `Registry`, i.e. the part of the beacon state that stores validator records. This is called during epoch processing.
///
/// See: https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#modified-process_registry_updates
fn process_registry_updates(
    ctx: &impl Ctx,
    registry: &mut BTreeMap<ValidatorIndex, ValidatorInfo>,
    finalized_checkpoint_epoch: Epoch,
    current_epoch: Epoch,
) {
    let activation_epoch = compute_activation_exit_epoch(ctx, current_epoch);

    for validator in registry.values_mut() {
        // process activation eligibility:
        if validator.is_eligible_for_activation_queue(ctx) {
            validator.activation_eligibility_epoch = current_epoch + 1;
        }
        // process activations:
        if validator.is_eligible_for_activation(finalized_checkpoint_epoch) {
            validator.activation_epoch = activation_epoch;
        }
    }
}

fn compute_activation_exit_epoch(ctx: &impl Ctx, epoch: Epoch) -> Epoch {
    epoch + 1 + ctx.max_seed_lookahead()
}

/// Extracts an u64 from a 32-byte SSZ chunk.
fn u64_from_chunk(node: &[u8; 32]) -> u64 {
    assert!(node[8..].iter().all(|&b| b == 0));
    u64::from_le_bytes(node[..8].try_into().unwrap())
}
