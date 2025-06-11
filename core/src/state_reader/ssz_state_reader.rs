use super::StateReader;
use crate::{
    Ctx, Epoch, GuestContext, PublicKey, StatePatch, VALIDATOR_LIST_TREE_DEPTH,
    VALIDATOR_TREE_DEPTH, ValidatorIndex, ValidatorInfo, Version,
};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use ssz_multiproofs::Multiproof;
use std::collections::BTreeMap;
use tracing::info;

/// A serializable structure that can be converted into a `SszStateReader`.
#[derive(Clone, Deserialize, Serialize)]
pub struct StateInput<'a> {
    /// Used fields of the BeaconState plus their inclusion proof against the state root.
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
    genesis_validators_root: B256,
    fork_current_version: Version,
    epoch: Epoch,
    validators: BTreeMap<ValidatorIndex, ValidatorInfo>,
    randao: BTreeMap<Epoch, B256>,

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
    /// Converts the `StateInput` into a `SszStateReader`
    /// beacon_root is a known root of the beacon state which is used to verify the multiproof as a sanity check
    pub fn into_state_reader(
        self,
        beacon_root: B256,
        context: &GuestContext,
    ) -> Result<SszStateReader, SszReaderError> {
        let (genesis_validators_root, state_epoch, fork_current_version, validators_root, randao) =
            extract_beacon_state_multiproof(context, &self.beacon_state).map_err(|e| {
                SszReaderError::SszMultiproof {
                    msg: "Failed to extract beacon state multiproof".to_string(),
                    source: e,
                }
            })?;

        self.beacon_state
            .verify(&beacon_root)
            .map_err(|e| SszReaderError::SszVerify {
                msg: "Beacon state root mismatch".to_string(),
                source: e,
            })?;

        let validator_cache =
            extract_validators_multiproof(self.public_keys, &self.active_validators).map_err(
                |e| SszReaderError::SszMultiproof {
                    msg: "Failed to extract active validators multiproof".to_string(),
                    source: e,
                },
            )?;

        self.active_validators
            .verify(&validators_root)
            .map_err(|e| SszReaderError::SszVerify {
                msg: "Validators root mismatch".to_string(),
                source: e,
            })?;

        // TODO: verify state patches
        for (epoch, _patch) in &self.patches {
            assert!(*epoch > state_epoch);
        }
        info!("{} State patches verified", self.patches.len());

        Ok(SszStateReader {
            context,
            genesis_validators_root: genesis_validators_root.into(),
            fork_current_version: fork_current_version[0..4].try_into().unwrap(),
            epoch: state_epoch,
            validators: validator_cache,
            randao,
            patches: self.patches,
        })
    }
}

impl StateReader for SszStateReader<'_> {
    type Error = SszReaderError;
    type Context = GuestContext;

    fn epoch(&self) -> Epoch {
        self.epoch
    }

    fn context(&self) -> &Self::Context {
        self.context
    }

    fn genesis_validators_root(&self) -> B256 {
        self.genesis_validators_root
    }

    fn fork_current_version(&self) -> Result<Version, Self::Error> {
        Ok(self.fork_current_version)
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        assert!(self.epoch >= epoch, "Only historical epochs supported");

        Ok(self
            .validators
            .iter()
            .map(|(idx, validator)| (*idx, validator))
            .filter(move |(_, validator)| validator.is_active_at(epoch)))
    }

    fn randao_mix(&self, epoch: Epoch, index: usize) -> Result<Option<B256>, Self::Error> {
        let randao = if self.epoch == epoch {
            self.randao.get(&(index as Epoch))
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

/// Extracts the relevant fields from the multiproof of the BeaconState.
/// Currently includes:
/// - genesis_validators_root
/// - slot
/// - fork_current_version
/// - validators_root
/// - randao_mixes (only the ones used)
fn extract_beacon_state_multiproof(
    ctx: &GuestContext,
    beacon_state: &Multiproof<'_>,
) -> Result<(B256, Epoch, [u8; 4], B256, BTreeMap<Epoch, B256>), ssz_multiproofs::Error> {
    let mut beacon_state_iter = beacon_state.values();
    let genesis_validators_root =
        beacon_state_iter.next_assert_gindex(ctx.genesis_validators_root_gindex())?;
    let slot = beacon_state_iter.next_assert_gindex(ctx.slot_gindex())?;
    let fork_current_version =
        beacon_state_iter.next_assert_gindex(ctx.fork_current_version_gindex())?;
    let validators_root = beacon_state_iter.next_assert_gindex(ctx.validators_gindex())?;

    // the remaining values of the beacon state correspond to RANDAO
    let randao_gindex_base = ctx.randao_mixes_0_gindex();
    let randao = beacon_state_iter
        .map(|(gindex, randao)| {
            // 0 <= index <= EPOCHS_PER_HISTORICAL_VECTOR
            assert!(gindex >= randao_gindex_base);
            assert!(gindex <= randao_gindex_base + ctx.epochs_per_historical_vector());

            let index = gindex - randao_gindex_base;
            (index, B256::from(randao))
        })
        .collect();

    Ok((
        genesis_validators_root.into(),
        ctx.compute_epoch_at_slot(u64_from_chunk(slot)),
        fork_current_version[0..4].try_into().unwrap(),
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
