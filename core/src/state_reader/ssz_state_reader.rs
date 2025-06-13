use super::StateReader;
use crate::{
    Ctx, Epoch, GuestContext, PublicKey, VALIDATOR_LIST_TREE_DEPTH, VALIDATOR_TREE_DEPTH,
    ValidatorIndex, ValidatorInfo, Version,
};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use ssz_multiproofs::Multiproof;
use std::collections::BTreeMap;

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

    /// Randao mixes. Double map epoch -> index -> mix.
    pub randao: BTreeMap<Epoch, BTreeMap<usize, B256>>,
}

pub struct SszStateReader<'a> {
    context: &'a GuestContext,
    genesis_validators_root: B256,
    fork_current_version: Version,
    epoch: Epoch,
    validators: BTreeMap<ValidatorIndex, ValidatorInfo>,

    randao: BTreeMap<Epoch, BTreeMap<usize, B256>>,
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
    MissingRandao(Epoch),
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
    /// Converts the `StateInput` into a `SszStateReader`
    /// beacon_root is a known root of the beacon state which can optionally be used to verify the
    /// SSZ proof of all fields and allow the data to be trusted (if the beacon_root is trusted).
    pub fn into_state_reader(
        self,
        beacon_root: Option<B256>,
        context: &GuestContext,
    ) -> Result<SszStateReader, SszReaderError> {
        let (genesis_validators_root, state_epoch, fork_current_version, validators_root) =
            extract_beacon_state_multiproof(context, &self.beacon_state)
                .context("Failed to extract beacon state multiproof")?;

        if let Some(beacon_root) = beacon_root {
            self.beacon_state
                .verify(&beacon_root)
                .context("Beacon state root mismatch")?;
        }

        let validator_cache =
            extract_validators_multiproof(self.public_keys, &self.active_validators)
                .context("Failed to extract active validators multiproof")?;

        self.active_validators
            .verify(&validators_root)
            .context("Validators root mismatch")?;

        Ok(SszStateReader {
            context,
            genesis_validators_root: genesis_validators_root.into(),
            fork_current_version: fork_current_version[0..4].try_into().unwrap(),
            epoch: state_epoch,
            validators: validator_cache,
            randao: self.randao,
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
        Ok(self
            .validators
            .iter()
            .map(|(idx, validator)| (*idx, validator))
            .filter(move |(_, validator)| validator.is_active_at(epoch)))
    }

    fn randao_mix(&self, epoch: Epoch, index: usize) -> Result<Option<B256>, Self::Error> {
        Ok(self
            .randao
            .get(&epoch)
            .ok_or(Self::Error::MissingRandao(epoch))?
            .get(&index)
            .cloned())
    }
}

/// Extracts the relevant fields from the multiproof of the BeaconState.
/// Currently includes:
/// - genesis_validators_root
/// - epoch
/// - fork_current_version
/// - validators_root
fn extract_beacon_state_multiproof(
    ctx: &GuestContext,
    beacon_state: &Multiproof<'_>,
) -> Result<(B256, Epoch, [u8; 4], B256), ssz_multiproofs::Error> {
    let mut beacon_state_iter = beacon_state.values();
    let genesis_validators_root =
        beacon_state_iter.next_assert_gindex(ctx.genesis_validators_root_gindex())?;
    let slot = beacon_state_iter.next_assert_gindex(ctx.slot_gindex())?;
    let fork_current_version =
        beacon_state_iter.next_assert_gindex(ctx.fork_current_version_gindex())?;
    let validators_root = beacon_state_iter.next_assert_gindex(ctx.validators_gindex())?;

    Ok((
        genesis_validators_root.into(),
        ctx.compute_epoch_at_slot(u64_from_chunk(slot)),
        fork_current_version[0..4].try_into().unwrap(),
        validators_root.into(),
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
