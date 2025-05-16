use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::{
    Epoch, GuestContext, PublicKey, VALIDATOR_LIST_TREE_DEPTH, VALIDATOR_TREE_DEPTH,
    ValidatorIndex, Version,
};
use crate::{StatePatch, ValidatorInfo};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use ssz_multiproofs::Multiproof;
use tracing::info;

use super::StateReader;

type Node = [u8; 32];

#[derive(Default)]
pub struct ComputedCache {
    // TODO(ec2): We should really only need the active ones. Can store in a map.
    pub validators: BTreeMap<ValidatorIndex, ValidatorInfo>,
    pub randao: [u8; 32],
    pub genesis_validators_root: B256,
    pub fork_version: Version,
}

#[derive(Deserialize, Serialize)]
pub struct SszStateReader<'a> {
    pub trusted_epoch: u64,
    #[serde(borrow)]
    pub beacon_state: Multiproof<'a>,
    #[serde(borrow)]
    // Ideally this is only validators that are accessed in the verification of all attestations given to us.
    // The second best thing is to have all the active validators.
    // The worst thing is to have all the validators. This is what we do now.
    // It should be a security issue to underpopulate this list, because Attestation verification will just fail.
    // We may fail to finalize a checkpoint, but we cannot finalize an invalid checkpoint since this is still merkle proved.
    pub validators: Multiproof<'a>,
    pub patches: BTreeMap<Epoch, StatePatch>,

    // chunked in 96
    #[serde(borrow)]
    pub public_keys: Cow<'a, [u8]>,

    #[serde(skip)]
    pub context: Option<&'a GuestContext>,
    // TODO(ec2): We can give hints from tthe host for the active validator count so we can proactively allocate memory
    #[serde(skip)]
    pub cache: ComputedCache,
}

impl<'a> SszStateReader<'a> {
    pub fn verify_and_cache(&mut self, trusted_state_root: [u8; 32], context: &'a GuestContext) {
        // TODO(ec2): verify patches are valid
        let mut beacon_state = self.beacon_state.values();
        let (_, genesis_validators_root) = beacon_state.next().unwrap();
        let (_, fork_current_version) = beacon_state.next().unwrap();

        let (_, validators_root) = beacon_state.next().unwrap();
        let (_, randao) = beacon_state.next().unwrap();

        // merkle verify beacon state root against trusted state root from input
        self.beacon_state
            .verify(&trusted_state_root)
            .expect("Beacon state root mismatch");
        info!("Beacon state root verified");
        // merkle verify validators root
        self.validators
            .verify(validators_root)
            .expect("Validators root mismatch");
        info!("Validators root verified");

        let mut validator_cache = BTreeMap::new();
        let mut values = self.validators.values();

        for i in 0.. {
            let (_, pk0) = match values.next() {
                Some(value) => value,
                None => break,
            };
            let (_, pk1) = values.next().unwrap();

            let (_, effective_balance) = values.next().unwrap();
            let effective_balance = u64_from_b256(effective_balance, 0);

            let (_, activation_epoch) = values.next().unwrap();
            let activation_epoch = u64_from_b256(activation_epoch, 0);

            let (exit_epoch_gindex, exit_epoch) = values.next().unwrap();
            let exit_epoch = u64_from_b256(exit_epoch, 0);

            // We are calulating the validator index from the gindex.
            let validator_index =
                (exit_epoch_gindex >> VALIDATOR_TREE_DEPTH) - (1 << VALIDATOR_LIST_TREE_DEPTH);
            let validator_index = usize::try_from(validator_index).unwrap();

            let uncompressed_key_bytes = &self.public_keys[i * 96..(i + 1) * 96];
            let pubkey = PublicKey::from_bytes(uncompressed_key_bytes).unwrap();

            let computed_compressed = pubkey.to_bytes();

            // asserts that the ssz serialized key corresponds to the decompressed key
            assert_eq!(
                pk0[0..32],
                computed_compressed[0..32],
                "Compressed key mismatch"
            );
            assert_eq!(
                pk1[0..16],
                computed_compressed[32..48],
                "Compressed key mismatch"
            );

            #[cfg(not(feature = "host"))]
            if i % 50000 == 0 {
                info!("Validator Cache Construction at {} validators", i);
            }

            validator_cache.insert(
                validator_index,
                ValidatorInfo {
                    pubkey: pubkey.into(),
                    effective_balance,
                    activation_epoch,
                    exit_epoch,
                },
            );
        }
        info!("Validator Cache Construction complete");

        assert!(
            values.next().is_none(),
            "Validator multiproof has more than expected values"
        );

        self.cache.validators = validator_cache;
        self.cache.randao = *randao;
        self.cache.genesis_validators_root = genesis_validators_root.into();
        self.cache.fork_version = fork_current_version[0..4].try_into().unwrap();
        info!(
            "Genesis validators root: {}",
            self.cache.genesis_validators_root
        );
        info!("Fork version: {:?}", self.cache.fork_version);

        self.context = Some(context);
    }
}

impl StateReader for SszStateReader<'_> {
    type Error = ();
    type Context = GuestContext;

    fn context(&self) -> &Self::Context {
        self.context.unwrap()
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        let patch = self.patches.get(&epoch);
        let iter = self
            .cache
            .validators
            .iter()
            .map(move |(idx, validator)| match patch {
                Some(patch) => (*idx, patch.validators.get(&idx).unwrap_or(validator)),
                None => (*idx, validator),
            });

        Ok(iter.filter(move |(_, validator)| is_active_validator(validator, epoch)))
    }

    fn randao_mix(&self, epoch: Epoch, index: usize) -> Result<Option<B256>, Self::Error> {
        let randao = if self.trusted_epoch == epoch {
            Some(B256::from_slice(&self.cache.randao))
        } else {
            self.patches
                .get(&epoch)
                .map(|patch| patch.randao_mixes.get(&index).cloned().unwrap())
        };

        Ok(randao)
    }

    fn genesis_validators_root(&self) -> B256 {
        self.cache.genesis_validators_root
    }

    // TODO(ec2): This needs to be handled for hardforks
    fn fork_version(&self, _epoch: Epoch) -> Result<Version, Self::Error> {
        Ok(self.cache.fork_version)
    }
}

/// Slice an 8 byte u64 out of a 32 byte chunk
/// pos gives the position (e.g. first 8 bytes, second 8 bytes, etc.)
fn u64_from_b256(node: &Node, pos: usize) -> u64 {
    u64::from_le_bytes(node[pos * 8..(pos + 1) * 8].try_into().unwrap())
}

/// Check if `validator` is active.
fn is_active_validator(validator: &ValidatorInfo, epoch: Epoch) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch
}
