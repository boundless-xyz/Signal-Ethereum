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

        let genesis_validators_root = beacon_state
            .next_assert_gindex(context.genesis_validators_root_gindex())
            .unwrap();
        let slot = beacon_state
            .next_assert_gindex(context.slot_gindex())
            .unwrap();
        let fork_current_version = beacon_state
            .next_assert_gindex(context.fork_current_version_gindex())
            .unwrap();
        let validators_root = beacon_state
            .next_assert_gindex(context.validators_gindex())
            .unwrap();

        // the remaining values of the beacon state correspond to RANDAO
        let randao_gindex_base = context.randao_mixes_0_gindex();
        let randao = beacon_state
            .map(|(gindex, randao)| {
                // 0 <= index <= EPOCHS_PER_HISTORICAL_VECTOR
                assert!(gindex >= randao_gindex_base);
                assert!(gindex <= randao_gindex_base + context.epochs_per_historical_vector());

                let index = (gindex - randao_gindex_base).try_into().unwrap();
                (index, B256::from(randao))
            })
            .collect();

        self.beacon_state
            .verify(&root)
            .expect("Beacon state root mismatch");
        info!("Beacon state root verified");

        let state_epoch = context.compute_epoch_at_slot(u64_from_chunk(slot));

        self.active_validators
            .verify(validators_root)
            .expect("Validators root mismatch");
        info!("Validators root verified");

        let mut values = self.active_validators.values();
        let validator_cache = self
            .public_keys
            .into_iter()
            .map(|pubkey| {
                // Note: We do not have to verify the gindices here. This is because the root of the Validators
                // list is verified against the root which is in the top level BeaconState and this is a homogeneous
                // collection. We are also using the exit_epoch_gindex to calculate the validator index.
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
            .collect();
        assert!(values.next().is_none());
        info!("Active validators verified");

        // TODO: verify state patches
        for (epoch, _patch) in &self.patches {
            assert!(*epoch > state_epoch);
        }
        info!("{} State patches verified", self.patches.len());

        SszStateReader {
            context,
            genesis_validators_root: genesis_validators_root.into(),
            fork_current_version: fork_current_version[0..4].try_into().unwrap(),
            epoch: state_epoch,
            validators: validator_cache,
            randao,
            patches: self.patches,
        }
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

        Ok(self
            .validators
            .iter()
            .map(|(idx, validator)| (*idx, validator))
            .filter(move |(_, validator)| is_active_validator(validator, epoch)))
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

/// Extracts an u64 from a 32-byte SSZ chunk.
fn u64_from_chunk(node: &[u8; 32]) -> u64 {
    assert!(node[8..].iter().all(|&b| b == 0));
    u64::from_le_bytes(node[..8].try_into().unwrap())
}

/// Check if `validator` is active.
fn is_active_validator(validator: &ValidatorInfo, epoch: Epoch) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch
}
