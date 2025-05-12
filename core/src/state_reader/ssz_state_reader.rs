use std::collections::BTreeMap;

use crate::{Epoch, PublicKey};
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
    pub validators: Vec<ValidatorInfo>,
    pub randao: [u8; 32],
    pub validator_count: u64,
    pub genesis_validators_root: B256,
    pub fork_version: [u8; 4],
}

#[derive(Deserialize, Serialize)]
pub struct SszStateReader<'a> {
    pub trusted_epoch: u64,
    #[serde(borrow)]
    pub beacon_state: Multiproof<'a>,
    #[serde(borrow)]
    pub validators: Multiproof<'a>,
    pub patches: BTreeMap<Epoch, StatePatch>,

    // TODO(ec2): We can give hints from tthe host for the active validator count so we can proactively allocate memory
    #[serde(skip)]
    pub cache: ComputedCache,
}

impl SszStateReader<'_> {
    #[tracing::instrument(skip(self, trusted_state_root))]
    pub fn verify_and_cache(&mut self, trusted_state_root: [u8; 32]) {
        // TODO(ec2): verify patches are valid
        info!("Patches: {:?}", self.patches);
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
        let validator_count = self.validators.get(3).unwrap();
        let validator_count = u64_from_b256(validator_count, 0);

        let mut validator_cache = Vec::new();
        let mut buf: [u8; 48] = [0; 48];
        let mut values = self.validators.values();

        for _i in 0..validator_count {
            let (_, pk0) = values.next().unwrap();
            buf[0..32].copy_from_slice(&pk0[0..32]);
            let (_, pk1) = values.next().unwrap();
            buf[32..48].copy_from_slice(&pk1[0..16]);

            let (_, effective_balance) = values.next().unwrap();
            let effective_balance = u64_from_b256(effective_balance, 0);

            let (_, activation_epoch) = values.next().unwrap();
            let activation_epoch = u64_from_b256(activation_epoch, 0);

            let (_, exit_epoch) = values.next().unwrap();
            let exit_epoch = u64_from_b256(exit_epoch, 0);

            let pubkey = PublicKey::from_bytes(buf.as_slice()).unwrap();
            #[cfg(not(feature = "host"))]
            if _i % 50000 == 0 {
                info!("Validator Cache Construction {}/{}", _i, validator_count);
            }
            validator_cache.push(ValidatorInfo {
                pubkey,
                effective_balance,
                activation_epoch,
                exit_epoch,
            });
        }
        info!("Validator Cache Construction complete");

        let (_, v_count) = values.next().unwrap();
        let v_count = u64_from_b256(v_count, 0);
        assert_eq!(v_count, validator_count);

        self.cache.validators = validator_cache;
        self.cache.validator_count = v_count;
        self.cache.randao = *randao;
        self.cache.genesis_validators_root = genesis_validators_root.into();
        self.cache.fork_version = fork_current_version[0..4].try_into().unwrap();
        info!(
            "Genesis validators root: {}",
            self.cache.genesis_validators_root
        );
        info!("Fork version: {:?}", self.cache.fork_version);
    }
}

impl StateReader for SszStateReader<'_> {
    type Error = ();

    fn get_randao(&self, epoch: crate::Epoch) -> Result<Option<[u8; 32]>, Self::Error> {
        Ok(self
            .patches
            .get(&(epoch))
            .map(|patch| {
                info!(
                    "Using patch {} for randao for epoch {}, randao: {:?}",
                    epoch - 1,
                    epoch,
                    patch.randao_next
                );
                patch.randao_next
            })
            .or(Some(self.cache.randao)))
    }

    fn aggregate_validator_keys_and_balance(
        &self,
        indices: impl IntoIterator<Item = usize>,
    ) -> Result<(Vec<PublicKey>, u64), Self::Error> {
        let mut bal_acc = 0;
        let pk_acc = indices
            .into_iter()
            .map(|idx| {
                let ValidatorInfo {
                    pubkey,
                    effective_balance,
                    ..
                } = &self.cache.validators[idx];
                bal_acc += effective_balance;

                pubkey.clone()
            })
            .collect();

        Ok((pk_acc, bal_acc))
    }

    fn get_validator_activation_and_exit_epochs(
        &self,
        epoch: crate::Epoch,
        validator_index: usize,
    ) -> Result<(u64, u64), Self::Error> {
        let mut activation = self.cache.validators[validator_index].activation_epoch;
        let mut exit = self.cache.validators[validator_index].exit_epoch;
        // replace any activations/exists with their most recent patch updates if any
        for (epoch, patch) in self.patches.iter().filter(|(e, _)| *e <= &epoch) {
            if patch
                .activations
                .iter()
                .filter(|vi| **vi == validator_index as u32)
                .next_back()
                .is_some()
            {
                info!(
                    "validator {} Patched! activation: {} exit: {}",
                    validator_index, activation, exit
                );
                activation = *epoch;
            }
            if patch
                .exits
                .iter()
                .filter(|vi| **vi == validator_index as u32)
                .next_back()
                .is_some()
            {
                info!(
                    "validator {} Patched! activation: {} exit: {}",
                    validator_index, activation, exit
                );
                exit = *epoch;
            }
        }

        Ok((activation, exit))
    }

    fn get_validator_count(&self, epoch: crate::Epoch) -> Result<Option<usize>, Self::Error> {
        let c = self.validators.get(3).unwrap();
        let mut c = u64_from_b256(c, 0);
        for (_, patch) in self.patches.iter().filter(|(e, _)| *e <= &epoch) {
            c += patch.n_deposits_processed as u64;
        }
        Ok(Some(c as usize))
    }

    fn get_total_active_balance(&self, epoch: crate::Epoch) -> Result<u64, Self::Error> {
        self.aggregate_validator_keys_and_balance(self.get_active_validator_indices(epoch)?)
            .map(|x| x.1)
    }

    fn get_active_validator_indices(&self, epoch: crate::Epoch) -> Result<Vec<usize>, Self::Error> {
        Ok((0_usize..self.get_validator_count(epoch)?.unwrap())
            .filter(|validator_index| {
                if let Ok((activation, exit)) =
                    self.get_validator_activation_and_exit_epochs(epoch, *validator_index)
                {
                    activation <= epoch && epoch < exit
                } else {
                    false
                }
            })
            .collect())
    }

    fn genesis_validators_root(&self) -> B256 {
        self.cache.genesis_validators_root
    }

    // TODO(ec2): This needs to be handled for hardforks
    fn fork_version(&self, _epoch: Epoch) -> [u8; 4] {
        self.cache.fork_version
    }
}

/// Slice an 8 byte u64 out of a 32 byte chunk
/// pos gives the position (e.g. first 8 bytes, second 8 bytes, etc.)
fn u64_from_b256(node: &Node, pos: usize) -> u64 {
    u64::from_le_bytes(node[pos * 8..(pos + 1) * 8].try_into().unwrap())
}
