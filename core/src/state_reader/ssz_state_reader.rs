use std::collections::BTreeMap;

use crate::{Epoch, PublicKey, VALIDATOR_LIST_TREE_DEPTH, VALIDATOR_TREE_DEPTH};
use crate::{StatePatch, ValidatorInfo};
use serde::{Deserialize, Serialize};
use ssz_multiproofs::Multiproof;
use tracing::info;

use super::StateReader;
type Node = [u8; 32];

#[derive(Default)]
pub struct ComputedCache {
    // TODO(ec2): We should really only need the active ones. Can store in a map.
    pub validators: BTreeMap<u64, ValidatorInfo>,
    pub randao: [u8; 32],
    pub validator_count: u64,
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

        let mut validator_cache = BTreeMap::new();
        let mut buf: [u8; 48] = [0; 48];
        let mut values = self.validators.values();

        let mut read_vcount = 0;

        for _i in 0..validator_count {
            let pk0_maybe = values.next();
            let pk1_maybe = values.next();
            if pk1_maybe.is_none() {
                // we are at the end of the multiproof, the last read value is the total validator count (not just the actives ones)
                let (_, v_count) = pk0_maybe.unwrap();
                read_vcount = u64_from_b256(v_count, 0);
                break;
            }
            let (_, pk0) = pk0_maybe.unwrap();

            let (_, pk1) = pk1_maybe.unwrap();

            let (_, effective_balance) = values.next().unwrap();
            let effective_balance = u64_from_b256(effective_balance, 0);

            let (_, activation_epoch) = values.next().unwrap();
            let activation_epoch = u64_from_b256(activation_epoch, 0);

            let (exit_epoch_gindex, exit_epoch) = values.next().unwrap();
            let exit_epoch = u64_from_b256(exit_epoch, 0);

            // We are calulating the validator index from the gindex.
            let validator_index =
                (exit_epoch_gindex >> VALIDATOR_TREE_DEPTH) - (1 << VALIDATOR_LIST_TREE_DEPTH) + 1;

            buf[0..32].copy_from_slice(&pk0[0..32]);
            buf[32..48].copy_from_slice(&pk1[0..16]);

            let pubkey = PublicKey::from_bytes(buf.as_slice()).unwrap();
            #[cfg(not(feature = "host"))]
            if read_vcount % 50000 == 0 {
                info!("Validator Cache Construction {}", read_vcount);
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
        assert_eq!(read_vcount, validator_count);

        assert!(
            values.next().is_none(),
            "Validator multiproof has more than expected values"
        );

        self.cache.validators = validator_cache;
        self.cache.validator_count = read_vcount as u64;
        self.cache.randao = *randao;
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
        indices: &[usize],
    ) -> Result<(Vec<PublicKey>, u64), Self::Error> {
        let mut pk_acc: Vec<PublicKey> = Vec::with_capacity(indices.len());
        let mut bal_acc = 0;
        for idx in indices.iter() {
            let ValidatorInfo {
                pubkey: pk,
                effective_balance: bal,
                ..
            } = &self
                .cache
                .validators
                .get(&(*idx as u64))
                .expect("Validator not found. Cache is incorrectly constructed");
            pk_acc.push(pk.clone());
            bal_acc += bal;
        }
        Ok((pk_acc, bal_acc))
    }

    fn get_validator_activation_and_exit_epochs(
        &self,
        epoch: crate::Epoch,
        validator_index: usize,
    ) -> Result<(u64, u64), Self::Error> {
        if let Some(&ValidatorInfo {
            mut activation_epoch,
            mut exit_epoch,
            ..
        }) = self.cache.validators.get(&(validator_index as u64))
        {
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
                        validator_index, activation_epoch, exit_epoch
                    );
                    activation_epoch = *epoch;
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
                        validator_index, activation_epoch, exit_epoch
                    );
                    exit_epoch = *epoch;
                }
            }

            Ok((activation_epoch, exit_epoch))
        } else {
            return Err(());
        }
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
        self.aggregate_validator_keys_and_balance(&self.get_active_validator_indices(epoch)?)
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
}

/// Slice an 8 byte u64 out of a 32 byte chunk
/// pos gives the position (e.g. first 8 bytes, second 8 bytes, etc.)
fn u64_from_b256(node: &Node, pos: usize) -> u64 {
    u64::from_le_bytes(node[pos * 8..(pos + 1) * 8].try_into().unwrap())
}
