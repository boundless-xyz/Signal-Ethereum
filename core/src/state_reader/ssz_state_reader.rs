use std::borrow::Cow;
use std::collections::BTreeMap;
use std::mem::MaybeUninit;

use crate::{Epoch, PublicKey, VALIDATOR_LIST_TREE_DEPTH, VALIDATOR_TREE_DEPTH};
use crate::{StatePatch, ValidatorInfo};
use alloy_primitives::B256;
use blst::blst_fp;
use serde::{Deserialize, Serialize};
use ssz_multiproofs::Multiproof;
use tracing::{info, warn};

use super::StateReader;
type Node = [u8; 32];

#[derive(Default)]
pub struct ComputedCache {
    // TODO(ec2): We should really only need the active ones. Can store in a map.
    pub validators: BTreeMap<u64, ValidatorInfo>,
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

    // TODO(ec2): We can give hints from tthe host for the active validator count so we can proactively allocate memory
    #[serde(skip)]
    pub cache: ComputedCache,
}

const FOUR: blst_fp = blst_fp {
    l: [
        0xaa270000000cfff3,
        0x53cc0032fc34000a,
        0x478fe97a6b0a807f,
        0xb1d37ebee6ba24d7,
        0x8ec9733bbf78ab2f,
        0x09d645513d83de7e,
    ],
};

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

        let mut validator_cache = BTreeMap::new();
        let mut pubkey_g1_compressed: [u8; 48] = [0; 48];
        let mut values = self.validators.values();

        let mut validator_count = 0;

        for i in 0.. {
            let pk0_maybe = values.next();
            let pk1_maybe = values.next();
            if pk1_maybe.is_none() {
                // we are at the end of the multiproof, the last read value is the total validator count (not just the actives ones)
                let (_, v_count) = pk0_maybe.unwrap();
                validator_count = u64_from_b256(v_count, 0);
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
                (exit_epoch_gindex >> VALIDATOR_TREE_DEPTH) - (1 << VALIDATOR_LIST_TREE_DEPTH);

            pubkey_g1_compressed[0..32].copy_from_slice(&pk0[0..32]);
            pubkey_g1_compressed[32..48].copy_from_slice(&pk1[0..16]);

            let mut uncompressed_key_bytes = self.public_keys[i * 96..(i + 1) * 96].to_vec();
            // TODO(ec2): Do we need to verify the sign of the Y-coordinate?
            let _y_sign = (pubkey_g1_compressed[0] >> 5) & 1;

            // check that the compressed x from merkle state is the same as the one we just pass in
            // Removes the first 3 bits (the flags)
            uncompressed_key_bytes[0] &= 0b0001_1111;
            pubkey_g1_compressed[0] &= 0b0001_1111;

            if pubkey_g1_compressed[0..48] != uncompressed_key_bytes[0..48] {
                warn!(
                    "Compressed x from merkle state does not match the one we just pass in: {}",
                    i
                );
            }
            // assert_eq!(
            //     pubkey_g1_compressed[0..48],
            //     uncompressed_key_bytes[0..48],
            //     "Compressed x from merkle state does not match the one we just pass in: {}",
            //     i
            // );

            let fp_x_cubed_plus_4 = unsafe {
                let mut x = MaybeUninit::<blst_fp>::uninit();
                blst::blst_fp_from_bendian(x.as_mut_ptr(), uncompressed_key_bytes[0..48].as_ptr());

                // Calculate x³ + 4
                let mut x_cubed = MaybeUninit::<blst_fp>::uninit();
                blst::blst_fp_sqr(x_cubed.as_mut_ptr(), &x.assume_init());
                blst::blst_fp_mul(
                    x_cubed.as_mut_ptr(),
                    &x_cubed.assume_init(),
                    &x.assume_init(),
                );
                blst::blst_fp_add(x_cubed.as_mut_ptr(), &x_cubed.assume_init(), &FOUR);
                x_cubed.assume_init()
            };

            let y_squared = unsafe {
                let mut fp_y = MaybeUninit::<blst_fp>::uninit();
                blst::blst_fp_from_bendian(
                    fp_y.as_mut_ptr(),
                    uncompressed_key_bytes[48..96].as_ptr(),
                );
                blst::blst_fp_sqr(fp_y.as_mut_ptr(), &fp_y.assume_init());
                fp_y.assume_init()
            };
            assert_eq!(y_squared, fp_x_cubed_plus_4);

            let pubkey = PublicKey::from_bytes(&uncompressed_key_bytes).unwrap();

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
        self.cache.validator_count = validator_count as u64;
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
                } = &self.cache.validators[&(idx as u64)];
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
        let mut activation = self
            .cache
            .validators
            .get(&(validator_index as u64))
            .ok_or(())?
            .activation_epoch;
        let mut exit = self
            .cache
            .validators
            .get(&(validator_index as u64))
            .ok_or(())?
            .exit_epoch;
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
        let mut c = self.cache.validator_count;
        for (_, patch) in self.patches.iter().filter(|(e, _)| *e <= &epoch) {
            c += patch.n_deposits_processed as u64;
        }
        Ok(Some(c as usize))
    }

    fn get_total_active_balance(&self, epoch: crate::Epoch) -> Result<u64, Self::Error> {
        self.aggregate_validator_keys_and_balance(self.get_active_validator_indices(epoch)?)
            .map(|x| x.1)
    }

    fn get_active_validator_indices(
        &self,
        epoch: crate::Epoch,
    ) -> Result<impl Iterator<Item = usize>, Self::Error> {
        Ok(self
            .cache
            .validators
            .keys()
            .filter_map(move |validator_index| {
                if let Ok((activation, exit)) =
                    self.get_validator_activation_and_exit_epochs(epoch, *validator_index as usize)
                {
                    if activation <= epoch && epoch < exit {
                        Some(*validator_index as usize)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }))
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
