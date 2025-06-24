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

extern crate alloc;
extern crate core;

use crate::serde_utils::DiskAttestation;
use alloy_primitives::B256;
use beacon_types::{ChainSpec, EthSpec, PublicKey};
use core::fmt;
use core::fmt::Display;
use serde::{Deserializer, Serializer};
use serde_with::serde_as;
use std::collections::HashMap;
use tree_hash::TreeHash;

mod attestation;
#[cfg(feature = "host")]
mod beacon_state;
mod bls;
mod committee_cache;
mod consensus_state;
mod guest_gindices;
#[cfg(feature = "host")]
mod input_builder;
mod serde_utils;
mod state_patch;
mod state_reader;
mod threshold;
mod verify;

pub use attestation::*;
#[cfg(feature = "host")]
pub use beacon_state::*;
pub use bls::*;
pub use committee_cache::*;
pub use consensus_state::*;
#[cfg(feature = "host")]
pub use input_builder::*;
use ssz_types::typenum::{U64, U131072};
pub use state_patch::*;
pub use state_reader::*;
pub use threshold::*;
pub use verify::*;

pub type MainnetEthSpec = beacon_types::MainnetEthSpec;
pub type MinimalEthSpec = beacon_types::MinimalEthSpec;
// Need to redefine/redeclare a bunch of types and constants because we can't use ssz-rs and ethereum-consensus in the guest

pub type Epoch = beacon_types::Epoch;
pub type Slot = beacon_types::Slot;
pub type CommitteeIndex = usize;
pub type ValidatorIndex = usize;
pub type RandaoMixIndex = u64;
pub type Root = B256;
pub type Version = [u8; 4];
pub type ForkDigest = [u8; 4];
pub type Domain = B256;
pub type DomainType = [u8; 4];

// Mainnet constants
pub type MaxValidatorsPerSlot = U131072; // 2**11
pub type MaxCommitteesPerSlot = U64; // 2**6
pub const BEACON_ATTESTER_DOMAIN: DomainType = 1u32.to_le_bytes();
pub const VALIDATOR_REGISTRY_LIMIT: u64 = 2u64.pow(40);
pub const VALIDATOR_LIST_TREE_DEPTH: u32 = VALIDATOR_REGISTRY_LIMIT.ilog2() + 1; // 41
pub const VALIDATOR_TREE_DEPTH: u32 = 3;

#[serde_as]
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Input<E: EthSpec> {
    pub state: ConsensusState,
    pub links: Vec<Link>,

    #[serde_as(as = "Vec<Vec<DiskAttestation>>")]
    pub attestations: Vec<Vec<Attestation<E>>>,
}

impl<E: EthSpec> fmt::Debug for Input<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut by_source: HashMap<Checkpoint, usize> = HashMap::new();
        for attestation in self.attestations.iter().flatten() {
            *by_source
                .entry(attestation.data().source.into())
                .or_default() += 1;
        }

        f.debug_struct("Input")
            .field("state", &self.state)
            .field("attestations", &by_source)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorInfo {
    pub pubkey: PublicKey,
    pub effective_balance: u64,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
}

impl ValidatorInfo {
    /// Check if ``validator`` is eligible to be placed into the activation queue.
    pub fn is_eligible_for_activation_queue(&self, spec: &ChainSpec) -> bool {
        self.activation_eligibility_epoch == spec.far_future_epoch
            && self.effective_balance >= spec.min_activation_balance
    }

    /// Check if the validator is eligible for activation with respect to the given state.
    pub fn is_eligible_for_activation(
        &self,
        spec: &ChainSpec,
        finalized_checkpoint_epoch: Epoch,
    ) -> bool {
        // placement in queue if finalized
        self.activation_eligibility_epoch <= finalized_checkpoint_epoch
            // has not yet been activated
            && self.activation_epoch == spec.far_future_epoch
    }

    /// Checks if the validator is active at the given epoch given knowledge of the most recently finalized epoch
    pub fn is_active_at(&self, epoch: Epoch) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }
}

#[cfg(feature = "host")]
impl From<&ethereum_consensus::phase0::Validator> for ValidatorInfo {
    fn from(v: &ethereum_consensus::phase0::Validator) -> Self {
        Self {
            pubkey: PublicKey::deserialize(&v.public_key).unwrap(),
            effective_balance: v.effective_balance,
            activation_epoch: v.activation_epoch.into(),
            activation_eligibility_epoch: v.activation_eligibility_epoch.into(),
            exit_epoch: v.exit_epoch.into(),
        }
    }
}

#[cfg(feature = "host")]
impl From<&beacon_types::Validator> for ValidatorInfo {
    fn from(v: &beacon_types::Validator) -> Self {
        Self {
            pubkey: v.pubkey.decompress().expect("fail to decompress pub key"),
            effective_balance: v.effective_balance,
            activation_epoch: v.activation_epoch,
            activation_eligibility_epoch: v.activation_eligibility_epoch,
            exit_epoch: v.exit_epoch,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq)]
#[repr(transparent)]
pub struct Checkpoint(beacon_types::Checkpoint);

impl TreeHash for Checkpoint {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        beacon_types::Checkpoint::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        beacon_types::Checkpoint::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl Checkpoint {
    pub const fn new(epoch: Epoch, root: Root) -> Self {
        Self(beacon_types::Checkpoint { epoch, root })
    }

    pub fn epoch(&self) -> Epoch {
        self.0.epoch
    }

    pub fn root(&self) -> Root {
        self.0.root
    }
}

impl Display for Checkpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({},{})", self.root(), self.epoch())
    }
}

impl serde::Serialize for Checkpoint {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(serde::Serialize)]
        struct EncCheckpoint<'a> {
            epoch: u64,
            root: &'a B256,
        }
        EncCheckpoint {
            epoch: self.0.epoch.as_u64(),
            root: &self.0.root,
        }
        .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Checkpoint {
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct DecCheckpoint {
            epoch: u64,
            root: B256,
        }
        let dec = DecCheckpoint::deserialize(deserializer)?;
        Ok(Self(beacon_types::Checkpoint {
            epoch: dec.epoch.into(),
            root: dec.root,
        }))
    }
}

impl From<beacon_types::Checkpoint> for Checkpoint {
    fn from(checkpoint: beacon_types::Checkpoint) -> Self {
        Self::new(checkpoint.epoch, checkpoint.root)
    }
}

impl From<Checkpoint> for beacon_types::Checkpoint {
    fn from(checkpoint: Checkpoint) -> Self {
        checkpoint.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Link {
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[cfg(feature = "host")]
impl From<ethereum_consensus::electra::Checkpoint> for Checkpoint {
    fn from(checkpoint: ethereum_consensus::electra::Checkpoint) -> Self {
        Self::new(checkpoint.epoch.into(), checkpoint.root)
    }
}

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $err:expr) => {
        if !$cond {
            return Err($err);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};
    use rand::{Rng, rng};

    #[test]
    fn bincode_input() {
        let mut raw_data = vec![0u8; 512];
        rng().fill(raw_data.as_mut_slice());
        let mut unstructured = Unstructured::new(&raw_data[..]);

        fn checkpoint(u: &mut Unstructured<'_>) -> beacon_types::Checkpoint {
            beacon_types::Checkpoint::arbitrary(u).unwrap()
        }

        let attestation = Attestation::<MainnetEthSpec>::empty_for_signing(
            1,
            1,
            Slot::arbitrary(&mut unstructured).unwrap(),
            Default::default(),
            checkpoint(&mut unstructured),
            checkpoint(&mut unstructured),
            &MainnetEthSpec::default_spec(),
        )
        .unwrap();

        let input = Input::<MainnetEthSpec> {
            state: ConsensusState {
                previous_justified_checkpoint: Checkpoint(checkpoint(&mut unstructured)),
                current_justified_checkpoint: Checkpoint(checkpoint(&mut unstructured)),
                finalized_checkpoint: Checkpoint(checkpoint(&mut unstructured)),
            },
            links: vec![Link {
                source: Checkpoint(checkpoint(&mut unstructured)),
                target: Checkpoint(checkpoint(&mut unstructured)),
            }],
            attestations: vec![vec![attestation]],
        };

        let bytes = bincode::serialize(&input).unwrap();
        let de = bincode::deserialize::<Input<MainnetEthSpec>>(&bytes).unwrap();
        assert_eq!(input, de);
    }
}
