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

use alloy_primitives::B256;
use alloy_rlp::{RlpDecodable, RlpEncodable};
use core::fmt;
use core::fmt::Display;
use std::collections::BTreeMap;

mod attestation;
#[cfg(feature = "host")]
mod beacon_state;
mod bls;
mod committee_cache;
mod consensus_state;
mod context;
mod guest_context;
#[cfg(feature = "host")]
mod input_builder;
mod shuffle_list;
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
pub use context::*;
#[cfg(feature = "host")]
pub use input_builder::*;
use ssz_types::typenum::{U64, U131072};
pub use state_patch::*;
pub use state_reader::*;
pub use threshold::*;
use tree_hash_derive::TreeHash;
pub use verify::*;

// Need to redefine/redeclare a bunch of types and constants because we can't use ssz-rs and ethereum-consensus in the guest

pub type Epoch = u64;
pub type Slot = u64;
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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Input {
    pub state: ConsensusState,
    pub links: Vec<Link>,
    pub attestations: Vec<Vec<Attestation>>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, RlpEncodable, RlpDecodable)]
pub struct Output {
    pub pre_state: ConsensusState,
    pub post_state: ConsensusState,
}

impl Output {
    #[inline]
    pub fn abi_encode(&self) -> Vec<u8> {
        alloy_rlp::encode(self)
    }
}

impl fmt::Debug for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut by_source: BTreeMap<Checkpoint, usize> = BTreeMap::new();
        for attestation in self.attestations.iter().flatten() {
            *by_source.entry(attestation.data.source).or_default() += 1;
        }

        f.debug_struct("Input")
            .field("state", &self.state)
            .field("attestations", &by_source)
            .finish()
    }
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ValidatorInfo {
    pub pubkey: PublicKey,
    pub effective_balance: u64,
    pub activation_eligibility_epoch: u64,
    pub activation_epoch: u64,
    pub exit_epoch: u64,
}

// TODO(willem): Move these to the context once we have decided how we want to do that
const FAR_FUTURE_EPOCH: u64 = Epoch::MAX;

impl ValidatorInfo {
    /// Check if ``validator`` is eligible to be placed into the activation queue.
    pub fn is_eligible_for_activation_queue(&self, ctx: &impl Ctx) -> bool {
        self.activation_eligibility_epoch == FAR_FUTURE_EPOCH
            && self.effective_balance >= ctx.min_activation_balance()
    }

    /// Check if the validator is eligible for activation with respect to the given state.
    pub fn is_eligible_for_activation(&self, finalized_checkpoint_epoch: Epoch) -> bool {
        // placement in queue if finalized
        self.activation_eligibility_epoch <= finalized_checkpoint_epoch
            // has not yet been activated
            && self.activation_epoch == FAR_FUTURE_EPOCH
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
            pubkey: PublicKey::uncompress(&v.public_key).unwrap(),
            effective_balance: v.effective_balance,
            activation_epoch: v.activation_epoch,
            activation_eligibility_epoch: v.activation_eligibility_epoch,
            exit_epoch: v.exit_epoch,
        }
    }
}

#[cfg(feature = "host")]
impl From<&beacon_types::Validator> for ValidatorInfo {
    fn from(v: &beacon_types::Validator) -> Self {
        Self {
            pubkey: PublicKey::uncompress(&v.pubkey.serialize()).unwrap(),
            effective_balance: v.effective_balance,
            activation_epoch: v.activation_epoch.into(),
            activation_eligibility_epoch: v.activation_eligibility_epoch.into(),
            exit_epoch: v.exit_epoch.into(),
        }
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    TreeHash,
    serde::Serialize,
    serde::Deserialize,
    RlpEncodable,
    RlpDecodable,
)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Root,
}

impl Display for Checkpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({},{})", self.root, self.epoch)
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Link {
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[cfg(feature = "host")]
impl From<ethereum_consensus::electra::Checkpoint> for Checkpoint {
    fn from(checkpoint: ethereum_consensus::electra::Checkpoint) -> Self {
        Self {
            epoch: checkpoint.epoch,
            root: checkpoint.root,
        }
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
