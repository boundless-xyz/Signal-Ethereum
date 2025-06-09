extern crate alloc;

use core::fmt;

use alloy_primitives::B256;
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
pub type Root = B256;
pub type Version = [u8; 4];
pub type ForkDigest = [u8; 4];
pub type Domain = [u8; 32];

// Mainnet constants
pub type MaxValidatorsPerSlot = U131072; // 2**11
pub type MaxCommitteesPerSlot = U64; // 2**6
pub const BEACON_ATTESTER_DOMAIN: [u8; 4] = 1u32.to_le_bytes();
pub const VALIDATOR_REGISTRY_LIMIT: u64 = 2u64.pow(40);
pub const VALIDATOR_LIST_TREE_DEPTH: u32 = VALIDATOR_REGISTRY_LIMIT.ilog2() + 1; // 41
pub const VALIDATOR_TREE_DEPTH: u32 = 3;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Input {
    pub consensus_state: ConsensusState,
    pub link: Vec<Link>,

    pub attestations: Vec<Vec<Attestation>>,

    pub trusted_checkpoint_state_root: Root, // The state root at trusted_checkpoint
}

impl fmt::Debug for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Input")
            .field("consensus_state", &self.consensus_state)
            .field("link", &self.link)
            .field(
                "attestations",
                &self
                    .attestations
                    .iter()
                    .map(|a| a.len())
                    .collect::<Vec<usize>>(),
            )
            .field(
                "trusted_checkpoint_state_root",
                &self.trusted_checkpoint_state_root,
            )
            .finish()
    }
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ValidatorInfo {
    pub pubkey: PublicKey,
    pub effective_balance: u64,
    pub activation_epoch: u64,
    pub exit_epoch: u64,
}

impl ValidatorInfo {
    /// Checks if the validator is active at the given epoch.
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
    serde::Serialize,
    serde::Deserialize,
    Default,
    TreeHash,
)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Root,
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
