extern crate alloc;

use core::fmt;

use alloy_primitives::B256;
#[cfg(feature = "host")]
mod beacon_state;
mod bls;
mod committee_cache;
mod consensus_state;
mod context;
#[cfg(feature = "host")]
mod input_builder;
mod shuffle_list;
mod state_patch;
mod state_reader;
mod verify;

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
pub const VALIDATOR_REGISTRY_LIMIT: u64 = 1099511627776; // 2**40
pub const VALIDATOR_LIST_TREE_DEPTH: u32 = VALIDATOR_REGISTRY_LIMIT.ilog2() + 1; // 41
pub const VALIDATOR_TREE_DEPTH: u32 = 3;

/// The depth of the Merkle tree of the BeaconState container.
pub const BEACON_STATE_TREE_DEPTH: u32 = 6;

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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, TreeHash)]
pub struct AttestationData {
    pub slot: Slot,
    pub index: CommitteeIndex,
    pub beacon_block_root: Root,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

// Note: This is was updated in electra.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Attestation {
    pub aggregation_bits: ssz_types::BitList<MaxValidatorsPerSlot>,
    pub data: AttestationData,
    pub signature: Signature,
    pub committee_bits: ssz_types::BitVector<MaxCommitteesPerSlot>,
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

#[cfg(feature = "host")]
impl From<ethereum_consensus::electra::AttestationData> for AttestationData {
    fn from(data: ethereum_consensus::electra::AttestationData) -> Self {
        Self {
            slot: data.slot,
            index: data.index,
            beacon_block_root: data.beacon_block_root,
            source: data.source.into(),
            target: data.target.into(),
        }
    }
}

#[cfg(feature = "host")]
impl<const MAX_VALIDATORS_PER_SLOT: usize, const MAX_COMMITTEES_PER_SLOT: usize>
    From<ethereum_consensus::electra::Attestation<MAX_VALIDATORS_PER_SLOT, MAX_COMMITTEES_PER_SLOT>>
    for Attestation
{
    fn from(
        attestation: ethereum_consensus::electra::Attestation<
            MAX_VALIDATORS_PER_SLOT,
            MAX_COMMITTEES_PER_SLOT,
        >,
    ) -> Self {
        let agg_bits_ser = ssz_rs::serialize(&attestation.aggregation_bits)
            .expect("Failed to serialize aggregation bits");
        let committee_bits_ser = ssz_rs::serialize(&attestation.committee_bits)
            .expect("Failed to serialize committee bits");

        Self {
            aggregation_bits: ssz_types::BitList::from_bytes(agg_bits_ser.into())
                .expect("Failed to deserialize aggregation bits"),
            data: attestation.data.into(),
            signature: attestation.signature.into(),
            committee_bits: ssz_types::BitVector::from_bytes(committee_bits_ser.into())
                .expect("Failed to deserialize committee bits"),
        }
    }
}
