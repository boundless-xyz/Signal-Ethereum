extern crate alloc;

use alloy_primitives::B256;
use ssz_rs::prelude::*;
#[cfg(feature = "host")]
mod beacon_state;
mod bls;
mod committee_cache;
mod context;
mod shuffle_list;
mod state_patch;
mod state_reader;
mod verify;

#[cfg(feature = "host")]
pub use beacon_state::*;
pub use committee_cache::*;
pub use context::*;
pub use state_patch::*;
pub use state_reader::*;
pub use verify::*;

pub use bls::*;

// Need to redefine/redeclare a bunch of types and constants because we can't use ssz-rs and ethereum-consensus in the guest

type Epoch = u64;
type Slot = u64;
type CommitteeIndex = usize;
type ValidatorIndex = usize;
type Root = B256;
pub type Version = [u8; 4];
pub type ForkDigest = [u8; 4];
pub type Domain = [u8; 32];

// Mainnet constants
pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048; // 2**11
pub const MAX_COMMITTEES_PER_SLOT: usize = 64; // 2**6
pub const BEACON_ATTESTER_DOMAIN: [u8; 4] = 1u32.to_le_bytes();
pub const VALIDATOR_REGISTRY_LIMIT: u64 = 1099511627776; // 2**40
pub const VALIDATOR_LIST_TREE_DEPTH: u32 = VALIDATOR_REGISTRY_LIMIT.ilog2() + 1; // 41
pub const VALIDATOR_TREE_DEPTH: u32 = 3;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Input {
    pub trusted_checkpoint: Checkpoint, // Already finalized Checkpoint
    pub candidate_checkpoint: Checkpoint, // Justified Checkpoint we are trying to finalize

    pub attestations: Vec<
        Attestation<
            { MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT },
            MAX_COMMITTEES_PER_SLOT,
        >,
    >,

    pub trusted_checkpoint_state_root: Root, // The state root at trusted_checkpoint
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
            pubkey: v.public_key.clone().into(),
            effective_balance: v.effective_balance,
            activation_epoch: v.activation_epoch,
            exit_epoch: v.exit_epoch,
        }
    }
}

#[derive(Clone, Debug, SimpleSerialize, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttestationData {
    pub slot: Slot,
    pub index: CommitteeIndex,
    pub beacon_block_root: Root,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

// Note: This is was updated in electra.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Attestation<const MAX_VALIDATORS_PER_SLOT: usize, const MAX_COMMITTEES_PER_SLOT: usize> {
    pub aggregation_bits: Bitlist<MAX_VALIDATORS_PER_SLOT>,
    pub data: AttestationData,
    pub signature: Signature,
    pub committee_bits: Bitvector<MAX_COMMITTEES_PER_SLOT>,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    SimpleSerialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Root,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Link(pub Checkpoint, pub Checkpoint);

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
    for Attestation<MAX_VALIDATORS_PER_SLOT, MAX_COMMITTEES_PER_SLOT>
{
    fn from(
        attestation: ethereum_consensus::electra::Attestation<
            MAX_VALIDATORS_PER_SLOT,
            MAX_COMMITTEES_PER_SLOT,
        >,
    ) -> Self {
        Self {
            aggregation_bits: attestation.aggregation_bits,
            data: attestation.data.into(),
            signature: attestation.signature.into(),
            committee_bits: attestation.committee_bits,
        }
    }
}
