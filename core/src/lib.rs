extern crate alloc;
extern crate core;

use alloy_primitives::B256;
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use beacon_types::EthSpec;
use core::fmt;
use core::fmt::Display;
use std::collections::HashMap;
use tree_hash::TreeHash;

mod attestation;
#[cfg(feature = "host")]
mod beacon_state;
mod bls;
mod committee_cache;
mod consensus_state;
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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Input<E: EthSpec> {
    pub state: ConsensusState,
    pub links: Vec<Link>,
    pub attestations: Vec<Vec<Attestation<E>>>,
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
        self.activation_epoch <= epoch.into() && epoch < self.exit_epoch
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
#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
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

impl Encodable for Checkpoint {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        #[derive(RlpEncodable)]
        struct EncCheckpoint<'a> {
            pub epoch: u64,
            pub root: &'a B256,
        }
        let enc_checkpoint = EncCheckpoint {
            epoch: self.0.epoch.as_u64(),
            root: &self.0.root,
        };
        enc_checkpoint.encode(out);
    }
}

impl Decodable for Checkpoint {
    fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
        #[derive(RlpDecodable)]
        struct DecCheckpoint {
            pub epoch: u64,
            pub root: B256,
        }
        let dec_checkpoint = DecCheckpoint::decode(buf)?;
        Ok(Checkpoint(beacon_types::Checkpoint {
            epoch: beacon_types::Epoch::new(dec_checkpoint.epoch),
            root: dec_checkpoint.root,
        }))
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
