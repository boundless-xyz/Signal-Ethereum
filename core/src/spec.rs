use core::fmt::Debug;

use ssz_types::typenum::{U5, U100, Unsigned};

/// Configurable trait for values specific to the ZKasper instantiation
///
/// This should NOT contain values that are specific to the chain
/// which should be in EthSpec instead.
pub trait ZkasperSpec {
    /// The maximum allowable number of epochs past the trusted state to look ahead
    /// when attempting to finalize a checkpoint.
    type EpochLookaheadLimit: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    /// Minimum supported version of this instantiation of the protocol.
    type MinSupportedVersion: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    /// Maximum supported version of this instantiation of the protocol.
    type MaxSupportedVersion: Unsigned + Clone + Sync + Send + Debug + PartialEq;

    fn is_supported_fork(version: &[u8; 4]) -> bool {
        let version = &version[0]; // currently only the first byte is used for versioning
        version >= &Self::MinSupportedVersion::to_u8()
            && version <= &Self::MaxSupportedVersion::to_u8()
    }

    fn epoch_lookahead_limit() -> u64 {
        Self::EpochLookaheadLimit::to_u64()
    }
}

/// Ethereum Foundation specifications.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DefaultSpec;

impl ZkasperSpec for DefaultSpec {
    type EpochLookaheadLimit = U100; // Arbitrary value picked for now
    type MinSupportedVersion = U5; // Electra
    type MaxSupportedVersion = U5; // Electra
}
