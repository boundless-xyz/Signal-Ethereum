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

use core::fmt::Debug;

use beacon_types::{EthSpec, MainnetEthSpec};
use ssz_types::typenum::{U5, U100, Unsigned};

/// Configurable trait for values specific to the ZKasper instantiation
///
/// This should NOT contain values that are specific to the chain
/// which should be in EthSpec instead.
pub trait ZkasperSpec {
    /// The EthSpec that defines the chain for this Zkasper instantiation
    type EthSpec: EthSpec;

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
    type EthSpec = MainnetEthSpec;
    type EpochLookaheadLimit = U100; // Arbitrary value picked for now
    type MinSupportedVersion = U5; // Electra
    type MaxSupportedVersion = U5; // Electra
}
