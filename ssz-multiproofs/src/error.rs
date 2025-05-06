// Copyright 2024 RISC Zero, Inc.
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[cfg(feature = "builder")]
    #[error("Error in merklization: {0}")]
    Merklization(#[from] ssz_rs::MerkleizationError),

    #[error("No gindices provided to multiproof builder")]
    EmptyProof,

    #[error("Attempted to use an invalid gindex. Cannot be zero")]
    InvalidGeneralizedIndex,

    #[error("Attempted to verify an invalid merkle multiproof")]
    InvalidProof,

    #[error("Root calculated by proof does not match expected root")]
    RootMismatch,

    #[error("attempted to read a value from a multiproof but none remain")]
    MissingValue,

    #[error("requested a value with gindex {} but got gindex {}", .expected, .actual)]
    GIndexMismatch { expected: u64, actual: u64 },
}

pub type Result<T> = std::result::Result<T, Error>;
