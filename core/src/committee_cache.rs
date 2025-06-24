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

use crate::{Epoch, ValidatorIndex, ensure};
use alloc::{vec, vec::Vec};
use alloy_primitives::B256;
pub use beacon_types::CommitteeCache;
use beacon_types::{ChainSpec, EthSpec};
use core::num::NonZeroUsize;
use swap_or_not_shuffle::shuffle_list;
use tracing::debug;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("Cache is not initialized")]
    NotInitialized,
    #[error("Cache is not initialized at epoch {0}")]
    NotInitializedAtEpoch(Epoch),
    #[error("Zero slots per epoch")]
    ZeroSlotsPerEpoch,
    #[error("Insufficient validators")]
    InsufficientValidators,
    #[error("Unable to shuffle")]
    UnableToShuffle,
    #[error("Too many validators")]
    TooManyValidators,
    #[error("Shuffle index out of bounds: {0}")]
    ShuffleIndexOutOfBounds(usize),
}

// Everything needed to compute the shuffle
pub struct ShuffleData {
    pub(crate) seed: B256,
    pub(crate) indices: Vec<ValidatorIndex>,
    pub(crate) committees_per_slot: u64,
}

/// Return a new, fully initialized cache.
pub fn initialized<E: EthSpec>(
    spec: &ChainSpec,
    ShuffleData {
        seed,
        indices: active_validator_indices,
        committees_per_slot,
    }: ShuffleData,
    epoch: Epoch,
) -> Result<CommitteeCache, Error> {
    // May cause divide-by-zero errors.
    ensure!(committees_per_slot > 0, Error::ZeroSlotsPerEpoch);

    let max_validator_index = *active_validator_indices
        .iter()
        .max()
        .ok_or(Error::InsufficientValidators)?;

    debug!(
        "Shuffling {} active validators for seed: {}",
        active_validator_indices.len(),
        seed
    );
    let shuffling = shuffle_list(
        active_validator_indices,
        spec.shuffle_round_count,
        &seed[..],
        false,
    )
    .ok_or(Error::UnableToShuffle)?;

    // The use of `NonZeroUsize` reduces the maximum number of possible validators by one.
    ensure!(max_validator_index < usize::MAX, Error::TooManyValidators);

    let mut shuffling_positions = vec![<_>::default(); max_validator_index + 1];
    for (i, &v) in shuffling.iter().enumerate() {
        *shuffling_positions
            .get_mut(v)
            .ok_or(Error::ShuffleIndexOutOfBounds(v))? = NonZeroUsize::new(i + 1);
    }

    #[derive(serde::Serialize)]
    struct CommitteeCacheWrapper {
        initialized_epoch: Option<Epoch>,
        shuffling: Vec<usize>,
        shuffling_positions: Vec<Option<NonZeroUsize>>,
        committees_per_slot: u64,
        slots_per_epoch: u64,
    }
    let cache = CommitteeCacheWrapper {
        initialized_epoch: Some(epoch),
        shuffling,
        shuffling_positions,
        committees_per_slot: committees_per_slot,
        slots_per_epoch: E::slots_per_epoch(),
    };
    // We do this because lighthouse's `CommitteeCache` constructor wants to take a beacon state.
    let cache_bytes = serde_json::to_vec(&cache).map_err(|_| Error::UnableToShuffle)?;

    let ret = serde_json::from_slice(&cache_bytes).map_err(|_| Error::UnableToShuffle)?;
    tracing::info!("Committee cache initialized!");
    Ok(ret)
}
