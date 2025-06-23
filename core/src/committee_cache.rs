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

use crate::{CommitteeIndex, Epoch, Slot, ValidatorIndex, ensure};
use alloc::{vec, vec::Vec};
use alloy_primitives::B256;
use beacon_types::EthSpec;
use core::num::NonZeroUsize;
use core::ops::Range;
use swap_or_not_shuffle::shuffle_list;
use tracing::debug;

/// Computes and stores the shuffling for an epoch. Provides various getters to allow callers to
/// read the committees for the given epoch.
#[derive(Debug, Default)]
pub struct CommitteeCache<E: EthSpec> {
    initialized_epoch: Option<Epoch>,
    shuffling: Vec<usize>,
    shuffling_positions: Vec<Option<NonZeroUsize>>,
    committees_per_slot: usize,
    slots_per_epoch: usize,
    _spec: core::marker::PhantomData<E>,
}

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

impl<E: EthSpec> CommitteeCache<E> {
    /// Return a new, fully initialized cache.
    pub fn initialized(
        ShuffleData {
            seed,
            indices: active_validator_indices,
            committees_per_slot,
        }: ShuffleData,
        epoch: Epoch,
    ) -> Result<CommitteeCache<E>, Error> {
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
            E::default_spec().shuffle_round_count,
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

        Ok(CommitteeCache {
            initialized_epoch: Some(epoch),
            shuffling,
            shuffling_positions,
            committees_per_slot: committees_per_slot.try_into().unwrap(),
            slots_per_epoch: E::slots_per_epoch() as usize,
            _spec: core::marker::PhantomData,
        })
    }

    /// Returns `true` if the cache has been initialized at the supplied `epoch`.
    ///
    /// An non-initialized cache does not provide any useful information.
    pub fn is_initialized_at(&self, epoch: Epoch) -> bool {
        Some(epoch) == self.initialized_epoch
    }

    /// Returns the shuffled list of active validator indices for the initialized epoch.
    ///
    /// Always returns `&[]` for a non-initialized epoch.
    pub fn shuffling(&self) -> &[usize] {
        &self.shuffling
    }

    /// Get the Beacon committee for the given `slot` and `index`.
    /// This is the validator indices for the committee members
    ///
    /// Return `None` if the cache is uninitialized, or the `slot` or `index` is out of range.
    pub fn get_beacon_committee(
        &self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Result<&[usize], Error> {
        ensure!(self.initialized_epoch.is_some(), Error::NotInitialized);
        ensure!(
            self.is_initialized_at(slot.epoch(E::slots_per_epoch())),
            Error::NotInitializedAtEpoch(slot.epoch(E::slots_per_epoch()))
        );
        ensure!(
            index < self.committees_per_slot,
            Error::ShuffleIndexOutOfBounds(index)
        );

        let committee_index = beacon_types::compute_committee_index_in_epoch(
            slot,
            self.slots_per_epoch,
            self.committees_per_slot,
            index,
        );
        self.compute_committee(committee_index)
            .ok_or(Error::UnableToShuffle)
    }

    /// Get all the Beacon committees at a given `slot`.
    ///
    /// Committees are sorted by ascending index order 0..committees_per_slot
    pub fn get_beacon_committees_at_slot(&self, slot: Slot) -> Result<Vec<&[usize]>, Error> {
        ensure!(self.initialized_epoch.is_some(), Error::NotInitialized);

        (0..self.get_committee_count_per_slot())
            .map(|index| self.get_beacon_committee(slot, index))
            .collect()
    }

    /// Returns the number of active validators in the initialized epoch.
    ///
    /// Always returns `usize::default()` for a non-initialized epoch.
    pub fn active_validator_count(&self) -> usize {
        self.shuffling.len()
    }

    /// Returns the total number of committees in the initialized epoch.
    ///
    /// Always returns `usize::default()` for a non-initialized epoch.
    pub fn epoch_committee_count(&self) -> usize {
        beacon_types::epoch_committee_count(self.committees_per_slot, self.slots_per_epoch)
    }

    /// Returns the number of committees per slot for this cache's epoch.
    pub fn get_committee_count_per_slot(&self) -> usize {
        self.committees_per_slot
    }

    /// Returns a slice of `self.shuffling` that represents the `index`'th committee in the epoch.
    fn compute_committee(&self, index: CommitteeIndex) -> Option<&[usize]> {
        self.shuffling.get(self.compute_committee_range(index)?)
    }

    /// Returns a range of `self.shuffling` that represents the `index`'th committee in the epoch.
    ///
    /// To avoid a divide-by-zero, returns `None` if `self.committee_count` is zero.
    ///
    /// Will also return `None` if the index is out of bounds.
    fn compute_committee_range(&self, index: CommitteeIndex) -> Option<Range<usize>> {
        beacon_types::compute_committee_range_in_epoch(
            self.epoch_committee_count(),
            index,
            self.shuffling.len(),
        )
    }

    /// Returns the index of some validator in `self.shuffling`.
    ///
    /// Always returns `None` for a non-initialized epoch.
    pub fn shuffled_position(&self, validator_index: usize) -> Option<usize> {
        self.shuffling_positions
            .get(validator_index)?
            .map(|p| p.get() - 1)
    }
}
