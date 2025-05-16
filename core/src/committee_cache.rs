use crate::shuffle_list::shuffle_list;
use crate::{CommitteeIndex, Ctx, Epoch, Slot, ValidatorIndex};
use alloc::{vec, vec::Vec};
use alloy_primitives::B256;
use core::num::NonZeroUsize;
use core::ops::Range;
use std::usize;
use tracing::debug;

/// Computes and stores the shuffling for an epoch. Provides various getters to allow callers to
/// read the committees for the given epoch.
#[derive(Debug, Default)]
pub struct CommitteeCache {
    initialized_epoch: Option<Epoch>,
    shuffling: Vec<usize>,
    shuffling_positions: Vec<Option<NonZeroUsize>>,
    committees_per_slot: usize,
    slots_per_epoch: usize,
}

#[derive(Debug)]
pub enum Error {
    NotInitialized,
    NotInitializedAtEpoch(Epoch),
    ZeroSlotsPerEpoch,
    InsufficientValidators,
    UnableToShuffle,
    TooManyValidators,
    ShuffleIndexOutOfBounds(usize),
}

// Everything needed to compute the shuffle
pub struct ShuffleData {
    pub(crate) seed: B256,
    pub(crate) indices: Vec<ValidatorIndex>,
    pub(crate) committees_per_slot: u64,
}

impl CommitteeCache {
    /// Return a new, fully initialized cache.
    pub fn initialized<C: Ctx>(
        ShuffleData {
            seed,
            indices: active_validator_indices,
            committees_per_slot,
        }: ShuffleData,
        epoch: Epoch,
        context: &C,
    ) -> Result<CommitteeCache, Error> {
        // May cause divide-by-zero errors.
        if context.slots_per_epoch() == 0 {
            return Err(Error::ZeroSlotsPerEpoch);
        }

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
            context.shuffle_round_count() as u8,
            &seed[..],
            false,
        )
        .ok_or(Error::UnableToShuffle)?;

        // The use of `NonZeroUsize` reduces the maximum number of possible validators by one.
        if max_validator_index == usize::MAX {
            return Err(Error::TooManyValidators);
        }

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
            slots_per_epoch: context.slots_per_epoch().try_into().unwrap(),
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
    pub fn get_beacon_committee<C: Ctx>(
        &self,
        slot: Slot,
        index: CommitteeIndex,
        context: &C,
    ) -> Result<&[usize], Error> {
        if self.initialized_epoch.is_none() {
            return Err(Error::NotInitialized);
        }
        if !self.is_initialized_at(context.compute_epoch_at_slot(slot)) {
            return Err(Error::NotInitializedAtEpoch(
                context.compute_epoch_at_slot(slot),
            ));
        }
        if index >= self.committees_per_slot {
            return Err(Error::ShuffleIndexOutOfBounds(index));
        }

        let committee_index = compute_committee_index_in_epoch(
            slot,
            self.slots_per_epoch.try_into().unwrap(),
            self.committees_per_slot.try_into().unwrap(),
            index,
        );
        self.compute_committee(committee_index)
            .ok_or(Error::UnableToShuffle)
    }

    /// Get all the Beacon committees at a given `slot`.
    ///
    /// Committees are sorted by ascending index order 0..committees_per_slot
    pub fn get_beacon_committees_at_slot<C: Ctx>(
        &self,
        slot: Slot,
        context: &C,
    ) -> Result<Vec<&[usize]>, Error> {
        if self.initialized_epoch.is_none() {
            return Err(Error::NotInitialized);
        }

        (0..self.committees_per_slot())
            .map(|index| self.get_beacon_committee(slot, index, context))
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
        epoch_committee_count(self.committees_per_slot, self.slots_per_epoch)
    }

    /// Returns the number of committees per slot for this cache's epoch.
    pub fn committees_per_slot(&self) -> usize {
        self.committees_per_slot.try_into().unwrap()
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
        compute_committee_range_in_epoch(self.epoch_committee_count(), index, self.shuffling.len())
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

/// Computes the position of the given `committee_index` with respect to all committees in the
/// epoch.
///
/// The return result may be used to provide input to the `compute_committee_range_in_epoch`
/// function.
pub fn compute_committee_index_in_epoch(
    slot: Slot,
    slots_per_epoch: usize,
    committees_per_slot: usize,
    committee_index: CommitteeIndex,
) -> CommitteeIndex {
    (slot % slots_per_epoch as u64) as CommitteeIndex * committees_per_slot
        + committee_index as CommitteeIndex
}

/// Computes the range for slicing the shuffled indices to determine the members of a committee.
///
/// The `index_in_epoch` parameter can be computed computed using
/// `compute_committee_index_in_epoch`.
pub fn compute_committee_range_in_epoch(
    epoch_committee_count: usize,
    index_in_epoch: usize,
    shuffling_len: usize,
) -> Option<Range<usize>> {
    if epoch_committee_count == 0 || index_in_epoch >= epoch_committee_count {
        return None;
    }

    let start = (shuffling_len * index_in_epoch) / epoch_committee_count;
    let end = (shuffling_len * (index_in_epoch + 1)) / epoch_committee_count;

    Some(start..end)
}

/// Returns the total number of committees in an epoch.
pub fn epoch_committee_count(committees_per_slot: usize, slots_per_epoch: usize) -> usize {
    committees_per_slot * slots_per_epoch
}
