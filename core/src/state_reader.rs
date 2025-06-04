use std::cmp::{max, min};

use alloy_primitives::B256;
use alloy_primitives::aliases::B32;
use sha2::Digest;
use thiserror::Error;

use crate::{Ctx, Epoch, Version};
use crate::{ValidatorIndex, ValidatorInfo};

#[cfg(feature = "host")]
mod host_state_reader;
mod ssz_state_reader;
#[cfg(feature = "host")]
mod state_provider;
#[cfg(feature = "host")]
mod tracking_state_reader;

#[cfg(feature = "host")]
pub use self::{host_state_reader::*, state_provider::*, tracking_state_reader::*};
pub use ssz_state_reader::*;

#[derive(Error, Debug)]
pub enum StateReaderError {
    #[error("any")]
    Any,
}

pub trait StateReader {
    type Error: alloc::fmt::Debug;
    type Context: Ctx;

    fn context(&self) -> &Self::Context;

    /// Return `state.genesis_validators_root`.
    fn genesis_validators_root(&self) -> B256;

    /// Return `state.fork.current_version`.
    // TODO(ec2): This should be handled in such a way that things won't break in the event of hardfork.
    fn fork_current_version(&self, state: Epoch) -> Result<Version, Self::Error>;

    /// Return the sequence of active validators at `epoch`.
    ///
    /// Returns the subset of all validators that are active in the given epoch. The returned validators are ordered by their index.
    /// This is equivalent to `state.validators.enumerate().filter(|(i,v)| is_active_validator(v, epoch))`.
    fn active_validators(
        &self,
        state: Epoch,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error>;

    /// Return `state.randao_mixes[idx]`.
    fn randao_mix(&self, state: Epoch, idx: usize) -> Result<Option<B256>, Self::Error>;

    /// Return the RANDAO mix at a recent `epoch`.
    fn get_randao_mix(&self, state: Epoch, epoch: Epoch) -> Result<B256, Self::Error> {
        let idx: usize = (epoch % self.context().epochs_per_historical_vector())
            .try_into()
            .unwrap();

        Ok(self
            .randao_mix(state, idx)?
            .expect("randao_mix should be present"))
    }

    /// Return the sequence of active validator indices at `epoch`.
    fn get_active_validator_indices(
        &self,
        state: Epoch,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = ValidatorIndex>, Self::Error> {
        Ok(self
            .active_validators(state, epoch)?
            .map(|(index, _)| index))
    }

    /// Return the seed at `epoch`.
    fn get_seed(&self, state: Epoch, epoch: Epoch, domain_type: B32) -> Result<B256, Self::Error> {
        let ctx = self.context();

        // the seed for epoch is based on the RANDAO from the epoch MIN_SEED_LOOKAHEAD + 1 ago
        let mix = self.get_randao_mix(
            state,
            epoch
                .checked_add(ctx.epochs_per_historical_vector() - ctx.min_seed_lookahead() - 1)
                .unwrap(),
        )?;

        let mut h = sha2::Sha256::new();
        Digest::update(&mut h, domain_type);
        Digest::update(&mut h, uint64_to_bytes(state));
        Digest::update(&mut h, mix);

        Ok(<[u8; 32]>::from(h.finalize()).into())
    }

    /// Return the number of committees in each slot for the given `epoch`.
    fn get_committee_count_per_slot(&self, state: Epoch, epoch: Epoch) -> Result<u64, Self::Error> {
        Ok(max(
            1u64,
            min(
                self.context().max_committees_per_slot() as u64,
                self.get_active_validator_indices(state, epoch)?.count() as u64
                    / self.context().slots_per_epoch()
                    / self.context().target_committee_size(),
            ),
        ))
    }

    /// Return the combined effective balance of the active validators.
    /// Note: ``get_total_balance`` returns ``EFFECTIVE_BALANCE_INCREMENT`` Gwei minimum to avoid divisions by zero.
    fn get_total_active_balance(&self, state: Epoch) -> Result<u64, Self::Error> {
        Ok(max(
            self.context().effective_balance_increment(),
            self.active_validators(state, state)?
                .map(|(_, validator)| validator.effective_balance)
                .sum(),
        ))
    }
}

#[inline]
pub fn uint64_to_bytes(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}
