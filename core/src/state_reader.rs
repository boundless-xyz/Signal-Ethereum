use std::cmp::{max, min};

use alloy_primitives::B256;
use alloy_primitives::aliases::B32;
use sha2::Digest;
use ssz_rs::prelude::*;
use thiserror::Error;

use crate::{Ctx, Epoch, Version};
use crate::{ValidatorIndex, ValidatorInfo};

mod assert_state_reader;
#[cfg(feature = "host")]
mod host_state_reader;
mod ssz_state_reader;
#[cfg(feature = "host")]
mod state_provider;
#[cfg(feature = "host")]
mod tracking_state_reader;

#[cfg(feature = "host")]
pub use self::{host_state_reader::*, tracking_state_reader::*};
pub use assert_state_reader::*;
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

    /// Return the sequence of active validators at `epoch`.
    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error>;

    /// Return the RANDAO mix at `index`
    fn randao_mix(&self, state: Epoch, index: usize) -> Result<Option<B256>, Self::Error>;

    /// Return the RANDAO mix for a recent `mix_epoch`.
    fn get_randao_mix(&self, state: Epoch, mix_epoch: Epoch) -> Result<B256, Self::Error> {
        let idx: usize = (mix_epoch % self.context().epochs_per_historical_vector())
            .try_into()
            .unwrap();

        Ok(self
            .randao_mix(state, idx)?
            .expect("randao_mix should be present"))
    }

    /// Return the seed at the current epoch.
    fn get_seed(&self, state: Epoch, domain_type: B32) -> Result<B256, Self::Error> {
        let ctx = self.context();

        // the seed for epoch is based on the RANDAO from the epoch MIN_SEED_LOOKAHEAD + 1 ago
        let current_epoch = state;
        let mix = self.get_randao_mix(
            state,
            current_epoch
                .checked_add(ctx.epochs_per_historical_vector() - ctx.min_seed_lookahead() - 1)
                .unwrap(),
        )?;

        let mut h = sha2::Sha256::new();
        Digest::update(&mut h, domain_type);
        Digest::update(&mut h, state.to_le_bytes());
        Digest::update(&mut h, mix);

        Ok(<[u8; 32]>::from(h.finalize()).into())
    }

    /// Return the number of committees in each slot for the given `epoch`.
    fn get_committee_count_per_slot(&self, epoch: Epoch) -> Result<u64, Self::Error> {
        Ok(max(
            1u64,
            min(
                self.context().max_committees_per_slot() as u64,
                self.get_active_validator_indices(epoch)?.count() as u64
                    / self.context().slots_per_epoch()
                    / self.context().target_committee_size(),
            ),
        ))
    }

    /// Return the combined effective balance of the active validators.
    fn get_total_active_balance(&self, epoch: Epoch) -> Result<u64, Self::Error> {
        Ok(self
            .active_validators(epoch)?
            .map(|(_, validator)| validator.effective_balance)
            .sum())
    }

    /// Return the sequence of active validator indices at `epoch`.
    fn get_active_validator_indices(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = ValidatorIndex>, Self::Error> {
        Ok(self.active_validators(epoch)?.map(|(index, _)| index))
    }

    fn genesis_validators_root(&self) -> B256;

    // TODO(ec2): This should be handled in such a way that things won't break in the event of hardfork.
    fn fork_version(&self, epoch: Epoch) -> Result<Version, Self::Error>;
}
