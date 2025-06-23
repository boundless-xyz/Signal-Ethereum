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

use crate::{Epoch, RandaoMixIndex, Root, ValidatorIndex, ValidatorInfo};
use alloy_primitives::B256;
use alloy_primitives::aliases::B32;
use beacon_types::EthSpec;
use sha2::Digest;
use std::cmp::max;
use thiserror::Error;

#[cfg(feature = "host")]
mod host_state_reader;
#[cfg(feature = "host")]
mod preflight_state_reader;
mod ssz_state_reader;
#[cfg(feature = "host")]
mod state_provider;

#[cfg(feature = "host")]
pub use self::{host_state_reader::*, preflight_state_reader::*, state_provider::*};
pub use ssz_state_reader::*;

#[derive(Error, Debug)]
pub enum StateReaderError {
    #[error("any")]
    Any,
}

pub trait StateReader {
    type Error: std::error::Error;
    type Spec: EthSpec;

    /// Return `state.genesis_validators_root`.
    fn genesis_validators_root(&self) -> Result<Root, Self::Error>;

    /// Return `state.fork`.
    fn fork(&self, epoch: Epoch) -> Result<beacon_types::Fork, Self::Error>;

    /// Return the sequence of active validators at `epoch`.
    ///
    /// Returns the subset of all validators that are active in the given epoch. The returned validators are ordered by their index.
    /// This is equivalent to `state.validators.enumerate().filter(|(i,v)| is_active_validator(v, epoch))`.
    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error>;

    /// Return `state.randao_mixes[idx]`.
    fn randao_mix(&self, epoch: Epoch, idx: RandaoMixIndex) -> Result<Option<B256>, Self::Error>;

    /// Return the RANDAO mix at a recent `epoch`.
    fn get_randao_mix(&self, state_epoch: Epoch, epoch: Epoch) -> Result<B256, Self::Error> {
        let idx: RandaoMixIndex = (epoch % Self::Spec::epochs_per_historical_vector() as u64)
            .try_into()
            .unwrap();

        Ok(self
            .randao_mix(state_epoch, idx)?
            .expect("randao_mix should be present"))
    }

    /// Return the sequence of active validator indices at `epoch`.
    fn get_active_validator_indices(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = ValidatorIndex>, Self::Error> {
        Ok(self.active_validators(epoch)?.map(|(index, _)| index))
    }

    /// Return the seed at `epoch`.
    fn get_seed(&self, epoch: Epoch, domain_type: B32) -> Result<B256, Self::Error> {
        // the seed for epoch is based on the RANDAO from the epoch MIN_SEED_LOOKAHEAD + 1 ago
        let mix = self.get_randao_mix(
            epoch,
            // TODO (ec2): I think we can do normal arithmetic here instead of `checked_add` since it will saturate.
            epoch
                .as_u64()
                .checked_add(
                    Self::Spec::epochs_per_historical_vector() as u64
                        - Self::Spec::default_spec().min_seed_lookahead.as_u64()
                        - 1,
                )
                .unwrap()
                .into(),
        )?;

        let mut h = sha2::Sha256::new();
        Digest::update(&mut h, domain_type);
        Digest::update(&mut h, uint64_to_bytes(epoch.into()));
        Digest::update(&mut h, mix);

        Ok(<[u8; 32]>::from(h.finalize()).into())
    }

    /// Return the combined effective balance of the active validators.
    fn get_total_active_balance(&self, epoch: Epoch) -> Result<u64, Self::Error> {
        Ok(max(
            Self::Spec::default_spec().effective_balance_increment,
            self.active_validators(epoch)?
                .map(|(_, validator)| validator.effective_balance)
                .sum(),
        ))
    }
}

#[inline]
pub fn uint64_to_bytes(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}
