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

use crate::conversions::TryAsBeaconType;
use crate::{CacheStateProvider, FileProvider, StateProvider, StateProviderError, StateRef};
use alloy_primitives::B256;
use beacon_types::{ChainSpec, EthSpec, Fork};
use elsa::FrozenMap;
use ethereum_consensus::phase0::Validator;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use safe_arith::ArithError;
use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, trace};
use z_core::{Epoch, RandaoMixIndex, Root, Slot, StateReader, ValidatorIndex, ValidatorInfo};

#[derive(Error, Debug)]
pub enum HostReaderError {
    #[error("Io: {0}")]
    Io(#[from] std::io::Error),
    #[error("SszDeserialize: {0}")]
    SszDeserialize(#[from] ssz_rs::DeserializeError),
    #[error("SszMerklize: {0}")]
    SszMerkleization(#[from] ssz_rs::MerkleizationError),
    #[error("State missing")]
    StateMissing,
    #[error("Not in cache")]
    NotInCache,
    #[error(transparent)]
    StateProviderError(#[from] StateProviderError),
    #[error("Arithmetic error: {0:?}")]
    ArithError(ArithError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<ArithError> for HostReaderError {
    fn from(e: ArithError) -> Self {
        HostReaderError::ArithError(e)
    }
}

pub struct HostStateReader<P> {
    spec: ChainSpec,
    provider: P,
    validator_cache: FrozenMap<Epoch, Vec<(ValidatorIndex, ValidatorInfo)>>,
}

impl<P: StateProvider> HostStateReader<P> {
    #[must_use]
    pub fn new(spec: ChainSpec, provider: P) -> Self {
        Self {
            spec,
            provider,
            validator_cache: Default::default(),
        }
    }

    #[inline]
    pub fn provider(&self) -> &P {
        &self.provider
    }

    fn state(&self, epoch: Epoch) -> Result<StateRef, StateProviderError> {
        self.provider.state_at_epoch(epoch)
    }
}

impl<E: EthSpec> HostStateReader<CacheStateProvider<FileProvider<E>>> {
    pub fn new_with_dir(spec: ChainSpec, dir: impl Into<PathBuf>) -> Result<Self, HostReaderError> {
        let provider = CacheStateProvider::new(FileProvider::new(dir)?);
        Ok(Self::new(spec, provider))
    }
}

impl<P: StateProvider> StateProvider for HostStateReader<P> {
    type Spec = P::Spec;

    fn state_at_slot(&self, slot: Slot) -> Result<StateRef, StateProviderError> {
        self.provider.state_at_slot(slot)
    }
}

impl<P: StateProvider> StateReader for HostStateReader<P> {
    type Error = HostReaderError;
    type Spec = P::Spec;

    fn chain_spec(&self) -> &ChainSpec {
        &self.spec
    }

    fn genesis_validators_root(&self) -> Result<Root, HostReaderError> {
        Ok(self.provider.genesis_validators_root()?)
    }

    fn fork(&self, epoch: Epoch) -> Result<Fork, HostReaderError> {
        let state = self.provider.state_at_epoch(epoch)?;
        Ok(Fork {
            previous_version: state.fork().previous_version,
            current_version: state.fork().current_version,
            epoch: state.fork().epoch.into(),
        })
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        trace!("HostStateReader::active_validators({epoch})");

        let iter = match self.validator_cache.get(&epoch) {
            Some(validators) => validators.iter(),
            None => {
                let beacon_state = self.state(epoch)?;

                debug!("Caching validators for epoch {epoch}");
                let validators: Vec<(ValidatorIndex, ValidatorInfo)> = beacon_state
                    .validators()
                    .par_iter()
                    .enumerate()
                    .filter(|(_, validator)| is_active_validator(validator, epoch.as_u64()))
                    .map(|(idx, validator)| validator.try_as_beacon_type().map(|info| (idx, info)))
                    .collect::<Result<_, _>>()?;
                debug!("Active validators: {}", validators.len());

                self.validator_cache.insert(epoch, validators).iter()
            }
        };

        Ok(iter.map(|(idx, validator)| (*idx, validator)))
    }

    fn randao_mix(&self, epoch: Epoch, idx: RandaoMixIndex) -> Result<Option<B256>, Self::Error> {
        trace!("HostStateReader::randao_mix({epoch},{idx})");
        let beacon_state = self.state(epoch)?;

        Ok(beacon_state
            .randao_mixes()
            .get(idx as usize)
            .map(|randao| B256::from_slice(randao.as_slice())))
    }
}

/// Check if `validator` is active.
fn is_active_validator(validator: &Validator, epoch: u64) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch
}
