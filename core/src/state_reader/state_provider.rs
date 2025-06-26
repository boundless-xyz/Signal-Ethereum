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

use crate::{Checkpoint, Epoch, Root, Slot, beacon_state::mainnet::BeaconState};
use anyhow::{Context, ensure};
use beacon_types::EthSpec;
use elsa::FrozenMap;
use ssz_rs::HashTreeRoot;
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs, marker::PhantomData};
use tracing::{debug, warn};

#[derive(Debug, thiserror::Error)]
pub enum StateProviderError {
    #[error("invalid checkpoint")]
    InvalidCheckpoint,
    #[error("state for slot {0} not found")]
    NotFound(Slot),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type StateRef = Arc<BeaconState>;

pub trait StateProvider {
    type Spec: EthSpec;
    fn genesis_validators_root(&self) -> Result<Root, StateProviderError> {
        Ok(self.state_at_slot(0u64.into())?.genesis_validators_root())
    }

    fn state_at_checkpoint(&self, checkpoint: Checkpoint) -> Result<StateRef, StateProviderError> {
        let state = self.state_at_epoch(checkpoint.epoch())?;

        // check that the start_slot is indeed the epoch boundary
        let epoch_boundary_slot = state.latest_block_header().slot;
        if epoch_boundary_slot == state.slot() {
            return Ok(state);
        }

        warn!(
            "Epoch {} does not contain the epoch boundary block, etching slot {}",
            checkpoint.epoch(),
            epoch_boundary_slot
        );

        let state = self.state_at_slot(epoch_boundary_slot.into())?;

        // check that the state matches the epoch boundary block
        let mut epoch_boundary_block = state.latest_block_header().clone();
        epoch_boundary_block.state_root = state.hash_tree_root().unwrap();
        crate::ensure!(
            checkpoint.root() == epoch_boundary_block.hash_tree_root().unwrap(),
            StateProviderError::InvalidCheckpoint
        );

        Ok(state)
    }

    fn state_at_epoch(&self, epoch: Epoch) -> Result<StateRef, StateProviderError> {
        let start_slot = epoch.start_slot(Self::Spec::slots_per_epoch());
        self.state_at_slot(start_slot)
    }

    fn state_at_slot(&self, slot: Slot) -> Result<StateRef, StateProviderError>;
}

#[derive(Clone)]
pub struct CacheStateProvider<P> {
    inner: P,
    cache: FrozenMap<Slot, Arc<BeaconState>>,
}

impl<P> CacheStateProvider<P> {
    pub fn new(provider: P) -> Self {
        Self {
            inner: provider,
            cache: FrozenMap::new(),
        }
    }

    #[inline]
    pub fn inner(&self) -> &P {
        &self.inner
    }
}

impl<P: StateProvider> StateProvider for CacheStateProvider<P> {
    type Spec = P::Spec;
    fn genesis_validators_root(&self) -> Result<Root, StateProviderError> {
        let cache = self.cache.clone().into_map();
        match cache.values().next() {
            Some(state) => Ok(state.genesis_validators_root()),
            None => Ok(self.state_at_slot(0u64.into())?.genesis_validators_root()),
        }
    }

    fn state_at_slot(&self, slot: Slot) -> Result<StateRef, StateProviderError> {
        match self.cache.map_get(&slot, Clone::clone) {
            None => {
                let state = self.inner.state_at_slot(slot)?;
                self.cache.insert(slot, state.clone());
                Ok(state)
            }
            Some(beacon_state) => Ok(beacon_state),
        }
    }
}
