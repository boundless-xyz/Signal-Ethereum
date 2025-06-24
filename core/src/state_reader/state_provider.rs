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
    cache: FrozenMap<Slot, Box<Arc<BeaconState>>>,
}

impl<P> CacheStateProvider<P> {
    pub fn new(provider: P) -> Self {
        Self {
            inner: provider,
            cache: FrozenMap::new(),
        }
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
        match self.cache.get(&slot) {
            None => {
                let state = self.inner.state_at_slot(slot)?;
                self.cache.insert(slot, state.clone().into());
                Ok(state)
            }
            Some(beacon_state) => Ok(beacon_state.clone()),
        }
    }
}

#[derive(Clone)]
pub struct FileProvider<E: EthSpec> {
    directory: PathBuf,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> FileProvider<E> {
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self, anyhow::Error> {
        let provider = Self {
            directory: directory.into(),
            _phantom: PhantomData,
        };
        ensure!(provider.directory.is_dir(), "not a directory");

        Ok(provider)
    }

    pub fn save_state(&self, state: &BeaconState) -> Result<(), anyhow::Error> {
        let slot = Slot::from(state.slot());
        let epoch = slot.epoch(E::slots_per_epoch());
        let file = self.directory.join(format!("{}_beacon_state.ssz", slot));
        ensure!(
            !file.exists(),
            "State file already exists: {}",
            file.display()
        );
        debug!("Saving beacon state at slot {slot} in epoch: {epoch}");
        fs::write(&file, ssz_rs::serialize(state)?)?;
        Ok(())
    }

    pub fn clear_states_before(&self, epoch: Epoch) -> Result<(), anyhow::Error> {
        let slot = epoch.start_slot(E::slots_per_epoch());
        tracing::info!(
            "Clearing all beacon states before epoch: {} (slot: {})",
            epoch,
            slot
        );
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            if let Some(file_slot) = entry.file_name().to_str() {
                if let Some(file_slot) = file_slot
                    .split('_')
                    .next()
                    .and_then(|s| s.parse::<Slot>().ok())
                {
                    if file_slot < slot {
                        fs::remove_file(entry.path())?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl<E: EthSpec> StateProvider for FileProvider<E> {
    type Spec = E;
    fn state_at_slot(&self, slot: Slot) -> Result<StateRef, StateProviderError> {
        let file = self.directory.join(format!("{}_beacon_state.ssz", slot));
        if !file.exists() {
            return Err(StateProviderError::NotFound(slot));
        }

        let bytes = fs::read(&file)
            .with_context(|| format!("failed to read beacon state file {}", file.display()))?;
        let state: BeaconState =
            ssz_rs::deserialize(&bytes).context("failed to deserialize beacon state")?;

        Ok(state.into())
    }
}
