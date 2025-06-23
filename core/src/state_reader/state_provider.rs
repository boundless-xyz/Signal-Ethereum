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

use crate::{Checkpoint, Ctx, Epoch, HostContext, Root, Slot, beacon_state::mainnet::BeaconState};
use anyhow::{Context, ensure};
use elsa::FrozenMap;
use ssz_rs::HashTreeRoot;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
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
    fn context(&self) -> &HostContext;

    fn genesis_validators_root(&self) -> Result<Root, StateProviderError> {
        Ok(self.state_at_slot(0)?.genesis_validators_root())
    }

    fn state_at_checkpoint(&self, checkpoint: Checkpoint) -> Result<StateRef, StateProviderError> {
        let state = self.state_at_epoch(checkpoint.epoch)?;

        // check that the start_slot is indeed the epoch boundary
        let epoch_boundary_slot = state.latest_block_header().slot;
        if epoch_boundary_slot == state.slot() {
            return Ok(state);
        }

        warn!(
            "Epoch {} does not contain the epoch boundary block, etching slot {}",
            checkpoint.epoch, epoch_boundary_slot
        );

        let state = self.state_at_slot(epoch_boundary_slot)?;

        // check that the state matches the epoch boundary block
        let mut epoch_boundary_block = state.latest_block_header().clone();
        epoch_boundary_block.state_root = state.hash_tree_root().unwrap();
        crate::ensure!(
            checkpoint.root == epoch_boundary_block.hash_tree_root().unwrap(),
            StateProviderError::InvalidCheckpoint
        );

        Ok(state)
    }

    fn state_at_epoch(&self, epoch: Epoch) -> Result<StateRef, StateProviderError> {
        let start_slot = self.context().compute_start_slot_at_epoch(epoch);
        self.state_at_slot(start_slot)
    }

    fn state_at_slot(&self, slot: Slot) -> Result<StateRef, StateProviderError>;
}

#[derive(Clone)]
pub struct CacheStateProvider<P> {
    inner: P,
    cache: FrozenMap<Slot, Box<Arc<BeaconState>>>,
}

impl<P: StateProvider> CacheStateProvider<P> {
    pub fn new(provider: P) -> Self {
        Self {
            inner: provider,
            cache: FrozenMap::new(),
        }
    }
}

impl<P: StateProvider> StateProvider for CacheStateProvider<P> {
    fn context(&self) -> &HostContext {
        self.inner.context()
    }

    fn genesis_validators_root(&self) -> Result<Root, StateProviderError> {
        let cache = self.cache.clone().into_map();
        match cache.values().next() {
            Some(state) => Ok(state.genesis_validators_root()),
            None => Ok(self.state_at_slot(0)?.genesis_validators_root()),
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
pub struct FileProvider {
    directory: PathBuf,
    context: HostContext,
}

impl FileProvider {
    pub fn new(
        directory: impl Into<PathBuf>,
        context: &HostContext,
    ) -> Result<Self, anyhow::Error> {
        let provider = Self {
            directory: directory.into(),
            context: context.clone(),
        };
        ensure!(provider.directory.is_dir(), "not a directory");

        Ok(provider)
    }

    pub fn save_state(&self, state: &BeaconState) -> Result<(), anyhow::Error> {
        let slot = state.slot();
        let epoch = self.context.compute_epoch_at_slot(slot);
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
        let slot = epoch * self.context.slots_per_epoch();
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
                    .and_then(|s| s.parse::<Epoch>().ok())
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

impl StateProvider for FileProvider {
    fn context(&self) -> &HostContext {
        &self.context
    }

    fn state_at_slot(&self, slot: u64) -> Result<StateRef, StateProviderError> {
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
