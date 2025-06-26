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

use crate::beacon_state::mainnet::BeaconState;
use crate::state_provider::{StateProvider, StateProviderError, StateRef};
use anyhow::{Context, ensure};
use beacon_types::EthSpec;
use std::path::PathBuf;
use std::{fs, marker::PhantomData};
use tracing::debug;
use z_core::{Epoch, Slot};

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
