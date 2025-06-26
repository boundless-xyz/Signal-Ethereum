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

pub mod cache_provider;
pub mod file_provider;
pub mod persistant_api_provider;

pub use cache_provider::*;
pub use file_provider::*;
pub use persistant_api_provider::*;

use beacon_types::EthSpec;
use ssz_rs::HashTreeRoot;
use std::sync::Arc;
use tracing::warn;
use z_core::{Checkpoint, Epoch, Root, Slot, mainnet::BeaconState};

pub type StateRef = Arc<BeaconState>;

#[derive(Debug, thiserror::Error)]
pub enum StateProviderError {
    #[error("invalid checkpoint")]
    InvalidCheckpoint,
    #[error("state for slot {0} not found")]
    NotFound(Slot),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

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

        z_core::ensure!(
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
