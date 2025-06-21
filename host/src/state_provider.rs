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

use anyhow::Context;
use std::path::PathBuf;
use tokio::runtime::Handle;
use z_core::{FileProvider, HostContext, StateProvider, StateProviderError, StateRef};

use crate::beacon_client::BeaconClient;

#[derive(Clone)]
pub(crate) struct PersistentApiStateProvider {
    file_provider: FileProvider,
    client: BeaconClient,
}

impl PersistentApiStateProvider {
    pub(crate) fn new(
        dir: impl Into<PathBuf>,
        client: BeaconClient,
        context: &HostContext,
    ) -> Result<Self, anyhow::Error> {
        let file_provider = FileProvider::new(dir, context)?;
        Ok(Self {
            file_provider,
            client,
        })
    }
}

impl StateProvider for PersistentApiStateProvider {
    fn context(&self) -> &HostContext {
        &self.file_provider.context()
    }
    fn state_at_slot(&self, slot: u64) -> Result<StateRef, StateProviderError> {
        // First try to get the state from the file provider
        match self.file_provider.state_at_slot(slot) {
            Err(StateProviderError::NotFound(_)) => {}
            state => return state,
        }

        let state = tokio::task::block_in_place(|| {
            Handle::current().block_on(self.client.get_beacon_state(slot))
        })
        .context("failed to get state from API")?;

        // Save the state to the file provider for future use
        self.file_provider.save_state(&state)?;

        Ok(state.into())
    }
}
