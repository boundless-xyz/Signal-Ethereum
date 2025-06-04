use std::{fmt::Display, path::PathBuf};

use tokio::runtime::Handle;
use z_core::{
    mainnet::BeaconState, BoxedStateProvider, Ctx, Epoch, FileProvider, HostContext, StateProvider,
};

use crate::beacon_client::BeaconClient;

#[derive(Clone)]
struct BeaconClientStateProvider {
    client: BeaconClient,
    context: HostContext,
}

impl BeaconClientStateProvider {
    fn new(client: BeaconClient, context: &HostContext) -> Self {
        Self {
            client,
            context: context.clone(),
        }
    }

    fn get_state_at(&self, state_id: impl Display) -> Result<Option<BeaconState>, anyhow::Error> {
        tokio::task::block_in_place(|| {
            Handle::current()
                .block_on(self.client.get_beacon_state(state_id))
                .map_err(|e| anyhow::anyhow!(e))
                .map(Option::Some)
        })
    }
}

impl StateProvider for BeaconClientStateProvider {
    fn get_state(&self, epoch: Epoch) -> Result<Option<BeaconState>, anyhow::Error> {
        let slot = self.context.compute_start_slot_at_epoch(epoch);
        tokio::task::block_in_place(|| {
            Handle::current()
                .block_on(self.client.get_beacon_state(slot))
                .map_err(|e| anyhow::anyhow!(e))
                .map(Option::Some)
        })
    }
}

impl From<BeaconClientStateProvider> for BoxedStateProvider {
    fn from(provider: BeaconClientStateProvider) -> Self {
        Box::new(provider)
    }
}

#[derive(Clone)]
pub(crate) struct FileBackedBeaconClientStateProvider {
    file_provider: FileProvider,
    client_provider: BeaconClientStateProvider,
}

impl FileBackedBeaconClientStateProvider {
    pub(crate) fn new(
        dir: impl Into<PathBuf>,
        client: BeaconClient,
        context: &HostContext,
    ) -> Result<Self, anyhow::Error> {
        let file_provider = FileProvider::new(dir, context)?;
        let client_provider = BeaconClientStateProvider::new(client, context);
        Ok(Self {
            file_provider,
            client_provider,
        })
    }
    /// Fetches and saves the beacon state at a specific `state_id`.
    /// NOTE: This will overwrite the file store's state for this epoch if it exists.
    pub(crate) fn cache_state_at(
        &self,
        state_id: impl Display,
    ) -> Result<Option<BeaconState>, anyhow::Error> {
        let state = self.client_provider.get_state_at(state_id);
        if let Ok(Some(state)) = state {
            self.file_provider.save_state(&state)?;
            Ok(Some(state))
        } else {
            state
        }
    }
}

impl StateProvider for FileBackedBeaconClientStateProvider {
    fn get_state(&self, epoch: Epoch) -> Result<Option<BeaconState>, anyhow::Error> {
        // First try to get the state from the file provider
        if let Ok(Some(state)) = self.file_provider.get_state(epoch) {
            return Ok(Some(state));
        }
        // If not found, fall back to the beacon client provider
        let state = self.client_provider.get_state(epoch);

        if let Ok(Some(state)) = state {
            // Save the state to the file provider for future use
            self.file_provider.save_state(&state)?;
            Ok(Some(state))
        } else {
            state
        }
    }
}

impl From<FileBackedBeaconClientStateProvider> for BoxedStateProvider {
    fn from(provider: FileBackedBeaconClientStateProvider) -> Self {
        Box::new(provider)
    }
}
