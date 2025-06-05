use std::{fmt::Display, path::PathBuf};

use tokio::runtime::Handle;
use z_core::{
    mainnet::BeaconState, BoxedStateProvider, Ctx, Epoch, FileProvider, HostContext, StateProvider,
};

use crate::beacon_client::BeaconClient;

#[derive(Clone)]
pub(crate) struct PersistentApiStateProvider {
    file_provider: FileProvider,
    client: BeaconClient,
    context: HostContext,
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
            context: context.clone(),
        })
    }
    /// Fetches and saves the beacon state at a specific `state_id`.
    /// NOTE: This will overwrite the file store's state for this epoch if it exists.
    pub(crate) fn cache_state_at(
        &self,
        state_id: impl Display,
    ) -> Result<Option<BeaconState>, anyhow::Error> {
        let state = tokio::task::block_in_place(|| {
            Handle::current()
                .block_on(self.client.get_beacon_state(state_id))
                .map_err(|e| anyhow::anyhow!(e))
                .map(Option::Some)
        });
        if let Ok(Some(state)) = state {
            self.file_provider.save_state(&state)?;
            Ok(Some(state))
        } else {
            state
        }
    }
}

impl StateProvider for PersistentApiStateProvider {
    fn get_state(&self, epoch: Epoch) -> Result<Option<BeaconState>, anyhow::Error> {
        // First try to get the state from the file provider
        if let Ok(Some(state)) = self.file_provider.get_state(epoch) {
            return Ok(Some(state));
        }
        // If not found, fall back to the beacon client provider
        let slot = self.context.compute_start_slot_at_epoch(epoch);
        let state = tokio::task::block_in_place(|| {
            Handle::current()
                .block_on(self.client.get_beacon_state(slot))
                .map_err(|e| anyhow::anyhow!(e))
                .map(Option::Some)
        });

        if let Ok(Some(state)) = state {
            // Save the state to the file provider for future use
            self.file_provider.save_state(&state)?;
            Ok(Some(state))
        } else {
            state
        }
    }
}

impl From<PersistentApiStateProvider> for BoxedStateProvider {
    fn from(provider: PersistentApiStateProvider) -> Self {
        Box::new(provider)
    }
}
