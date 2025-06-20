use anyhow::Context;
use beacon_types::EthSpec;
use std::path::PathBuf;
use tokio::runtime::Handle;
use z_core::{FileProvider, Slot, StateProvider, StateProviderError, StateRef};

use crate::beacon_client::BeaconClient;

#[derive(Clone)]
pub(crate) struct PersistentApiStateProvider<E: EthSpec> {
    file_provider: FileProvider<E>,
    client: BeaconClient,
}

impl<E: EthSpec> PersistentApiStateProvider<E> {
    pub(crate) fn new(
        dir: impl Into<PathBuf>,
        client: BeaconClient,
    ) -> Result<Self, anyhow::Error> {
        let file_provider = FileProvider::new(dir)?;
        Ok(Self {
            file_provider,
            client,
        })
    }
}

impl<E: EthSpec> StateProvider for PersistentApiStateProvider<E> {
    type Spec = E;

    fn state_at_slot(&self, slot: Slot) -> Result<StateRef, StateProviderError> {
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
