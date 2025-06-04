use tokio::runtime::Handle;
use z_core::{
    mainnet::BeaconState, BoxedStateProvider, Ctx, Epoch, FileProvider, HostContext, StateProvider,
};

use crate::beacon_client::BeaconClient;

pub(crate) struct BeaconClientStateProvider {
    client: BeaconClient,
    context: HostContext,
    rt: tokio::runtime::Runtime,
}

impl BeaconClientStateProvider {
    pub fn new(client: BeaconClient, context: &HostContext) -> Self {
        Self {
            client,
            context: context.clone(),
            rt: tokio::runtime::Runtime::new().expect("Failed to create runtime"),
        }
    }
}

impl StateProvider for BeaconClientStateProvider {
    fn get_state(&self, epoch: Epoch) -> Result<Option<BeaconState>, anyhow::Error> {
        // TODO(ec2): What do if skip slot?
        let slot = self.context.compute_start_slot_at_epoch(epoch);
        Handle::current()
            .block_on(self.client.get_beacon_state_ssz(slot))
            .map_err(|e| anyhow::anyhow!(e))
            .map(Option::Some)
    }
}

impl From<BeaconClientStateProvider> for BoxedStateProvider {
    fn from(provider: BeaconClientStateProvider) -> Self {
        Box::new(provider)
    }
}

pub(crate) struct FileBackedBeaconClientStateProvider {
    file_provider: FileProvider,
    client_provider: BeaconClientStateProvider,
}

impl FileBackedBeaconClientStateProvider {
    pub fn new(file_provider: FileProvider, client_provider: BeaconClientStateProvider) -> Self {
        Self {
            file_provider,
            client_provider,
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
