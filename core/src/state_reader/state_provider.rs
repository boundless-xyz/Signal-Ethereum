use crate::{Epoch, beacon_state::mainnet::BeaconState};
use anyhow::ensure;
use ethereum_consensus::{electra::compute_epoch_at_slot, state_transition::Context};
use std::fs;
use std::path::PathBuf;
use tracing::debug;

pub trait StateProvider {
    /// Returns the beacon state at `epoch`.
    fn get_state(&self, epoch: Epoch) -> Result<Option<BeaconState>, anyhow::Error>;
}

pub type BoxedStateProvider = Box<dyn StateProvider>;

pub struct FileProvider {
    directory: PathBuf,
    context: Context,
}

impl FileProvider {
    pub(crate) fn new(
        directory: impl Into<PathBuf>,
        context: &Context,
    ) -> Result<Self, anyhow::Error> {
        let provider = Self {
            directory: directory.into(),
            context: context.clone(),
        };
        ensure!(provider.directory.is_dir(), "not a directory");

        Ok(provider)
    }
}

impl StateProvider for FileProvider {
    fn get_state(&self, epoch: Epoch) -> Result<Option<BeaconState>, anyhow::Error> {
        let file = self.directory.join(format!("{}_beacon_state.ssz", epoch));
        if !file.exists() {
            return Ok(None);
        }

        debug!("Loading beacon state for epoch: {}", epoch);
        let bytes = fs::read(&file)?;
        let state: BeaconState = ssz_rs::deserialize(&bytes)?;
        let state_epoch = compute_epoch_at_slot(state.slot(), &self.context);
        ensure!(epoch == state_epoch, "Invalid epoch");

        Ok(Some(state))
    }
}

impl From<FileProvider> for BoxedStateProvider {
    fn from(provider: FileProvider) -> Self {
        Box::new(provider)
    }
}
