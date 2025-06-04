use crate::{Ctx, Epoch, HostContext, beacon_state::mainnet::BeaconState};
use anyhow::ensure;
use std::fs;
use std::path::PathBuf;
use tracing::debug;

pub trait StateProvider {
    /// Returns the beacon state at `epoch`.
    fn get_state(&self, epoch: Epoch) -> Result<Option<BeaconState>, anyhow::Error>;
}

pub type BoxedStateProvider = Box<dyn StateProvider>;

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
        let epoch = self.context.compute_epoch_at_slot(state.slot());
        let file = self.directory.join(format!("{}_beacon_state.ssz", epoch));
        debug!("Saving beacon state for epoch: {}", epoch);
        fs::write(&file, ssz_rs::serialize(state)?)?;
        Ok(())
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
        let state_epoch = self.context.compute_epoch_at_slot(state.slot());
        ensure!(epoch == state_epoch, "Invalid epoch");

        Ok(Some(state))
    }
}

impl From<FileProvider> for BoxedStateProvider {
    fn from(provider: FileProvider) -> Self {
        Box::new(provider)
    }
}
