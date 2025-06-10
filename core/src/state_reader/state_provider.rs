use crate::{Ctx, Epoch, HostContext, beacon_state::mainnet::BeaconState};
use anyhow::ensure;
use std::fs;
use std::path::PathBuf;
use tracing::debug;

pub trait StateProvider {
    /// Returns the beacon state at `epoch`.
    fn get_state_at_epoch_boundary(
        &self,
        epoch: Epoch,
    ) -> Result<Option<BeaconState>, anyhow::Error>;
    fn get_state_at_slot(&self, slot: u64) -> Result<Option<BeaconState>, anyhow::Error>;
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
}

impl StateProvider for FileProvider {
    fn get_state_at_epoch_boundary(
        &self,
        epoch: Epoch,
    ) -> Result<Option<BeaconState>, anyhow::Error> {
        let slot = self.context.compute_start_slot_at_epoch(epoch);
        let state = self.get_state_at_slot(slot);

        if let Ok(Some(state)) = state {
            let latest_block_header = state.latest_block_header();
            if latest_block_header.slot == slot {
                Ok(Some(state))
            } else {
                tracing::info!(
                    "Epoch {}, State slot {} does not match latest block header slot {}, going backwards",
                    epoch,
                    slot,
                    latest_block_header.slot
                );
                self.get_state_at_slot(latest_block_header.slot)
            }
        } else {
            state
        }
    }

    fn get_state_at_slot(&self, slot: u64) -> Result<Option<BeaconState>, anyhow::Error> {
        let epoch = self.context.compute_epoch_at_slot(slot);
        let file = self.directory.join(format!("{}_beacon_state.ssz", slot));
        if !file.exists() {
            return Ok(None);
        }

        debug!("Loading beacon state at slot {slot} in epoch: {epoch}");
        let bytes = fs::read(&file)?;
        let state: BeaconState = ssz_rs::deserialize(&bytes)?;

        Ok(Some(state))
    }
}

impl From<FileProvider> for BoxedStateProvider {
    fn from(provider: FileProvider) -> Self {
        Box::new(provider)
    }
}
