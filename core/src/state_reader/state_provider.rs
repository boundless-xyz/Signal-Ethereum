use crate::{Ctx, Epoch, HostContext, beacon_state::mainnet::BeaconState};
use anyhow::ensure;
use std::fs;
use std::path::PathBuf;
use tracing::debug;

/// A state provider is something that is able to provide a beacon state at a given slot or epoch.
/// This could be an RPC, a cache on disk, or a node running in the same process
pub trait StateProvider {
    fn context(&self) -> &HostContext;

    /// Returns the beacon state at the start of a given epoch. If the slot there is a skip slot,
    /// it will return the state at the latest block header slot that is less than to the epoch's start slot.
    fn get_state_at_epoch_boundary(
        &self,
        epoch: Epoch,
    ) -> Result<Option<BeaconState>, anyhow::Error> {
        let slot = self.context().compute_start_slot_at_epoch(epoch);
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

    fn get_state_at_slot(&self, slot: u64) -> Result<Option<BeaconState>, anyhow::Error>;
}

pub type BoxedStateProvider = Box<dyn StateProvider>;

/// A disk-based state provider that saves and loads beacon states
/// from a specified directory according to a specific naming convention
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
    pub fn clear_state(&self, epoch: Epoch) -> Result<(), anyhow::Error> {
        let file = self.directory.join(format!("{}_beacon_state.ssz", epoch));
        if file.exists() {
            debug!("Clearing beacon state for epoch: {}", epoch);
            fs::remove_file(file)?;
        }
        Ok(())
    }
    pub fn clear_states_before(&self, epoch: Epoch) -> Result<(), anyhow::Error> {
        debug!("Clearing all beacon states before epoch: {}", epoch);
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            if let Some(file_epoch) = entry.file_name().to_str() {
                if let Some(file_epoch) = file_epoch
                    .split('_')
                    .next()
                    .and_then(|s| s.parse::<Epoch>().ok())
                {
                    if file_epoch < epoch {
                        fs::remove_file(entry.path())?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl StateProvider for FileProvider {
    fn context(&self) -> &HostContext {
        &self.context
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
