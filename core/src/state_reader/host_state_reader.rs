use ethereum_consensus::{electra::compute_epoch_at_slot, state_transition::Context};
use ssz_rs::prelude::*;
use thiserror::Error;
use tracing::{info, trace};

use crate::{
    Epoch, PublicKey, Root, StateReader, ValidatorInfo, beacon_state::mainnet::BeaconState,
};
use std::{collections::BTreeMap, io::Write, path::PathBuf};

use super::{StateReaderError, TrackingStateReader};

#[derive(Error, Debug)]
pub enum HostReaderError {
    #[error("Io: {0}")]
    Io(#[from] std::io::Error),
    #[error("SszDeserialize: {0}")]
    SszDeserialize(#[from] ssz_rs::DeserializeError),
    #[error("SszMerklize: {0}")]
    SszMerkleization(#[from] ssz_rs::MerkleizationError),
}

pub struct HostStateReader {
    /// Epochs to state roots
    pub state_root: BTreeMap<Epoch, Root>,
    /// Map from state_root to map of gindex and hash or value
    pub cache: BTreeMap<Root, BeaconState>,

    pub validator_cache: Vec<ValidatorInfo>,

    pub context: Context,

    dir: Option<PathBuf>,
}

impl HostStateReader {
    pub fn new_empty(context: Context) -> Self {
        Self {
            state_root: BTreeMap::new(),
            cache: BTreeMap::new(),
            validator_cache: Vec::new(),
            context,
            dir: None,
        }
    }

    pub fn new_with_dir(
        dir: impl Into<PathBuf>,
        context: Context,
    ) -> Result<Self, HostReaderError> {
        let mut dir = dir.into();
        dir.push("states/");
        let mut reader = Self {
            state_root: BTreeMap::new(),
            cache: BTreeMap::new(),
            validator_cache: Vec::new(),
            context,
            dir: Some(dir),
        };
        reader.load_all_from_file()?;
        Ok(reader)
    }

    /// For testing
    pub fn test_with_just_one_dir(
        dir: impl Into<PathBuf>,
        epoch: Epoch,
        context: Context,
    ) -> Result<Self, HostReaderError> {
        let mut reader = Self::new_empty(context);

        let mut dir = dir.into();
        dir.push("states/");
        reader.dir = Some(dir.into());

        let state = reader
            .load_state_file_by_epoch(epoch)?
            .expect("State not found");
        let c_epoch = compute_epoch_at_slot(state.slot(), &reader.context);
        let root = state.hash_tree_root()?;
        assert!(c_epoch == epoch, "Epoch mismatch: {} != {}", c_epoch, epoch);
        reader.cache.insert(root, state);
        reader.state_root.insert(epoch, root);
        Ok(reader)
    }

    pub fn track(self, at_epoch: Epoch) -> TrackingStateReader {
        TrackingStateReader::new(self, at_epoch)
    }

    #[tracing::instrument(skip(self), fields(epoch = %epoch))]
    pub fn build_validator_cache(&mut self, epoch: Epoch) -> Result<(), StateReaderError> {
        info!("Starting to build validator cache");
        let info: Vec<_> = self
            .get_beacon_state_by_epoch(epoch)
            .map(|state| {
                state
                    .validators()
                    .iter()
                    .map(|v| ValidatorInfo {
                        pubkey: v.public_key.clone().into(),
                        effective_balance: v.effective_balance,
                        activation_epoch: v.activation_epoch,
                        exit_epoch: v.exit_epoch,
                    })
                    .collect()
            })
            .unwrap();
        self.validator_cache = info;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn load_all_from_file(&mut self) -> Result<(), HostReaderError> {
        let dir = self
            .dir
            .as_ref()
            .ok_or(HostReaderError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No directory provided",
            )))?;
        let data_dir = std::fs::read_dir(dir)?;
        for path in data_dir {
            let path = path?.path();
            if path.is_file() {
                let mut file = std::fs::File::open(path)?;
                let mut state_bytes = Vec::new();
                std::io::Read::read_to_end(&mut file, &mut state_bytes)?;
                let state: BeaconState = ssz_rs::deserialize(&state_bytes)?;
                let root = state.hash_tree_root()?;
                let epoch = compute_epoch_at_slot(state.slot(), &self.context);
                self.cache.insert(root, state);
                self.state_root.insert(epoch, root);
            }
        }
        info!("Loaded states epochs: {:?}", self.state_root.keys());
        self.save_to_files()?;
        Ok(())
    }

    pub fn save_to_files(&self) -> Result<(), HostReaderError> {
        let dir = self
            .dir
            .as_ref()
            .ok_or(HostReaderError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No directory provided",
            )))?;
        let mut new_write = 0;
        let mut skipped = 0;
        for (epoch, root) in self.state_root.iter() {
            if let Some(state) = self.cache.get(root) {
                let file_path = format!(
                    "{}/{}_{}_beacon_state.ssz",
                    dir.to_string_lossy(),
                    epoch,
                    root
                );
                match std::fs::File::create_new(&file_path) {
                    Ok(mut file) => {
                        file.write_all(&ssz_rs::serialize(state).unwrap())?;
                        new_write += 1;
                    }
                    Err(_e) => {
                        skipped += 1;
                    }
                }
            } else {
                unreachable!("Should be a 1-1 mapping of state_root and cache");
            }
        }
        info!(
            "Saved {} new states and skipped {} existing ones",
            new_write, skipped
        );
        Ok(())
    }

    pub fn get_beacon_state(&self, root: Root) -> Option<&BeaconState> {
        self.cache.get(&root)
    }

    #[tracing::instrument(skip(self), fields(epoch = %epoch))]
    pub fn get_beacon_state_by_epoch(&self, epoch: Epoch) -> Option<&BeaconState> {
        trace!("Get beacon state by epoch: {}", epoch);
        let root = self.state_root.get(&epoch)?;
        self.cache.get(root)
    }

    fn load_state_file_by_epoch(
        &self,
        epoch: Epoch,
    ) -> Result<Option<BeaconState>, HostReaderError> {
        let dir = self
            .dir
            .as_ref()
            .ok_or(HostReaderError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No directory provided",
            )))?;
        // loop through the directory and find the file that starts with epoch
        let data_dir = std::fs::read_dir(dir)?;
        for path in data_dir {
            let path = path?.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                if file_name.starts_with(&format!("{}_", epoch)) {
                    info!("Found file: {}", file_name);
                    let mut file = std::fs::File::open(path)?;
                    let mut state_bytes = Vec::new();
                    std::io::Read::read_to_end(&mut file, &mut state_bytes)?;
                    let state: BeaconState = ssz_rs::deserialize(&state_bytes)?;
                    return Ok(Some(state));
                }
            }
        }
        Ok(None)
    }

    fn _load_state_file_by_root(&self, root: Root) -> Result<Option<BeaconState>, HostReaderError> {
        let dir = self
            .dir
            .as_ref()
            .ok_or(HostReaderError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No directory provided",
            )))?;
        // loop through the directory and find the file that contains the root
        let data_dir = std::fs::read_dir(dir)?;
        for path in data_dir {
            let path = path?.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                if file_name.contains(&format!("_{}_", root)) {
                    let mut file = std::fs::File::open(path)?;
                    let mut state_bytes = Vec::new();
                    std::io::Read::read_to_end(&mut file, &mut state_bytes)?;
                    let state: BeaconState = ssz_rs::deserialize(&state_bytes)?;
                    return Ok(Some(state));
                }
            }
        }
        Ok(None)
    }
}

impl StateReader for HostStateReader {
    type Error = HostReaderError;
    #[tracing::instrument(skip(self), fields(epoch = %epoch))]
    fn get_randao(&self, epoch: u64) -> Result<Option<[u8; 32]>, Self::Error> {
        let mix_epoch = (epoch
            + (self.context.epochs_per_historical_vector - self.context.min_seed_lookahead)
            - 1)
            % self.context.epochs_per_historical_vector;
        info!("Mix epoch: {}", mix_epoch);
        let state = self.get_beacon_state_by_epoch(epoch).unwrap();

        Ok(state
            .randao_mixes()
            .get(mix_epoch as usize)
            .map(|x| {
                let mut mix = [0u8; 32];
                mix.copy_from_slice(x.as_ref());
                Some(mix)
            })
            .expect("randao mix index invalid"))
    }

    #[tracing::instrument(skip(self), fields(epoch = %epoch))]
    fn get_validator_count(&self, epoch: Epoch) -> Result<Option<usize>, Self::Error> {
        Ok(self
            .get_beacon_state_by_epoch(epoch)
            .map(|state| state.validators().len()))
    }
    // return the single aggregate signature and combined active balance obtained from validators indexed by the given indices
    // not that validators indices never change so this is valid even if using a newer state than the current epoch
    fn aggregate_validator_keys_and_balance(
        &self,
        indices: impl IntoIterator<Item = usize>,
    ) -> Result<(Vec<PublicKey>, u64), Self::Error> {
        let mut bal_acc = 0;
        let pk_acc = indices
            .into_iter()
            .map(|idx| {
                let ValidatorInfo {
                    pubkey,
                    effective_balance,
                    ..
                } = &self.validator_cache[idx];
                bal_acc += effective_balance;

                pubkey.clone()
            })
            .collect();

        Ok((pk_acc, bal_acc))
    }

    fn get_validator_activation_and_exit_epochs(
        &self,
        //TODO(ec2): Handle this
        _epoch: Epoch,
        validator_index: usize,
    ) -> Result<(u64, u64), Self::Error> {
        Ok((
            self.validator_cache[validator_index].activation_epoch,
            self.validator_cache[validator_index].exit_epoch,
        ))
    }

    #[tracing::instrument(skip(self), fields(epoch = %epoch))]
    fn get_total_active_balance(&self, epoch: u64) -> Result<u64, Self::Error> {
        self.aggregate_validator_keys_and_balance(self.get_active_validator_indices(epoch)?)
            .map(|x| x.1)
    }

    // can override if there is already a cached copy of this available
    #[tracing::instrument(skip(self), fields(epoch = %epoch))]
    fn get_active_validator_indices(
        &self,
        epoch: u64,
    ) -> Result<impl Iterator<Item = usize>, Self::Error> {
        Ok(
            (0_usize..self.get_validator_count(epoch)?.unwrap()).filter_map(
                move |validator_index| {
                    // TODO: Remove this unwrap
                    let (activation, exit) = self
                        .get_validator_activation_and_exit_epochs(epoch, validator_index)
                        .unwrap();
                    if activation <= epoch && epoch < exit {
                        Some(validator_index)
                    } else {
                        None
                    }
                },
            ),
        )
    }

    fn genesis_validators_root(&self) -> alloy_primitives::B256 {
        let (_, state) = self.cache.first_key_value().unwrap();
        state.genesis_validators_root()
    }

    fn fork_version(&self, epoch: Epoch) -> [u8; 4] {
        self.get_beacon_state_by_epoch(epoch)
            .map(|state| state.fork().current_version)
            .unwrap()
    }
}
