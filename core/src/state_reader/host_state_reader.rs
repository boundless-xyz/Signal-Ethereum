use crate::HostReaderError::StateMissing;
use crate::state_reader::state_provider::{BoxedStateProvider, FileProvider};
use crate::{Ctx, StateProvider, ensure};
use crate::{
    Epoch, HostContext, Root, StateReader, ValidatorIndex, ValidatorInfo, Version,
    beacon_state::mainnet::BeaconState,
};
use alloy_primitives::B256;
use elsa::FrozenMap;
use ethereum_consensus::phase0::Validator;
use ssz_rs::prelude::*;
use std::cell::RefCell;
use std::ops::DerefMut;
use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, trace};

#[derive(Error, Debug)]
pub enum HostReaderError {
    #[error("Io: {0}")]
    Io(#[from] std::io::Error),
    #[error("SszDeserialize: {0}")]
    SszDeserialize(#[from] ssz_rs::DeserializeError),
    #[error("SszMerklize: {0}")]
    SszMerkleization(#[from] ssz_rs::MerkleizationError),
    #[error("State missing")]
    StateMissing,
    #[error("Retrieved state does not match expected genesis validators root")]
    GenesisValidatorRootMismatch { expected: Root, actual: Root },
    #[error("Not in cache")]
    NotInCache,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub struct HostReaderBuilder {
    context: HostContext,
    state_cache: StateCache,
    validator_cache: FrozenMap<Epoch, Vec<(ValidatorIndex, ValidatorInfo)>>,
}

struct StateCache {
    provider: BoxedStateProvider,
    state_cache: FrozenMap<Epoch, Box<BeaconState>>,
    genesis_validators_root: RefCell<Option<Root>>,
}

impl StateCache {
    fn new(provider: BoxedStateProvider) -> Self {
        Self {
            provider,
            state_cache: FrozenMap::new(),
            genesis_validators_root: RefCell::new(None),
        }
    }

    pub fn get(&self, epoch: Epoch) -> Result<&BeaconState, HostReaderError> {
        match self.state_cache.get(&epoch) {
            Some(beacon_state) => Ok(beacon_state),
            None => {
                let state = self
                    .provider
                    .get_state_at_epoch_boundary(epoch)?
                    .ok_or(StateMissing)?;
                let genesis_validators_root = state.genesis_validators_root();
                match self.genesis_validators_root.borrow_mut().deref_mut() {
                    Some(root) => {
                        ensure!(
                            *root == genesis_validators_root,
                            HostReaderError::GenesisValidatorRootMismatch {
                                expected: *root,
                                actual: genesis_validators_root
                            }
                        );
                    }
                    root => *root = Some(genesis_validators_root),
                }
                Ok(self.state_cache.insert(epoch, state.into()))
            }
        }
    }

    pub fn genesis_validators_root(&self) -> Option<Root> {
        *self.genesis_validators_root.borrow()
    }
}

impl HostReaderBuilder {
    pub fn new(provider: BoxedStateProvider, context: HostContext) -> Self {
        Self {
            context,
            state_cache: StateCache::new(provider),
            validator_cache: Default::default(),
        }
    }

    pub fn new_with_dir(
        dir: impl Into<PathBuf>,
        context: HostContext,
    ) -> Result<Self, HostReaderError> {
        let provider = FileProvider::new(dir, &context)?;
        Ok(Self::new(provider.into(), context))
    }

    pub fn get_beacon_state_by_epoch(&self, epoch: Epoch) -> Result<&BeaconState, HostReaderError> {
        self.state_cache.get(epoch)
    }

    /// Obtain an HostStateReader for a specific epoch
    pub fn build_at_epoch<'a>(&'a self, epoch: Epoch) -> HostStateReader<'a> {
        HostStateReader {
            host_state_reader: self,
            epoch,
        }
    }
}

impl StateProvider for HostReaderBuilder {
    fn context(&self) -> &HostContext {
        &self.context
    }

    fn get_state_at_epoch_boundary(
        &self,
        epoch: Epoch,
    ) -> Result<Option<BeaconState>, anyhow::Error> {
        Ok(self
            .state_cache
            .get(epoch)
            .map(|state| Some(state.clone()))?)
    }

    fn get_state_at_slot(&self, slot: u64) -> Result<Option<BeaconState>, anyhow::Error> {
        Ok(self
            .state_cache
            .get(self.context.compute_epoch_at_slot(slot))
            .map(|state| Some(state.clone()))?)
    }
}

pub struct HostStateReader<'a> {
    host_state_reader: &'a HostReaderBuilder,
    epoch: Epoch,
}

impl<'a> StateReader for HostStateReader<'a> {
    type Error = HostReaderError;
    type Context = HostContext;

    fn epoch(&self) -> Epoch {
        self.epoch
    }

    fn context(&self) -> &Self::Context {
        &self.host_state_reader.context
    }

    fn genesis_validators_root(&self) -> B256 {
        let root = self
            .host_state_reader
            .state_cache
            .genesis_validators_root()
            .unwrap();
        B256::from(root.0)
    }

    fn fork_current_version(&self) -> Result<Version, HostReaderError> {
        let state = self.host_state_reader.state_cache.get(self.epoch)?;
        Ok(state.fork().current_version)
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        trace!("HostStateReader::active_validators({},{epoch})", self.epoch);

        let iter = match self.host_state_reader.validator_cache.get(&self.epoch) {
            Some(validators) => validators.iter(),
            None => {
                let state = self.host_state_reader.state_cache.get(self.epoch)?;

                debug!("Caching validators for epoch {}...", self.epoch);
                let validators: Vec<_> = state
                    .validators()
                    .iter()
                    .enumerate()
                    .filter(move |(_, validator)| is_active_validator(validator, epoch))
                    .map(move |(idx, validator)| (idx, ValidatorInfo::from(validator)))
                    .collect();
                debug!("Active validators: {}", validators.len());

                self.host_state_reader
                    .validator_cache
                    .insert(self.epoch, validators)
                    .iter()
            }
        };

        Ok(iter.map(|(idx, validator)| (*idx, validator)))
    }

    fn randao_mix(&self, epoch: Epoch, idx: usize) -> Result<Option<B256>, Self::Error> {
        trace!("HostStateReader::randao_mix({epoch},{idx})");
        let state = self.host_state_reader.state_cache.get(epoch)?;

        Ok(state
            .randao_mixes()
            .get(idx)
            .map(|randao| B256::from_slice(randao.as_slice())))
    }
}

/// Check if `validator` is active.
fn is_active_validator(validator: &Validator, epoch: Epoch) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch
}
