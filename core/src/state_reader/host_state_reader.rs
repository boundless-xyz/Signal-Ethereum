use super::TrackingStateReader;
use crate::HostReaderError::StateMissing;
use crate::state_reader::state_provider::{BoxedStateProvider, FileProvider};
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
    #[error("Not in cache")]
    NotInCache,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub struct HostStateReader {
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
                        assert_eq!(
                            root, &genesis_validators_root,
                            "Validator root not the same"
                        );
                    }
                    root => *root = Some(genesis_validators_root),
                }
                // TODO: check that the states form a chain

                Ok(self.state_cache.insert(epoch, state.into()))
            }
        }
    }

    pub fn genesis_validators_root(&self) -> Option<Root> {
        *self.genesis_validators_root.borrow()
    }
}

impl HostStateReader {
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

    pub fn track(&self, at_epoch: Epoch) -> TrackingStateReader<'_> {
        TrackingStateReader::new(&self, at_epoch)
    }

    pub fn get_beacon_state_by_epoch(&self, epoch: Epoch) -> Result<&BeaconState, HostReaderError> {
        self.state_cache.get(epoch)
    }
}

impl StateReader for HostStateReader {
    type Error = HostReaderError;
    type Context = HostContext;

    fn context(&self) -> &Self::Context {
        &self.context
    }

    fn genesis_validators_root(&self) -> B256 {
        let root = self.state_cache.genesis_validators_root().unwrap();
        B256::from(root.0)
    }

    fn fork_current_version(&self, epoch: Epoch) -> Result<Version, HostReaderError> {
        let state = self.state_cache.get(epoch)?;
        Ok(state.fork().current_version)
    }

    fn active_validators(
        &self,
        state_epoch: Epoch,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        trace!("HostStateReader::active_validators({state_epoch},{epoch})");
        assert!(state_epoch >= epoch, "Only historical epochs supported");

        let iter = match self.validator_cache.get(&state_epoch) {
            Some(validators) => validators.iter(),
            None => {
                let state = self.state_cache.get(state_epoch)?;

                debug!("Caching validators for epoch {}...", state_epoch);
                let validators: Vec<_> = state
                    .validators()
                    .iter()
                    .enumerate()
                    .filter(move |(_, validator)| is_active_validator(validator, epoch))
                    .map(move |(idx, validator)| (idx, ValidatorInfo::from(validator)))
                    .collect();
                debug!("Active validators: {}", validators.len());

                self.validator_cache.insert(state_epoch, validators).iter()
            }
        };

        Ok(iter.map(|(idx, validator)| (*idx, validator)))
    }

    fn randao_mix(&self, epoch: Epoch, idx: usize) -> Result<Option<B256>, Self::Error> {
        trace!("HostStateReader::randao_mix({epoch},{idx})");
        let state = self.state_cache.get(epoch)?;

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
