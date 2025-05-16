use super::TrackingStateReader;
use crate::HostReaderError::StateMissing;
use crate::state_reader::state_provider::{BoxedStateProvider, FileProvider};
use crate::{
    Epoch, HostContext, Root, StateReader, ValidatorIndex, ValidatorInfo, Version,
    beacon_state::mainnet::BeaconState,
};
use alloy_primitives::B256;
use elsa::FrozenMap;
use ethereum_consensus::state_transition::Context;
use ssz_rs::prelude::*;
use std::cell::{Cell, RefCell};
use std::mem::MaybeUninit;
use std::ops::DerefMut;
use std::{path::PathBuf, slice};
use thiserror::Error;
use tracing::debug;

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
    validator_cache: AppendVec<ValidatorInfo, 2_000_000>,
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
                let state = self.provider.get_state(epoch)?.ok_or(StateMissing)?;
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

/// An append-only buffer of capacity N.
/// `append` takes &self, there's no realloc or borrow panics.
pub struct AppendVec<T, const N: usize> {
    buf: RefCell<Box<[MaybeUninit<T>]>>,
    len: Cell<usize>,
}

impl<T, const N: usize> AppendVec<T, N> {
    /// Create an empty buffer.
    pub fn new() -> Self {
        Self {
            buf: RefCell::new(Box::new_uninit_slice(N)),
            len: Cell::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.len.get()
    }

    pub fn extend(&self, iter: impl IntoIterator<Item = T>) {
        iter.into_iter().for_each(|x| self.append(x))
    }

    /// Append one element. Panics if full.
    pub fn append(&self, x: T) {
        let i = self.len();
        assert!(i < N);
        self.buf.borrow_mut()[i].write(x);
        self.len.set(i + 1);
    }

    /// Borrow all initialized elements as a slice.
    pub fn as_slice(&self) -> &[T] {
        let len = self.len();
        unsafe { slice::from_raw_parts(self.buf.borrow().as_ptr() as *const T, len) }
    }
}

impl<T, const N: usize> Drop for AppendVec<T, N> {
    fn drop(&mut self) {
        for elem in &mut self.buf.borrow_mut()[0..self.len()] {
            unsafe { elem.assume_init_drop() };
        }
    }
}

impl HostStateReader {
    pub fn new(provider: BoxedStateProvider, context: Context) -> Self {
        Self {
            context: context.into(),
            state_cache: StateCache::new(provider),
            validator_cache: AppendVec::new(),
        }
    }

    pub fn new_with_dir(
        dir: impl Into<PathBuf>,
        context: Context,
    ) -> Result<Self, HostReaderError> {
        let provider = FileProvider::new(dir, &context)?;
        Ok(Self::new(provider.into(), context))
    }

    pub fn track(self, at_epoch: Epoch) -> TrackingStateReader {
        TrackingStateReader::new(self, at_epoch)
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

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        // check whether we need to append new validators to the cache
        let state = self.state_cache.get(epoch)?;
        let validator_count = state.validators().len();

        let cache_len = self.validator_cache.len();
        if validator_count > cache_len {
            debug!("Caching new validators: {}", validator_count - cache_len);
            self.validator_cache.extend(
                state
                    .validators()
                    .get(cache_len..)
                    .unwrap()
                    .iter()
                    .map(ValidatorInfo::from),
            );
        }

        Ok(self
            .validator_cache
            .as_slice()
            .iter()
            .enumerate()
            .filter(move |(_, validator)| is_active_validator(validator, epoch)))
    }

    fn randao_mix(&self, epoch: Epoch, idx: usize) -> Result<Option<B256>, Self::Error> {
        let state = self.state_cache.get(epoch)?;

        Ok(state
            .randao_mixes()
            .get(idx)
            .map(|randao| B256::from_slice(randao.as_slice())))
    }

    fn genesis_validators_root(&self) -> B256 {
        let root = self.state_cache.genesis_validators_root().unwrap();
        B256::from(root.0)
    }

    fn fork_version(&self, epoch: Epoch) -> Result<Version, HostReaderError> {
        let state = self.state_cache.get(epoch)?;
        Ok(state.fork().current_version)
    }
}

/// Check if `validator` is active.
fn is_active_validator(validator: &ValidatorInfo, epoch: Epoch) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch
}
