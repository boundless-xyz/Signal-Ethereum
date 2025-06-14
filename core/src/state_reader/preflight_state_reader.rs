use ethereum_consensus::electra::{Validator, mainnet::VALIDATOR_REGISTRY_LIMIT};
use ssz_multiproofs::MultiproofBuilder;
use ssz_rs::prelude::*;
use thiserror::Error;

use super::{StateInput, host_state_reader::HostReaderError};
use crate::{
    Epoch, StateProvider, StateReader, ValidatorIndex, ValidatorInfo, Version,
    beacon_state::mainnet::BeaconState, mainnet::ElectraBeaconState,
};
use alloy_primitives::B256;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};
use tracing::info;

#[derive(Error, Debug)]
pub enum PreflightError {
    #[error("HostReaderError: {0}")]
    HostReader(#[from] HostReaderError),

    #[error("StateProvider error: {0}")]
    StateProviderError(#[from] anyhow::Error),

    #[error("Provider returned None state for epoch: {0}")]
    MissingState(Epoch),

    #[error("Missing Randao mix for epoch: {0}, index: {1}")]
    MissingRandao(Epoch, usize),
}

/// A PreflightStateReader wraps a state reader and records which pieces of data are read.
/// This data can then be packed into a `StateInput`
/// This StateInput can be serialized and sent to another context for use where there is no access to a beacon API
pub struct PreflightStateReader<'a, SR> {
    /// The wrapped StateReader
    inner: &'a SR,
    // The data used for recording the state data read from the StateReader
    validator_indices: RefCell<BTreeSet<ValidatorIndex>>,
    randao_reads: RefCell<BTreeMap<Epoch, BTreeSet<usize>>>,
}

impl<'a, SR> PreflightStateReader<'a, SR>
where
    SR: StateReader,
{
    pub fn new(reader: &'a SR) -> Self {
        Self {
            inner: reader,
            validator_indices: Default::default(),
            randao_reads: Default::default(),
        }
    }

    pub fn host_reader(&self) -> &SR {
        &self.inner
    }

    pub fn to_input<SP>(&self, state_provider: &SP) -> Result<StateInput, PreflightError>
    where
        SP: StateProvider,
    {
        let mut randao: BTreeMap<Epoch, BTreeMap<usize, B256>> = BTreeMap::new();
        let proof_builder: MultiproofBuilder = MultiproofBuilder::new();

        // Retrieve all the data for every RANDO read
        // These are unconstrained so no need to add them to the multiproof
        for (epoch, indices) in self.randao_reads.take() {
            let mix_state = state_provider
                .get_state_at_epoch_boundary(epoch)?
                .ok_or(PreflightError::MissingState(epoch))?;

            for idx in indices {
                let mix = mix_state
                    .randao_mixes()
                    .get(idx)
                    .ok_or(PreflightError::MissingRandao(epoch, idx))?;
                randao
                    .entry(epoch)
                    .or_default()
                    .entry(idx)
                    .or_insert_with(|| B256::from_slice(mix.as_slice()));
            }
        }

        info!("Building State multiproof");
        let state = state_provider
            .get_state_at_epoch_boundary(self.inner.epoch())?
            .ok_or(PreflightError::MissingState(self.inner.epoch()))?;
        let beacon_state_root = state.hash_tree_root().unwrap();

        let state_multiproof = match state {
            BeaconState::Electra(ref state) => proof_builder
                .with_path::<ElectraBeaconState>(&["genesis_validators_root".into()])
                .with_path::<ElectraBeaconState>(&["slot".into()])
                .with_path::<ElectraBeaconState>(&["fork".into(), "current_version".into()])
                .with_path::<ElectraBeaconState>(&["validators".into()])
                .build(state)
                .unwrap(),
            _ => {
                panic!("Unsupported beacon fork. electra only for now")
            }
        };
        state_multiproof.verify(&beacon_state_root).unwrap();
        info!("State multiproof finished");

        let validators_root = state.validators().hash_tree_root().unwrap();

        let mut validators = BTreeMap::new();
        for idx in self.validator_indices.take() {
            let validator = ValidatorInfo::from(state.validators().get(idx).unwrap());
            validators.insert(idx, validator);
        }
        info!(
            "Used validators: {}/{}",
            validators.len(),
            state.validators().len()
        );

        let g_indices = validators.keys().flat_map(|&idx| {
            let public_key_path: &[Path] = &[
                &[idx.into(), "public_key".into(), 0.into()],
                &[idx.into(), "public_key".into(), 47.into()], // public key is a Vector<u8, 48>, so it takes up 2 leafs
            ];

            let balance_epoch_path: &[Path] = &[
                &[idx.into(), "effective_balance".into()],
                &[idx.into(), "activation_epoch".into()],
                &[idx.into(), "exit_epoch".into()],
            ];

            let g_indices = public_key_path
                .iter()
                .chain(balance_epoch_path)
                .map(|path| {
                    <List<Validator, VALIDATOR_REGISTRY_LIMIT>>::generalized_index(path).unwrap()
                })
                .collect::<Vec<_>>();

            g_indices
        });

        info!("Building Validator multiproof");
        let validator_multiproof = MultiproofBuilder::new()
            .with_gindices(g_indices)
            .build(state.validators())
            .unwrap();
        validator_multiproof.verify(&validators_root).unwrap();
        info!("Validator multiproof finished");

        let public_keys = validators
            .into_values()
            .map(|validator| validator.pubkey)
            .collect();

        Ok(StateInput {
            epoch: self.inner.epoch(),
            beacon_state: state_multiproof,
            active_validators: validator_multiproof,
            public_keys,
            randao,
        })
    }
}

impl<'a, SR> StateReader for PreflightStateReader<'a, SR>
where
    SR: StateReader,
{
    type Error = SR::Error;
    type Context = SR::Context;

    fn epoch(&self) -> Epoch {
        self.inner.epoch()
    }

    fn context(&self) -> &Self::Context {
        self.inner.context()
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        let iter = self.inner.active_validators(epoch)?;
        Ok(iter.inspect(|(idx, _)| {
            self.validator_indices.borrow_mut().insert(*idx);
        }))
    }

    fn randao_mix(&self, epoch: Epoch, idx: usize) -> Result<Option<B256>, Self::Error> {
        assert!(epoch >= self.epoch());

        // to be able to prove the inclusion, the randao value must exist
        let randao = self.inner.randao_mix(epoch, idx)?.unwrap();
        self.randao_reads
            .borrow_mut()
            .entry(epoch)
            .or_default()
            .insert(idx);

        Ok(Some(randao))
    }

    fn genesis_validators_root(&self) -> alloy_primitives::B256 {
        self.inner.genesis_validators_root()
    }

    fn fork_current_version(&self) -> Result<Version, Self::Error> {
        Ok(self.inner.fork_current_version()?)
    }
}
