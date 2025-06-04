use ethereum_consensus::electra::{Validator, mainnet::VALIDATOR_REGISTRY_LIMIT};
use ssz_multiproofs::MultiproofBuilder;
use ssz_rs::prelude::*;
use thiserror::Error;

use super::{HostStateReader, StateInput, host_state_reader::HostReaderError};
use crate::{
    Epoch, HostContext, StatePatchBuilder, StateReader, ValidatorIndex, ValidatorInfo, Version,
    beacon_state::mainnet::BeaconState, mainnet::ElectraBeaconState,
};
use alloy_primitives::B256;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};
use tracing::info;

#[derive(Error, Debug)]
pub enum TrackingReaderError {
    #[error("HostReaderError: {0}")]
    HostReaderError(#[from] HostReaderError),
}

pub struct TrackingStateReader<'a> {
    trusted_epoch: Epoch,
    inner: &'a HostStateReader,
    validator_indices: RefCell<BTreeSet<ValidatorIndex>>,
    validator_epochs: RefCell<BTreeSet<Epoch>>,
    mix_epochs: RefCell<BTreeMap<Epoch, BTreeSet<usize>>>,
}

impl<'a> TrackingStateReader<'a> {
    pub fn new(reader: &'a HostStateReader, trusted_epoch: Epoch) -> Self {
        Self {
            trusted_epoch,
            inner: reader,
            validator_indices: Default::default(),
            validator_epochs: Default::default(),
            mix_epochs: Default::default(),
        }
    }

    pub fn host_reader(&self) -> &HostStateReader {
        &self.inner
    }

    pub fn to_input(&self) -> StateInput {
        let state = self
            .inner
            .get_beacon_state_by_epoch(self.trusted_epoch)
            .unwrap();
        let beacon_state_root = state.hash_tree_root().unwrap();

        let mut patch_builder: BTreeMap<Epoch, StatePatchBuilder> = BTreeMap::new();
        let mut proof_builder: MultiproofBuilder = MultiproofBuilder::new();

        for (epoch, indices) in self.mix_epochs.take() {
            if epoch == self.trusted_epoch {
                for idx in indices {
                    let path = ["randao_mixes".into(), idx.into()];
                    proof_builder = proof_builder.with_path::<ElectraBeaconState>(&path);
                }
            } else {
                let patch = patch_builder
                    .entry(epoch)
                    .or_insert(self.patch_builder(epoch).unwrap());
                for idx in indices {
                    patch.randao_mix(idx);
                }
            }
        }

        info!("Building State multiproof");
        let state_multiproof = match state {
            BeaconState::Electra(state) => proof_builder
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

        let patches = patch_builder
            .into_iter()
            .map(|(k, v)| (k, v.build()))
            .collect();

        StateInput {
            beacon_state: state_multiproof,
            active_validators: validator_multiproof,
            public_keys,
            patches,
        }
    }

    fn patch_builder(&self, epoch: Epoch) -> Result<StatePatchBuilder, HostReaderError> {
        let state = self.inner.get_beacon_state_by_epoch(epoch)?;
        let context = self.inner.context();

        Ok(StatePatchBuilder::new(state, context))
    }
}

impl<'a> StateReader for TrackingStateReader<'a> {
    type Error = TrackingReaderError;
    type Context = HostContext;

    fn context(&self) -> &Self::Context {
        self.inner.context()
    }

    fn active_validators(
        &self,
        state: Epoch,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        assert!(state >= self.trusted_epoch);

        let iter = self.inner.active_validators(state, epoch)?;
        self.validator_epochs.borrow_mut().insert(state);

        Ok(iter.inspect(|(idx, _)| {
            self.validator_indices.borrow_mut().insert(*idx);
        }))
    }

    fn randao_mix(&self, epoch: Epoch, idx: usize) -> Result<Option<B256>, Self::Error> {
        assert!(epoch >= self.trusted_epoch);

        // to be able to prove the inclusion, the randao value must exist
        let randao = self.inner.randao_mix(epoch, idx)?.unwrap();
        self.mix_epochs
            .borrow_mut()
            .entry(epoch)
            .or_default()
            .insert(idx);

        Ok(Some(randao))
    }

    fn genesis_validators_root(&self) -> alloy_primitives::B256 {
        self.inner.genesis_validators_root()
    }

    fn fork_current_version(&self, epoch: Epoch) -> Result<Version, Self::Error> {
        Ok(self.inner.fork_current_version(epoch)?)
    }
}
