use ethereum_consensus::electra::{Validator, mainnet::VALIDATOR_REGISTRY_LIMIT};
use ssz_multiproofs::MultiproofBuilder;
use ssz_rs::prelude::*;
use thiserror::Error;
use tracing::info;

use crate::{
    Epoch, HostContext, PublicKey, StatePatch, StateReader, beacon_state::mainnet::BeaconState,
    mainnet::ElectraBeaconState,
};
use std::{cell::RefCell, collections::BTreeMap};

use super::{HostStateReader, SszStateReader, host_state_reader::HostReaderError};

#[derive(Error, Debug)]
pub enum TrackingReaderError {
    #[error("HostReaderError: {0}")]
    HostReaderError(#[from] HostReaderError),
}

pub struct TrackingStateReader {
    pub trusted_epoch: Epoch,
    pub patches: RefCell<BTreeMap<Epoch, StatePatch>>,
    pub reader: HostStateReader,
}

impl TrackingStateReader {
    pub fn new(reader: HostStateReader, trusted_epoch: Epoch) -> Self {
        Self {
            trusted_epoch,
            // validators_accessed: RefCell::new(BTreeSet::new()),
            patches: RefCell::new(BTreeMap::new()),
            reader,
        }
    }

    pub fn host_reader(&self) -> &HostStateReader {
        &self.reader
    }

    #[tracing::instrument(skip(self))]
    pub fn build(&mut self) -> SszStateReader {
        let state = self
            .reader
            .get_beacon_state_by_epoch(self.trusted_epoch)
            .unwrap();
        let beacon_state_root = state.hash_tree_root().unwrap();

        let state_builder: MultiproofBuilder = MultiproofBuilder::new();

        let randao_mixes_gindex = {
            let mix_epoch = (self.trusted_epoch
                + (self.reader.context.epochs_per_historical_vector
                    - self.reader.context.min_seed_lookahead)
                - 1)
                % self.reader.context.epochs_per_historical_vector;
            let path = &["randao_mixes".into(), (mix_epoch as usize).into()];
            ElectraBeaconState::generalized_index(path).unwrap()
        };

        let state_multiproof = match state {
            BeaconState::Electra(state) => state_builder
                .with_path::<ElectraBeaconState>(&["validators".into()])
                .with_gindex(randao_mixes_gindex)
                .build(state)
                .unwrap(),
            _ => {
                panic!("Unsupported beacon fork. electra only for now")
            }
        };

        state_multiproof.verify(&beacon_state_root).unwrap();

        let validators_root = state.validators().hash_tree_root().unwrap();

        info!("Number of validators: {}", state.validators().len());
        let g_indices = (0..state.validators().len()).flat_map(|idx| {
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
        let v_count_gindex =
            <List<Validator, VALIDATOR_REGISTRY_LIMIT>>::generalized_index(&[PathElement::Length])
                .unwrap();
        let g_indices = g_indices.chain(std::iter::once(v_count_gindex));

        info!("Building Validator multiproof");
        let validator_multiproof = MultiproofBuilder::new()
            .with_gindices(g_indices)
            .build(state.validators())
            .unwrap();
        info!("Validator multiproof finished");

        validator_multiproof.verify(&validators_root).unwrap();

        let patches = self.patches.replace(BTreeMap::new());
        SszStateReader {
            trusted_epoch: self.trusted_epoch,
            beacon_state: state_multiproof,
            validators: validator_multiproof,
            patches,
            cache: Default::default(),
        }
    }
}

impl StateReader for TrackingStateReader {
    type Error = TrackingReaderError;

    fn get_randao(&self, epoch: Epoch) -> Result<Option<[u8; 32]>, Self::Error> {
        if epoch != self.trusted_epoch {
            let state_a = self.reader.get_beacon_state_by_epoch(epoch - 1).unwrap();
            let state_b = self.reader.get_beacon_state_by_epoch(epoch).unwrap();
            info!("Creating patch for epoch {} to {}", epoch - 1, epoch);
            let patch = StatePatch::patch::<HostContext>(
                &self.reader.context.clone().into(),
                state_a,
                state_b,
            )
            .unwrap();
            if self.patches.borrow_mut().insert(epoch, patch).is_some() {
                panic!("Patch for epoch {} already exists", epoch);
            }
        }
        Ok(self.reader.get_randao(epoch)?)
    }

    fn aggregate_validator_keys_and_balance(
        &self,
        indices: impl IntoIterator<Item = usize>,
    ) -> Result<(Vec<PublicKey>, u64), Self::Error> {
        Ok(self.reader.aggregate_validator_keys_and_balance(indices)?)
    }

    fn get_validator_activation_and_exit_epochs(
        &self,
        epoch: Epoch,
        validator_index: usize,
    ) -> Result<(u64, u64), Self::Error> {
        Ok(self
            .reader
            .get_validator_activation_and_exit_epochs(epoch, validator_index)?)
    }

    fn get_validator_count(&self, epoch: Epoch) -> Result<Option<usize>, Self::Error> {
        Ok(self.reader.get_validator_count(epoch)?)
    }

    fn get_total_active_balance(&self, epoch: Epoch) -> Result<u64, Self::Error> {
        Ok(self.reader.get_total_active_balance(epoch)?)
    }

    fn get_active_validator_indices(&self, epoch: Epoch) -> Result<Vec<usize>, Self::Error> {
        Ok(self.reader.get_active_validator_indices(epoch)?)
    }
}
