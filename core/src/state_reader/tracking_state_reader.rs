use ethereum_consensus::electra::{Validator, mainnet::VALIDATOR_REGISTRY_LIMIT};
use ssz_multiproofs::MultiproofBuilder;
use ssz_rs::prelude::*;
use thiserror::Error;
use tracing::info;

use super::{HostStateReader, SszStateReader, host_state_reader::HostReaderError};
use crate::{
    Epoch, HostContext, StatePatch, StateReader, ValidatorIndex, ValidatorInfo, Version,
    beacon_state::mainnet::BeaconState, mainnet::ElectraBeaconState,
};
use alloy_primitives::B256;
use std::{cell::RefCell, collections::BTreeMap};

#[derive(Error, Debug)]
pub enum TrackingReaderError {
    #[error("HostReaderError: {0}")]
    HostReaderError(#[from] HostReaderError),
}

pub struct TrackingStateReader {
    trusted_epoch: Epoch,
    patches: RefCell<BTreeMap<Epoch, StatePatch>>,
    mix_epochs: RefCell<Vec<Epoch>>,
    reader: HostStateReader,
}

impl TrackingStateReader {
    pub fn new(reader: HostStateReader, trusted_epoch: Epoch) -> Self {
        Self {
            trusted_epoch,
            // validators_accessed: RefCell::new(BTreeSet::new()),
            patches: RefCell::new(BTreeMap::new()),
            mix_epochs: RefCell::new(Vec::new()),
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
            let &[mix_epoch] = self.mix_epochs.borrow().as_slice() else {
                panic!("only one mix epoch is supported");
            };
            let path = &["randao_mixes".into(), (mix_epoch as usize).into()];
            ElectraBeaconState::generalized_index(path).unwrap()
        };

        let state_multiproof = match state {
            BeaconState::Electra(state) => state_builder
                .with_path::<ElectraBeaconState>(&["genesis_validators_root".into()])
                .with_path::<ElectraBeaconState>(&["fork".into(), "current_version".into()])
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

        info!("Total Number of validators: {}", state.validators().len());
        let active_validators = self
            .get_active_validator_indices(self.trusted_epoch)
            .unwrap()
            .collect::<Vec<_>>();
        let active_validator_count = active_validators.len();
        info!("Number of active validators: {active_validator_count}");
        let patches: BTreeMap<u64, StatePatch> = self.patches.replace(BTreeMap::new());

        // Get all the validator indices in patches (activations and exits)
        let patched_val_indices = patches
            .values()
            .flat_map(|patch| {
                patch
                    .activations
                    .iter()
                    .chain(patch.exits.iter())
                    .map(|idx| *idx as usize)
            })
            .collect::<Vec<_>>();
        info!(
            "Number of patched validators: {}",
            patched_val_indices.len()
        );
        let g_indices = active_validators
            .into_iter()
            .chain(patched_val_indices)
            .flat_map(|idx| {
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
                        <List<Validator, VALIDATOR_REGISTRY_LIMIT>>::generalized_index(path)
                            .unwrap()
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
    type Context = HostContext;

    fn context(&self) -> &Self::Context {
        self.reader.context()
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        Ok(self.reader.active_validators(epoch)?)
    }

    fn get_randao_mix(&self, epoch: Epoch, mix: Epoch) -> Result<B256, Self::Error> {
        if epoch != self.trusted_epoch {
            let state_a = self.reader.get_beacon_state_by_epoch(epoch - 1).unwrap();
            let state_b = self.reader.get_beacon_state_by_epoch(epoch).unwrap();
            info!("Creating patch for epoch {} to {}", epoch - 1, epoch);
            let patch =
                StatePatch::patch::<HostContext>(self.reader.context(), state_a, state_b).unwrap();
            if self.patches.borrow_mut().insert(epoch, patch).is_some() {
                panic!("Patch for epoch {} already exists", epoch);
            }
        } else {
            self.mix_epochs.borrow_mut().push(mix);
        }
        Ok(self.reader.get_randao_mix(epoch, mix)?)
    }

    fn genesis_validators_root(&self) -> alloy_primitives::B256 {
        self.reader.genesis_validators_root()
    }

    fn fork_version(&self, epoch: Epoch) -> Result<Version, Self::Error> {
        Ok(self.reader.fork_version(epoch)?)
    }
}
