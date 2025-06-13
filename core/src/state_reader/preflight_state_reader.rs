use ethereum_consensus::electra::{Validator, mainnet::VALIDATOR_REGISTRY_LIMIT};
use ssz_multiproofs::MultiproofBuilder;
use ssz_rs::prelude::*;
use thiserror::Error;

use super::{StateInput, host_state_reader::HostReaderError};
use crate::{
    Epoch, StatePatchBuilder, StateProvider, StateReader, ValidatorIndex, ValidatorInfo, Version,
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

/// A PreflightStateReader functions identically to a StateReader. In fact it is just a wrapper around one.
/// It is used to record the state data read from the StateReader as it is used. This data can then be packed into a `StateInput`
/// This StateInput can be serialized and sent to another context for use where there is no access to a beacon API
pub struct PreflightStateReader<'a, SR> {
    /// The wrapped StateReader
    inner: &'a SR,
    // The data used for recording the state data read from the StateReader
    validator_indices: RefCell<BTreeSet<ValidatorIndex>>,
    mix_epochs: RefCell<BTreeMap<Epoch, BTreeSet<usize>>>,
}

impl<'a, SR> PreflightStateReader<'a, SR>
where
    SR: StateReader,
{
    pub fn new(reader: &'a SR) -> Self {
        Self {
            inner: reader,
            validator_indices: Default::default(),
            mix_epochs: Default::default(),
        }
    }

    pub fn host_reader(&self) -> &SR {
        &self.inner
    }

    pub fn to_input<SP>(&self, state_provider: &SP) -> StateInput
    where
        SP: StateProvider,
    {
        let state = state_provider
            .get_state_at_epoch_boundary(self.inner.epoch())
            .unwrap()
            .expect("StateProvider should provide state at epoch boundary");
        let beacon_state_root = state.hash_tree_root().unwrap();

        let mut patch_builder: BTreeMap<Epoch, StatePatchBuilder<SR::Context>> = BTreeMap::new();
        let mut proof_builder: MultiproofBuilder = MultiproofBuilder::new();

        for (epoch, indices) in self.mix_epochs.take() {
            let mix_state = state_provider
                .get_state_at_epoch_boundary(epoch)
                .unwrap()
                .expect("StateProvider should provide state at epoch boundary");
            if epoch == self.inner.epoch() {
                for idx in indices {
                    let path = ["randao_mixes".into(), idx.into()];
                    proof_builder = proof_builder.with_path::<ElectraBeaconState>(&path);
                }
            } else {
                let patch = patch_builder
                    .entry(epoch)
                    .or_insert(StatePatchBuilder::new(mix_state, self.context()));
                for idx in indices {
                    patch.randao_mix(idx);
                }
            }
        }

        info!("Building State multiproof");
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

    fn fork_current_version(&self) -> Result<Version, Self::Error> {
        Ok(self.inner.fork_current_version()?)
    }
}
