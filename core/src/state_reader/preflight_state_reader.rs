use ethereum_consensus::electra::{Validator, mainnet::VALIDATOR_REGISTRY_LIMIT};
use ssz_multiproofs::MultiproofBuilder;
use ssz_rs::prelude::*;
use thiserror::Error;

use super::{StateInput, host_state_reader::HostReaderError};
use crate::{
    Checkpoint, Ctx, Epoch, RandaoMixIndex, Root, StatePatchBuilder, StateProvider, StateReader,
    ValidatorIndex, ValidatorInfo, Version, beacon_state::mainnet::BeaconState,
    mainnet::ElectraBeaconState,
};
use alloy_primitives::B256;
use ethereum_consensus::phase0::BeaconBlockHeader;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    ops::Deref,
};
use tracing::info;

#[derive(Error, Debug)]
pub enum PreflightReaderError {
    #[error("HostReaderError: {0}")]
    HostReaderError(#[from] HostReaderError),
}

pub struct PreflightStateReader<'a, SR> {
    trusted_checkpoint: Checkpoint,
    inner: &'a SR,
    validator_indices: RefCell<BTreeSet<ValidatorIndex>>,
    validator_epochs: RefCell<BTreeSet<Epoch>>,
    mix_epochs: RefCell<BTreeMap<Epoch, BTreeSet<RandaoMixIndex>>>,
}

impl<'a, S> PreflightStateReader<'a, S>
where
    S: StateReader + StateProvider,
{
    pub fn new(reader: &'a S, trusted_checkpoint: Checkpoint) -> Self {
        Self {
            trusted_checkpoint,
            inner: reader,
            validator_indices: Default::default(),
            validator_epochs: Default::default(),
            mix_epochs: Default::default(),
        }
    }

    pub fn to_input(&self) -> StateInput {
        let trusted_state = self
            .inner
            .get_state_at_checkpoint(self.trusted_checkpoint)
            .unwrap();
        let beacon_state_root = trusted_state.hash_tree_root().unwrap();

        info!("Building beacon block multiproof");
        let mut epoch_boundary_block = trusted_state.latest_block_header().clone();
        epoch_boundary_block.state_root = beacon_state_root;
        let block_multiproof = MultiproofBuilder::new()
            .with_path::<BeaconBlockHeader>(&["slot".into()])
            .with_path::<BeaconBlockHeader>(&["state_root".into()])
            .build(&epoch_boundary_block)
            .unwrap();
        block_multiproof
            .verify(&self.trusted_checkpoint.root)
            .unwrap();
        info!("Beacon block multiproof finished");

        let mut patch_builder: BTreeMap<Epoch, StatePatchBuilder<S::Context>> = BTreeMap::new();
        let mut proof_builder: MultiproofBuilder = MultiproofBuilder::new();

        for (epoch, indices) in self.mix_epochs.take() {
            if epoch == self.trusted_checkpoint.epoch {
                for idx in indices {
                    let path = ["randao_mixes".into(), (idx as usize).into()];
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

        let state_multiproof = match trusted_state.deref() {
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

        let validators_root = trusted_state.validators().hash_tree_root().unwrap();

        let mut validators = BTreeMap::new();
        for idx in self.validator_indices.take() {
            let validator = ValidatorInfo::from(trusted_state.validators().get(idx).unwrap());
            validators.insert(idx, validator);
        }
        info!(
            "Used validators: {}/{}",
            validators.len(),
            trusted_state.validators().len()
        );

        // Build validator exit epoch patches
        for epoch in self.validator_epochs.take() {
            if epoch != self.trusted_checkpoint.epoch {
                let patch = patch_builder
                    .entry(epoch)
                    .or_insert(self.patch_builder(epoch).unwrap());
                patch.validator_exit_diff(&validators);
            }
        }

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
            .build(trusted_state.validators())
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
            beacon_block: block_multiproof,
            beacon_state: state_multiproof,
            active_validators: validator_multiproof,
            public_keys,
            patches,
        }
    }

    fn patch_builder(
        &self,
        epoch: Epoch,
    ) -> Result<StatePatchBuilder<S::Context>, HostReaderError> {
        let context = StateReader::context(self.inner);
        let state = self
            .inner
            .get_state_at_slot(context.compute_start_slot_at_epoch(epoch))?;

        Ok(StatePatchBuilder::new(state, context))
    }
}

impl<SR> StateReader for PreflightStateReader<'_, SR>
where
    SR: StateReader,
{
    type Error = SR::Error;
    type Context = SR::Context;

    fn context(&self) -> &Self::Context {
        self.inner.context()
    }

    fn genesis_validators_root(&self) -> Result<Root, Self::Error> {
        self.inner.genesis_validators_root()
    }

    fn fork_current_version(&self, epoch: Epoch) -> Result<Version, Self::Error> {
        self.inner.fork_current_version(epoch)
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        assert!(epoch >= self.trusted_checkpoint.epoch);

        let iter = self.inner.active_validators(epoch)?;
        self.validator_epochs.borrow_mut().insert(epoch);

        Ok(iter.inspect(|(idx, _)| {
            self.validator_indices.borrow_mut().insert(*idx);
        }))
    }

    fn randao_mix(&self, epoch: Epoch, idx: RandaoMixIndex) -> Result<Option<B256>, Self::Error> {
        // to be able to prove the inclusion, the randao value must exist
        let randao = self.inner.randao_mix(epoch, idx)?.unwrap();
        self.mix_epochs
            .borrow_mut()
            .entry(epoch)
            .or_default()
            .insert(idx);

        Ok(Some(randao))
    }
}
