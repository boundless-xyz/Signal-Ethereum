// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use beacon_types::{ChainSpec, EthSpec};
use ethereum_consensus::electra::{Validator, mainnet::VALIDATOR_REGISTRY_LIMIT};
use ssz_multiproofs::MultiproofBuilder;
use ssz_rs::prelude::*;
use thiserror::Error;

use crate::{HostReaderError, StateProvider};
use alloy_primitives::B256;
use ethereum_consensus::phase0::BeaconBlockHeader;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    ops::Deref,
};
use tracing::{debug, info};
use z_core::{
    Checkpoint, Epoch, RandaoMixIndex, Root, StateInput, StatePatchBuilder, StateReader,
    ValidatorIndex, ValidatorInfo, mainnet::BeaconState, mainnet::ElectraBeaconState,
};

#[derive(Error, Debug)]
pub enum PreflightReaderError {
    #[error("HostReaderError: {0}")]
    HostReaderError(#[from] HostReaderError),
}

pub struct PreflightStateReader<'a, SR> {
    trusted_checkpoint: Checkpoint,
    inner: &'a SR,
    validator_epochs: RefCell<BTreeSet<Epoch>>,
    mix_epochs: RefCell<BTreeMap<Epoch, BTreeSet<RandaoMixIndex>>>,
}

impl<'a, S, E: EthSpec> PreflightStateReader<'a, S>
where
    S: StateReader<Spec = E> + StateProvider<Spec = E>,
{
    pub fn new(reader: &'a S, trusted_checkpoint: Checkpoint) -> Self {
        Self {
            trusted_checkpoint,
            inner: reader,
            validator_epochs: Default::default(),
            mix_epochs: Default::default(),
        }
    }

    pub fn to_input(&self) -> StateInput {
        let trusted_state = self
            .inner
            .state_at_checkpoint(self.trusted_checkpoint)
            .unwrap();
        let beacon_state_root = trusted_state.hash_tree_root().unwrap();

        info!("Building beacon block proof");
        let mut epoch_boundary_block = trusted_state.latest_block_header().clone();
        epoch_boundary_block.state_root = beacon_state_root;
        let block_multiproof = MultiproofBuilder::new()
            .with_path::<BeaconBlockHeader>(&["state_root".into()])
            .build(&epoch_boundary_block)
            .unwrap();
        block_multiproof
            .verify(&self.trusted_checkpoint.root())
            .unwrap();
        info!("Beacon block proof finished");

        info!("Building beacon state proof");
        let state_multiproof = match trusted_state.deref() {
            BeaconState::Electra(state) => MultiproofBuilder::new()
                .with_path::<ElectraBeaconState>(&["genesis_validators_root".into()])
                .with_path::<ElectraBeaconState>(&["slot".into()])
                .with_path::<ElectraBeaconState>(&["fork".into(), "previous_version".into()])
                .with_path::<ElectraBeaconState>(&["fork".into(), "current_version".into()])
                .with_path::<ElectraBeaconState>(&["fork".into(), "epoch".into()])
                .with_path::<ElectraBeaconState>(&["validators".into()])
                .with_path::<ElectraBeaconState>(&["finalized_checkpoint".into(), "epoch".into()])
                .with_path::<ElectraBeaconState>(&["earliest_exit_epoch".into()])
                .with_path::<ElectraBeaconState>(&["earliest_consolidation_epoch".into()])
                .build(state)
                .unwrap(),
            _ => {
                panic!("Unsupported beacon fork. electra only for now")
            }
        };
        state_multiproof.verify(&beacon_state_root).unwrap();
        info!("Beacon state proof finished");

        let validators_root = trusted_state.validators().hash_tree_root().unwrap();
        type Validators = List<Validator, VALIDATOR_REGISTRY_LIMIT>;

        let mut public_keys = Vec::with_capacity(trusted_state.validators().len());

        info!("Building validators proof");
        let mut proof_builder = MultiproofBuilder::new();
        proof_builder = proof_builder.with_path::<Validators>(&[PathElement::Length]);

        for (idx, validator) in trusted_state.validators().iter().enumerate() {
            // if the validator is no longer active only include its exit_epoch field
            if self.trusted_checkpoint.epoch().as_u64() >= validator.exit_epoch {
                proof_builder =
                    proof_builder.with_path::<Validators>(&[idx.into(), "exit_epoch".into()]);
            } else {
                proof_builder = proof_builder
                    .with_path::<Validators>(&[idx.into(), "public_key".into(), 0.into()])
                    .with_path::<Validators>(&[idx.into(), "public_key".into(), 47.into()])
                    .with_path::<Validators>(&[idx.into(), "effective_balance".into()])
                    .with_path::<Validators>(&[idx.into(), "slashed".into()])
                    .with_path::<Validators>(&[idx.into(), "activation_eligibility_epoch".into()])
                    .with_path::<Validators>(&[idx.into(), "activation_epoch".into()])
                    .with_path::<Validators>(&[idx.into(), "exit_epoch".into()]);

                public_keys.push(ValidatorInfo::from(validator).pubkey);
            }
        }
        let validator_multiproof = proof_builder.build(trusted_state.validators()).unwrap();
        validator_multiproof.verify(&validators_root).unwrap();
        info!("Validators proof finished");
        debug!(
            num = public_keys.len(),
            num_total = trusted_state.validators().len(),
            "Included validators",
        );

        info!("Building state patches");
        let mut patch_builder: BTreeMap<Epoch, StatePatchBuilder> = BTreeMap::new();
        for (epoch, indices) in self.mix_epochs.take() {
            let patch = patch_builder
                .entry(epoch)
                .or_insert(self.patch_builder(epoch).unwrap());
            for idx in indices {
                patch.randao_mix(idx);
            }
        }
        for epoch in self.validator_epochs.take() {
            if epoch != self.trusted_checkpoint.epoch() {
                let patch = patch_builder
                    .entry(epoch)
                    .or_insert(self.patch_builder(epoch).unwrap());
                patch.validator_diff(trusted_state.validators().iter());
            }
        }
        let patches = patch_builder
            .into_iter()
            .map(|(k, v)| (k, v.build::<E>()))
            .collect();

        StateInput {
            beacon_block: block_multiproof,
            beacon_state: state_multiproof,
            active_validators: validator_multiproof,
            public_keys,
            patches,
        }
    }

    fn patch_builder(&self, epoch: Epoch) -> Result<StatePatchBuilder, HostReaderError> {
        let state = self
            .inner
            .state_at_slot(epoch.start_slot(E::slots_per_epoch()))?;

        Ok(StatePatchBuilder::new(state))
    }
}

impl<SR> StateReader for PreflightStateReader<'_, SR>
where
    SR: StateReader,
{
    type Error = SR::Error;
    type Spec = SR::Spec;

    fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }

    fn genesis_validators_root(&self) -> Result<Root, Self::Error> {
        self.inner.genesis_validators_root()
    }

    fn fork(&self, epoch: Epoch) -> Result<beacon_types::Fork, Self::Error> {
        self.inner.fork(epoch)
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        assert!(epoch >= self.trusted_checkpoint.epoch());

        let iter = self.inner.active_validators(epoch)?;
        self.validator_epochs.borrow_mut().insert(epoch);

        Ok(iter)
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
