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

use crate::conversions::TryAsBeaconType;
use beacon_types::EthSpec;
use ethereum_consensus::{electra::mainnet::SignedBeaconBlockHeader, types::mainnet::BeaconBlock};
use std::collections::HashMap;
use std::fmt::Display;
use tracing::debug;
use z_core::{Attestation, Checkpoint, ConsensusError, ConsensusState, Epoch, Input, Link, ensure};

/// A trait to abstract reading data from an instance of a beacon chain
/// This could be an RPC to a node or something else (e.g. test harness)
pub trait ChainReader {
    #[allow(async_fn_in_trait)]
    async fn get_block_header(
        &self,
        block_id: impl Display,
    ) -> Result<Option<SignedBeaconBlockHeader>, anyhow::Error>;

    #[allow(async_fn_in_trait)]
    async fn get_block(&self, block_id: impl Display)
    -> Result<Option<BeaconBlock>, anyhow::Error>;

    #[allow(async_fn_in_trait)]
    async fn get_consensus_state(
        &self,
        state_id: impl Display,
    ) -> Result<ConsensusState, anyhow::Error>;
}

#[derive(thiserror::Error, Debug)]
pub enum InputBuilderError {
    #[error("Unsupported block version")]
    UnsupportedBlockVersion,
    #[error("Trusted checkpoint is not valid")]
    InvalidTrustedCheckpoint,
    #[error("Consensus error")]
    ConsensusError(#[from] ConsensusError),
    #[error("Chain reader error")]
    ChainReader(#[from] anyhow::Error),
}

pub struct InputBuilder<E, CR> {
    chain_reader: CR,
    _phantom: std::marker::PhantomData<E>,
}

impl<E: EthSpec, CR: ChainReader> InputBuilder<E, CR> {
    pub fn new(chain_reader: CR) -> Self {
        Self {
            chain_reader,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Given the current Checkpoint, query a beacon node to build an input that can be
    /// used to evolve the consensus state at this checkpoint to a new consensus state in the "best" way possible
    pub async fn build(
        &self,
        trusted_checkpoint: Checkpoint,
    ) -> Result<(Input<E>, ConsensusState), InputBuilderError> {
        // Find the first consensus state that confirms the finality of the trusted_checkpoint
        let finalization_epoch = self.find_finalization_epoch(trusted_checkpoint).await?;
        debug!(
            epoch = finalization_epoch.as_u64(),
            "Found state confirming trusted checkpoint"
        );

        let (state, next_state, links) = self
            .get_justifications_until_new_finality(finalization_epoch)
            .await?;
        assert_eq!(state.finalized_checkpoint(), trusted_checkpoint);
        debug!(
            num_justifications = links.len(),
            "Collected justifications until new finality"
        );

        // Concurrently fetch attestations for all required links.
        let attestations = self.collect_attestations_for_links(&links).await?;

        Ok((
            Input {
                consensus_state: state,
                attestations,
            },
            next_state,
        ))
    }

    async fn find_finalization_epoch(
        &self,
        trusted_checkpoint: Checkpoint,
    ) -> Result<Epoch, InputBuilderError> {
        /*
        // Sanity check: the node's head must recognize the trusted checkpoint as finalized.
        let head_state = self.chain_reader.get_consensus_state("head").await?;
        ensure!(
            head_state.finalized.epoch >= trusted_checkpoint.epoch,
            InputBuilderError::InvalidTrustedCheckpoint
        );
        */

        for epoch in trusted_checkpoint.epoch().as_u64() + 1.. {
            let slot = Epoch::from(epoch).start_slot(E::slots_per_epoch());
            let state = self.chain_reader.get_consensus_state(slot).await?;
            if state.finalized_checkpoint() == trusted_checkpoint {
                return Ok(epoch.into());
            }

            // if the trusted checkpoint has been skipped, it is invalid
            ensure!(
                state.finalized_checkpoint().epoch() < trusted_checkpoint.epoch(),
                InputBuilderError::InvalidTrustedCheckpoint
            );
        }

        unreachable!()
    }

    /// Starting from a given state, find all subsequent consensus_states that form a chain to the next finalized checkpoint.
    async fn get_justifications_until_new_finality(
        &self,
        start_epoch: Epoch,
    ) -> Result<(ConsensusState, ConsensusState, Vec<Link>), InputBuilderError> {
        let initial_state = self
            .chain_reader
            .get_consensus_state(start_epoch.start_slot(E::slots_per_epoch()))
            .await?;
        let initial_finalized_checkpoint = initial_state.finalized_checkpoint();

        let mut links = Vec::new();

        let mut prev_state = initial_state.clone();
        for epoch in (start_epoch.as_u64() + 1).. {
            let current_state = self
                .chain_reader
                .get_consensus_state(Epoch::from(epoch).start_slot(E::slots_per_epoch()))
                .await?;

            // add potential justification
            if let Some(link) = prev_state.transition_link(&current_state)? {
                links.push(link);
            }

            // If finality has advanced, we have collected all necessary states.
            if current_state.finalized_checkpoint() != initial_finalized_checkpoint {
                return Ok((initial_state, current_state, links));
            }

            prev_state = current_state;
        }

        unreachable!()
    }

    /// Gathers the attestations for links, looking at block in the range [start_slot, end_slot].
    async fn collect_attestations_for_links(
        &self,
        links: &[Link],
    ) -> Result<Vec<Attestation<E>>, InputBuilderError> {
        if links.is_empty() {
            return Ok(vec![]);
        }

        // safe unwrap: links cannot be empty
        let min_epoch = links.iter().map(|l| l.target.epoch()).min().unwrap();
        let max_epoch = links.iter().map(|l| l.target.epoch()).max().unwrap();

        // The attestation must be no newer than MIN_ATTESTATION_INCLUSION_DELAY slots.
        // It is safe to ignore this and assume MIN_ATTESTATION_INCLUSION_DELAY = 0
        let start_slot = min_epoch * E::slots_per_epoch();
        // The attestation must be no older than SLOTS_PER_EPOCH slots.
        let end_slot = (max_epoch + 1) * E::slots_per_epoch();

        // 1. Fetch all blocks concurrently
        let block_futs =
            (start_slot.as_u64()..=end_slot.as_u64()).map(|slot| self.chain_reader.get_block(slot));
        let blocks = futures::future::try_join_all(block_futs).await?;

        // 2. Group attestations by link in a HashMap for efficient lookup
        let mut attestations_by_link = HashMap::<Link, Vec<Attestation<E>>>::new();
        for block in blocks.into_iter().flatten() {
            let body = match block.body() {
                ethereum_consensus::types::BeaconBlockBodyRef::Electra(body) => body,
                _ => return Err(InputBuilderError::UnsupportedBlockVersion),
            };
            for attestation in body.attestations.iter() {
                let attestation = attestation.try_as_beacon_type()?;
                let link = Link {
                    source: attestation.data().source.into(),
                    target: attestation.data().target.into(),
                };
                attestations_by_link
                    .entry(link)
                    .or_default()
                    .push(attestation);
            }
        }

        // 3. Assemble the final nested Vec in the correct order
        let result = links
            .iter()
            .flat_map(|link| attestations_by_link.remove(link).unwrap_or_default())
            .collect();

        Ok(result)
    }
}
