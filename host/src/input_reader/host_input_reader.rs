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
use crate::{
    BeaconClient, CacheStateProvider, ChainReader, FileProvider, StateProvider, StateProviderError,
    StateRef,
};
use alloy_primitives::B256;
use beacon_types::{ChainSpec, EthSpec, Fork};
use elsa::FrozenMap;
use ethereum_consensus::phase0::Validator;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use safe_arith::ArithError;
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, trace};
use z_core::{
    Attestation, Checkpoint, ConsensusError, ConsensusState, Epoch, InputReader, Link,
    RandaoMixIndex, Root, Slot, ValidatorIndex, ValidatorInfo, ensure,
};

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
    #[error("Block missing")]
    BlockMissing,
    #[error("Not in cache")]
    NotInCache,
    #[error(transparent)]
    StateProviderError(#[from] StateProviderError),
    #[error("Arithmetic error: {0:?}")]
    ArithError(ArithError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error("Unsupported block version")]
    UnsupportedBlockVersion,
    #[error("Trusted checkpoint is not valid")]
    InvalidTrustedCheckpoint,
    #[error("Consensus error")]
    ConsensusError(#[from] ConsensusError),
    #[error("Unable to retrieve finalized block with root: {0}")]
    UnableToRetrieveFinalizedBlock(Root),
}

impl From<ArithError> for HostReaderError {
    fn from(e: ArithError) -> Self {
        HostReaderError::ArithError(e)
    }
}

pub struct HostInputReader<E: EthSpec, P, CR> {
    spec: ChainSpec,
    provider: P,
    chain_reader: CR,
    validator_cache: FrozenMap<Epoch, Vec<(ValidatorIndex, ValidatorInfo)>>,
    consensus_state: ConsensusState,
    attestation_cache: Vec<Attestation<E>>,
    _phantom: std::marker::PhantomData<E>,
}

impl<E: EthSpec, P: StateProvider, CR: ChainReader> HostInputReader<E, P, CR> {
    #[must_use]
    pub async fn new(
        spec: ChainSpec,
        provider: P,
        chain_reader: CR,
        trusted_checkpoint: Checkpoint,
    ) -> Result<Self, HostReaderError> {
        // Find the first consensus state that confirms the finality of the trusted_checkpoint
        let finalization_epoch =
            find_finalization_epoch::<E, _>(&chain_reader, trusted_checkpoint).await?;
        debug!(
            epoch = finalization_epoch.as_u64(),
            "Found state confirming trusted checkpoint"
        );

        let (state, _next_state, links) =
            get_justifications_until_new_finality::<E, _>(&chain_reader, finalization_epoch)
                .await?;
        assert_eq!(state.finalized_checkpoint(), trusted_checkpoint);
        debug!(
            num_justifications = links.len(),
            "Collected justifications until new finality"
        );

        // Concurrently fetch attestations for all required links.
        let attestations = collect_attestations_for_links(&chain_reader, &links).await?;

        Ok(Self {
            spec,
            provider,
            chain_reader,
            validator_cache: Default::default(),

            consensus_state: state,
            attestation_cache: attestations,

            _phantom: std::marker::PhantomData,
        })
    }

    #[inline]
    pub fn provider(&self) -> &P {
        &self.provider
    }

    fn state(&self, epoch: Epoch) -> Result<StateRef, StateProviderError> {
        self.provider.state_at_epoch(epoch)
    }
}

impl<E: EthSpec> HostInputReader<E, CacheStateProvider<FileProvider<E>>, BeaconClient> {
    pub async fn new_with_dir(
        spec: ChainSpec,
        dir: impl Into<PathBuf>,
        beacon_client: BeaconClient,
        trusted_checkpoint: Checkpoint,
    ) -> Result<Self, HostReaderError> {
        let provider = CacheStateProvider::new(FileProvider::new(dir)?);
        Self::new(spec, provider, beacon_client, trusted_checkpoint).await
    }
}

impl<E: EthSpec, P: StateProvider, CR> StateProvider for HostInputReader<E, P, CR> {
    type Spec = P::Spec;

    fn state_at_slot(&self, slot: Slot) -> Result<StateRef, StateProviderError> {
        self.provider.state_at_slot(slot)
    }
}

impl<E: EthSpec, P: StateProvider, CR: ChainReader> InputReader for HostInputReader<E, P, CR> {
    type Error = HostReaderError;
    type Spec = E;

    fn chain_spec(&self) -> &ChainSpec {
        &self.spec
    }

    fn genesis_validators_root(&self) -> Result<Root, HostReaderError> {
        Ok(self.provider.genesis_validators_root()?)
    }

    fn fork(&self, epoch: Epoch) -> Result<Fork, HostReaderError> {
        let state = self.provider.state_at_epoch(epoch)?;
        Ok(Fork {
            previous_version: state.fork().previous_version,
            current_version: state.fork().current_version,
            epoch: state.fork().epoch.into(),
        })
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        trace!("HostInputReader::active_validators({epoch})");

        let iter = match self.validator_cache.get(&epoch) {
            Some(validators) => validators.iter(),
            None => {
                let beacon_state = self.state(epoch)?;

                debug!("Caching validators for epoch {epoch}");
                let validators: Vec<(ValidatorIndex, ValidatorInfo)> = beacon_state
                    .validators()
                    .par_iter()
                    .enumerate()
                    .filter(|(_, validator)| is_active_validator(validator, epoch.as_u64()))
                    .map(|(idx, validator)| validator.try_as_beacon_type().map(|info| (idx, info)))
                    .collect::<Result<_, _>>()?;
                debug!("Active validators: {}", validators.len());

                self.validator_cache.insert(epoch, validators).iter()
            }
        };

        Ok(iter.map(|(idx, validator)| (*idx, validator)))
    }

    fn randao_mix(&self, epoch: Epoch, idx: RandaoMixIndex) -> Result<Option<B256>, Self::Error> {
        trace!("HostInputReader::randao_mix({epoch},{idx})");
        let beacon_state = self.state(epoch)?;

        Ok(beacon_state
            .randao_mixes()
            .get(idx as usize)
            .map(|randao| B256::from_slice(randao.as_slice())))
    }

    fn attestations(&self) -> Result<impl Iterator<Item = &z_core::Attestation<E>>, Self::Error> {
        Ok(self.attestation_cache.iter())
    }

    fn consensus_state(&self) -> Result<z_core::ConsensusState, Self::Error> {
        Ok(self.consensus_state.clone())
    }

    fn slot_for_block(&self, block_root: &Root) -> Result<u64, Self::Error> {
        let block_header =
            futures::executor::block_on(self.chain_reader.get_block_header(*block_root))?
                .ok_or(HostReaderError::BlockMissing)?;
        Ok(block_header.message.slot)
    }
}

/// Check if `validator` is active.
fn is_active_validator(validator: &Validator, epoch: u64) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch
}

async fn find_finalization_epoch<E: EthSpec, CR: ChainReader>(
    chain_reader: &CR,
    trusted_checkpoint: Checkpoint,
) -> Result<Epoch, HostReaderError> {
    for epoch in trusted_checkpoint.epoch().as_u64() + 1.. {
        let slot = Epoch::from(epoch).start_slot(E::slots_per_epoch());
        let state = chain_reader.get_consensus_state(slot).await?;
        if state.finalized_checkpoint() == trusted_checkpoint {
            return Ok(epoch.into());
        }

        // if the trusted checkpoint has been skipped, it is invalid
        ensure!(
            state.finalized_checkpoint().epoch() < trusted_checkpoint.epoch(),
            HostReaderError::InvalidTrustedCheckpoint
        );
    }

    unreachable!()
}

/// Starting from a given state, find all subsequent consensus_states that form a chain to the next finalized checkpoint.
async fn get_justifications_until_new_finality<E: EthSpec, CR: ChainReader>(
    chain_reader: &CR,
    start_epoch: Epoch,
) -> Result<(ConsensusState, ConsensusState, Vec<Link>), HostReaderError> {
    let initial_state = chain_reader
        .get_consensus_state(start_epoch.start_slot(E::slots_per_epoch()))
        .await?;
    let initial_finalized_checkpoint = initial_state.finalized_checkpoint();

    let mut links = Vec::new();

    let mut prev_state = initial_state.clone();
    for epoch in (start_epoch.as_u64() + 1).. {
        let current_state = chain_reader
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
async fn collect_attestations_for_links<E: EthSpec, CR: ChainReader>(
    chain_reader: &CR,
    links: &[Link],
) -> Result<Vec<Attestation<E>>, HostReaderError> {
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
        (start_slot.as_u64()..=end_slot.as_u64()).map(|slot| chain_reader.get_block(slot));
    let blocks = futures::future::try_join_all(block_futs).await?;

    // 2. Group attestations by link in a HashMap for efficient lookup
    let mut attestations_by_link = HashMap::<Link, Vec<Attestation<E>>>::new();
    for block in blocks.into_iter().flatten() {
        let body = match block.body() {
            ethereum_consensus::types::BeaconBlockBodyRef::Electra(body) => body,
            _ => return Err(HostReaderError::UnsupportedBlockVersion),
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
