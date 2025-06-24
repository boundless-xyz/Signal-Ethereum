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

use crate::{
    AttestationData, BEACON_ATTESTER_DOMAIN, CommitteeCache, Epoch, Input, ShuffleData,
    StateReader, StateTransitionError, ValidatorIndex, ValidatorInfo,
    consensus_state::ConsensusState, ensure, get_attesting_indices, threshold::threshold,
};

use alloc::collections::BTreeMap;
use beacon_types::{AggregateSignature, EthSpec, SignedRoot};
use tracing::{debug, info};
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum VerifyError {
    #[error("Invalid attestation: {0}")]
    InvalidAttestation(String),
    #[error("State transition error: {0}")]
    StateTransition(#[from] StateTransitionError),
    #[error("Consensus state is inconsistent")]
    InconsistentState,
    #[error(
        "Attesting balance not met: {attesting_balance} < {threshold} (lookahead: {lookahead})"
    )]
    ThresholdNotMet {
        lookahead: u64,
        attesting_balance: u64,
        threshold: u64,
    },
    #[error("Committee cache error: {0:?}")]
    CommitteeCacheError(#[from] crate::committee_cache::Error),
    #[error("State reader error: {0}")]
    StateReaderError(String),
    #[error("Missing validator info for index: {0}")]
    MissingValidatorInfo(ValidatorIndex),

    #[error("Lighthouse types: {0:?}")]
    LighthouseTypes(beacon_types::Error),
    #[error("Verify error: {0}")]
    Other(String),
}

impl From<beacon_types::Error> for VerifyError {
    fn from(e: beacon_types::Error) -> Self {
        VerifyError::LighthouseTypes(e)
    }
}

pub fn verify<S: StateReader>(
    state_reader: &S,
    input: Input<S::Spec>,
) -> Result<ConsensusState, VerifyError> {
    let Input {
        mut state,
        links: link,
        attestations,
    } = input;
    ensure!(
        link.len() == attestations.len(),
        VerifyError::Other("Link and attestations must be the same length".to_string())
    );

    let trusted_checkpoint = state.finalized_checkpoint;

    let mut validator_cache: BTreeMap<Epoch, BTreeMap<ValidatorIndex, &ValidatorInfo>> =
        BTreeMap::new();

    let mut committee_caches: BTreeMap<Epoch, CommitteeCache> = BTreeMap::new();
    for (link, attestations) in link.iter().zip(attestations.into_iter()) {
        let attesting_balance: u64 = attestations
            .into_iter()
            .filter(|a| {
                a.data().source == link.source.into() && a.data().target == link.target.into()
            })
            .map(|attestation| {
                let data = &attestation.data();
                debug!("Processing attestation: {:?}", data);

                assert_eq!(data.index, 0);

                let attestation_epoch = data.target.epoch;

                let committee_cache =
                    committee_caches
                        .entry(attestation_epoch)
                        .or_insert_with(|| {
                            get_shufflings_for_epoch(state_reader, attestation_epoch).unwrap()
                        });

                let attesting_indices = get_attesting_indices(&attestation, committee_cache)?;

                let state_validators =
                    validator_cache.entry(attestation_epoch).or_insert_with(|| {
                        state_reader
                            .active_validators(attestation_epoch)
                            .map_err(|e| VerifyError::StateReaderError(e.to_string()))
                            .unwrap()
                            .collect()
                    });

                let attesting_validators = attesting_indices
                    .iter()
                    .map(|i| {
                        state_validators
                            .get(i)
                            .ok_or(VerifyError::MissingValidatorInfo(*i))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let attesting_balance = attesting_validators
                    .iter()
                    .fold(0u64, |acc, e| acc + e.effective_balance);

                ensure!(
                    is_valid_indexed_attestation(
                        state_reader,
                        attesting_validators.into_iter(),
                        data,
                        attestation.signature(),
                    )?,
                    VerifyError::InvalidAttestation("Invalid indexed attestation".to_string(),)
                );

                Ok(attesting_balance)
            })
            .sum::<Result<u64, VerifyError>>()?;

        let total_active_balance = state_reader
            .get_total_active_balance(link.target.epoch())
            .map_err(|e| VerifyError::StateReaderError(e.to_string()))?;

        // In the worst case attestations can arrive one epoch after their target and because we don't have information about which epoch they belong to in the chain
        // (if any) we need to assume the worst case
        // TODO: Fix
        let lookahead = link.target.epoch() + 1 - trusted_checkpoint.epoch();
        let threshold = threshold(lookahead.as_u64(), total_active_balance);

        ensure!(
            attesting_balance >= threshold,
            VerifyError::ThresholdNotMet {
                lookahead: lookahead.as_u64(),
                attesting_balance,
                threshold,
            }
        );

        state = state.state_transition(link)?;
        ensure!(state.is_consistent(), VerifyError::InconsistentState);

        debug!("state: {:?}", state)
    }

    Ok(state)
}

fn is_valid_indexed_attestation<'a, S: StateReader>(
    state_reader: &S,
    attesting_validators: impl IntoIterator<Item = &'a &'a ValidatorInfo>,
    data: &AttestationData,
    signature: &AggregateSignature,
) -> Result<bool, VerifyError> {
    let pubkeys = attesting_validators
        .into_iter()
        .map(|validator| &validator.pubkey)
        .collect::<Vec<_>>();
    if pubkeys.is_empty() {
        return Ok(false);
    }
    let domain = state_reader.chain_spec().get_domain(
        data.target.epoch,
        beacon_types::Domain::BeaconAttester,
        &state_reader
            .fork(data.target.epoch)
            .map_err(|e| VerifyError::StateReaderError(e.to_string()))?,
        state_reader
            .genesis_validators_root()
            .map_err(|e| VerifyError::StateReaderError(e.to_string()))?,
    );
    let signing_root = data.signing_root(domain);

    Ok(signature.eth_fast_aggregate_verify(signing_root, &pubkeys))
}

// this can compute validators for up to
// 1 epoch ahead of the epoch the state_reader can read from
pub fn get_shufflings_for_epoch<S: StateReader>(
    state_reader: &S,
    epoch: Epoch,
) -> Result<CommitteeCache, VerifyError> {
    info!("Getting shufflings for epoch: {}", epoch);

    let indices = state_reader
        .get_active_validator_indices(epoch)
        .map_err(|e| VerifyError::StateReaderError(e.to_string()))?
        .collect();
    let seed = state_reader
        .get_seed(epoch, BEACON_ATTESTER_DOMAIN.into())
        .map_err(|e| VerifyError::StateReaderError(e.to_string()))?;

    let committees_per_slot = S::Spec::get_committee_count_per_slot(
        state_reader
            .get_active_validator_indices(epoch)
            .map_err(|e| VerifyError::StateReaderError(e.to_string()))?
            .count(),
        state_reader.chain_spec(),
    )? as u64;

    crate::committee_cache::initialized::<S::Spec>(
        state_reader.chain_spec(),
        ShuffleData {
            seed,
            indices,
            committees_per_slot,
        },
        epoch,
    )
    .map_err(Into::into)
}
