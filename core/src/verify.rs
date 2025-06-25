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
    AttestationData, Checkpoint, CommitteeCache, Epoch, Input, Link, ShuffleData, StateReader,
    StateTransitionError, ValidatorIndex, ValidatorInfo, committee_cache,
    consensus_state::ConsensusState, ensure, get_attesting_indices, get_total_balance,
    threshold::threshold,
};
use beacon_types::{AggregateSignature, Attestation, Domain, EthSpec, SignedRoot};
use itertools::Itertools;
use safe_arith::{ArithError, SafeArith};
use std::collections::BTreeMap;
use tracing::{debug, info, trace};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum VerifyError {
    #[error("Invalid attestation: {0}")]
    InvalidAttestation(&'static str),
    #[error("Invalid finalization: {0}")]
    InvalidFinalization(Checkpoint),
    #[error("Invalid state transition")]
    StateTransition(#[from] StateTransitionError),
    #[error(
        "Attesting balance not met: {attesting_balance} < {threshold} (lookahead: {lookahead})"
    )]
    ThresholdNotMet {
        lookahead: u64,
        attesting_balance: u64,
        threshold: u64,
    },
    #[error("Committee cache error")]
    CommitteeCacheError(#[from] committee_cache::Error),
    #[error("State reader error: {0}")]
    StateReaderError(String),
    #[error("Missing validator for index: {0}")]
    MissingValidatorInfo(ValidatorIndex),
    #[error("{0:?}")]
    LighthouseTypes(beacon_types::Error),
    #[error("Arithmetic error: {0:?}")]
    ArithError(ArithError),
}

impl From<ArithError> for VerifyError {
    fn from(e: ArithError) -> Self {
        VerifyError::ArithError(e)
    }
}

/// Verifies a batch of attestations to advance the consensus state.
///
/// This function processes the given attestations. For each corresponding superiority link it
/// updates the consensus state until a new finalization is reached.
///
/// # Preconditions
///
/// The `input.attestations` are expected to be sorted by `(attestation.data.source, attestation.data.target)`.
pub fn verify<S: StateReader>(
    state_reader: &S,
    input: Input<S::Spec>,
) -> Result<ConsensusState, VerifyError> {
    let trusted_checkpoint = input.consensus_state.finalized_checkpoint;
    let Input {
        mut consensus_state,
        attestations,
    } = input;

    // group attestations by their corresponding link
    for (link, attestations) in &attestations
        .iter()
        .chunk_by(|a| (&a.data().source, &a.data().target))
    {
        // we must not process more than one new finalization
        ensure!(
            consensus_state.finalized_checkpoint == trusted_checkpoint,
            VerifyError::InvalidFinalization(consensus_state.finalized_checkpoint)
        );

        let link = Link {
            source: (*link.0).into(),
            target: (*link.1).into(),
        };
        info!("Processing attestations for {}", link);

        // compute all committees for the target epoch
        let active_validators: BTreeMap<_, _> = state_reader
            .active_validators(link.target.epoch())
            .map_err(|e| VerifyError::StateReaderError(e.to_string()))?
            .collect();
        let committees = compute_committees(state_reader, &active_validators, link.target.epoch())?;

        let mut attesting_balance = 0u64;
        for attestation in attestations {
            let balance =
                process_attestation(state_reader, &active_validators, &committees, attestation)?;
            attesting_balance.safe_add_assign(balance)?;
        }

        let total_active_balance =
            get_total_balance(state_reader.chain_spec(), active_validators.values())?;
        debug!(
            attesting_balance,
            total_active_balance, "Attestations processed"
        );

        // In the worst case attestations can arrive one epoch after their target and because we don't have information about which epoch they belong to in the chain
        // (if any) we need to assume the worst case
        // TODO: Fix
        let lookahead = link.target.epoch() + 1 - consensus_state.finalized_checkpoint.epoch();
        let threshold = threshold(lookahead.as_u64(), total_active_balance);

        ensure!(
            attesting_balance >= threshold,
            VerifyError::ThresholdNotMet {
                lookahead: lookahead.as_u64(),
                attesting_balance,
                threshold,
            }
        );

        consensus_state = consensus_state.state_transition(&link)?;
        // the new state should always be consistent
        assert!(consensus_state.is_consistent());
    }

    // we must process exactly one finalization
    ensure!(
        consensus_state.finalized_checkpoint != trusted_checkpoint,
        VerifyError::InvalidFinalization(consensus_state.finalized_checkpoint)
    );

    Ok(consensus_state)
}

fn process_attestation<S: StateReader, E: EthSpec>(
    state: &S,
    active_validators: &BTreeMap<ValidatorIndex, &ValidatorInfo>,
    committees: &CommitteeCache<E>,
    attestation: &Attestation<E>,
) -> Result<u64, VerifyError> {
    let attesting_indices = get_attesting_indices(attestation, committees)?;
    let attesting_validators = attesting_indices
        .iter()
        .map(|i| {
            active_validators
                .get(i)
                .copied()
                .ok_or(VerifyError::MissingValidatorInfo(*i))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // verify signature
    ensure!(
        is_valid_indexed_attestation(
            state,
            &attesting_validators,
            attestation.data(),
            attestation.signature(),
        )?,
        VerifyError::InvalidAttestation("Invalid signature")
    );

    // sum up the effective balance of all validators who have not been slashed
    let target_balance = get_total_balance(
        state.chain_spec(),
        attesting_validators.iter().filter(|v| !v.slashed),
    )?;

    Ok(target_balance)
}

/// Checks if given indexed attestation is not empty and has a valid aggregate signature.
fn is_valid_indexed_attestation<S: StateReader>(
    state_reader: &S,
    attesting_validators: &[&ValidatorInfo],
    data: &AttestationData,
    signature: &AggregateSignature,
) -> Result<bool, VerifyError> {
    if attesting_validators.is_empty() {
        return Err(VerifyError::InvalidAttestation("Empty attestation"));
    }

    let pubkeys = attesting_validators
        .iter()
        .map(|validator| &validator.pubkey)
        .collect::<Vec<_>>();

    let domain = state_reader.chain_spec().get_domain(
        data.target.epoch,
        Domain::BeaconAttester,
        &state_reader
            .fork(data.target.epoch)
            .map_err(|e| VerifyError::StateReaderError(e.to_string()))?,
        state_reader
            .genesis_validators_root()
            .map_err(|e| VerifyError::StateReaderError(e.to_string()))?,
    );
    let signing_root = data.signing_root(domain);
    trace!(
        num_pubkeys = pubkeys.len(),
        "Verifying attestation signature"
    );

    Ok(signature.eth_fast_aggregate_verify(signing_root, &pubkeys))
}

/// Return all the committees for the given epoch.
fn compute_committees<S: StateReader>(
    state_reader: &S,
    active_validators: &BTreeMap<ValidatorIndex, &ValidatorInfo>,
    epoch: Epoch,
) -> Result<CommitteeCache<S::Spec>, VerifyError> {
    let spec = state_reader.chain_spec();

    let domain = spec.get_domain_constant(Domain::BeaconAttester);
    let seed = state_reader
        .get_seed(epoch, domain.to_le_bytes().into())
        .map_err(|e| VerifyError::StateReaderError(e.to_string()))?;
    let indices: Vec<_> = active_validators.keys().copied().collect();
    let committees_per_slot = S::Spec::get_committee_count_per_slot(indices.len(), spec)
        .map_err(VerifyError::LighthouseTypes)?;

    let committee_cache = CommitteeCache::initialized(
        spec,
        ShuffleData {
            seed,
            indices,
            committees_per_slot,
        },
        epoch,
    )?;

    Ok(committee_cache)
}
