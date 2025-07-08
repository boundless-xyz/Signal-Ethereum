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
    AttestationData, Checkpoint, CommitteeCache, Config, ConsensusError, Epoch, Input, Link,
    ShuffleData, StateReader, ValidatorIndex, ValidatorInfo, committee_cache,
    consensus_state::ConsensusState, ensure, get_attesting_indices, get_total_balance,
};
use beacon_types::{
    AggregateSignature, Attestation, ChainSpec, Domain, EthSpec, ForkName, SignedRoot,
};
use itertools::Itertools;
use safe_arith::{ArithError, SafeArith};
use std::collections::{BTreeMap, BTreeSet};
use tracing::{debug, info, trace};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum VerifyError {
    #[error("Invalid attestation: {0}")]
    InvalidAttestation(&'static str),
    #[error("Invalid finalization: {0}")]
    InvalidFinalization(Checkpoint),
    #[error("Invalid state transition")]
    ConsensusError(#[from] ConsensusError),
    #[error("Attesting balance not met: {attesting_balance} < {threshold}")]
    ThresholdNotMet {
        attesting_balance: u64,
        threshold: u64,
    },
    #[error("Committee cache error")]
    CommitteeCacheError(#[from] committee_cache::Error),
    #[error("State reader error: {0}")]
    StateReaderError(String),
    #[error("Missing validator for index: {0}")]
    MissingValidatorInfo(ValidatorIndex),
    #[error("Unsupported fork: {0}")]
    UnsupportedFork(ForkName),
    #[error("{0:?}")]
    LighthouseTypes(beacon_types::Error),
    #[error("Epoch lookahead limit exceeded: {0} > {1}")]
    LookaheadExceedsLimit(Epoch, Epoch),
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
    cfg: &Config,
    state_reader: &S,
    input: Input<S::Spec>,
) -> Result<ConsensusState, VerifyError> {
    let spec = state_reader.chain_spec();
    let trusted_checkpoint = input.consensus_state.finalized_checkpoint();
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
            consensus_state.finalized_checkpoint() == trusted_checkpoint,
            VerifyError::InvalidFinalization(consensus_state.finalized_checkpoint())
        );

        let link = Link {
            source: (*link.0).into(),
            target: (*link.1).into(),
        };
        validate_link(cfg, spec, trusted_checkpoint, &link)?;
        let target_epoch = link.target.epoch();

        info!("Computing committees for epoch {}", target_epoch);

        // compute all committees for the target epoch
        let active_validators: BTreeMap<_, _> = state_reader
            .active_validators(target_epoch)
            .map_err(|e| VerifyError::StateReaderError(e.to_string()))?
            .collect();
        let committees = compute_committees(state_reader, &active_validators, target_epoch)?;

        info!("Processing attestations for {}", link);
        let mut participating_indices = BTreeSet::new();
        for attestation in attestations {
            let attesting_indices =
                process_attestation(state_reader, &active_validators, &committees, attestation)?;
            participating_indices.extend(attesting_indices);
        }

        let unslashed_participating_validators = participating_indices
            .iter()
            .map(|i| active_validators.get(i).unwrap())
            .filter(|v| !v.slashed);
        let target_balance = get_total_balance(spec, unslashed_participating_validators)?;

        let total_active_balance = get_total_balance(spec, active_validators.values())?;
        debug!(
            target_balance,
            total_active_balance, "Attestations processed"
        );

        // the target balance must be sufficient for a new justification
        let lhs = target_balance as u128 * cfg.justification_threshold_quotient as u128;
        let rhs = total_active_balance as u128 * cfg.justification_threshold_factor as u128;
        ensure!(
            lhs >= rhs,
            VerifyError::ThresholdNotMet {
                attesting_balance: target_balance,
                // this is not exactly equivalent, but good enough for an error message
                threshold: (rhs / cfg.justification_threshold_quotient as u128) as u64,
            }
        );
        // just a simple sanity check against catastrophic misconfiguration
        assert!(target_balance.safe_mul(3)? >= total_active_balance.safe_mul(2)?);

        consensus_state = consensus_state.state_transition(&link)?;
        // the new state should always be consistent
        assert!(consensus_state.is_valid());
    }

    // we must process exactly one finalization
    ensure!(
        consensus_state.finalized_checkpoint() != trusted_checkpoint,
        VerifyError::InvalidFinalization(consensus_state.finalized_checkpoint())
    );

    Ok(consensus_state)
}

/// Validates an attestation's link against the internal config.
fn validate_link(
    cfg: &Config,
    spec: &ChainSpec,
    trusted_checkpoint: Checkpoint,
    link: &Link,
) -> Result<(), VerifyError> {
    let target_epoch = link.target.epoch();

    // check that the target fork is supported
    let target_fork_name = spec.fork_name_at_epoch(target_epoch);
    ensure!(
        cfg.is_supported_version(target_fork_name),
        VerifyError::UnsupportedFork(target_fork_name)
    );

    // If the target epoch is less than the trusted checkpoint, this will pass, but it is definitely
    // not a valid state transition.
    let lookahead = target_epoch.saturating_sub(trusted_checkpoint.epoch());
    ensure!(
        lookahead <= cfg.epoch_lookahead_limit,
        VerifyError::LookaheadExceedsLimit(lookahead, cfg.epoch_lookahead_limit)
    );

    Ok(())
}

/// Verifies a single attestation returning its attesting validator indices.
fn process_attestation<S: StateReader, E: EthSpec>(
    state: &S,
    active_validators: &BTreeMap<ValidatorIndex, &ValidatorInfo>,
    committees: &CommitteeCache<E>,
    attestation: &Attestation<E>,
) -> Result<BTreeSet<ValidatorIndex>, VerifyError> {
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

    Ok(attesting_indices)
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
