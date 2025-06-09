use std::collections::BTreeSet;

use crate::{
    AttestationData, BEACON_ATTESTER_DOMAIN, BlsError, CommitteeCache, Domain, Epoch, Input,
    PublicKey, Root, ShuffleData, Signature, StateReader, StateTransitionError, ValidatorIndex,
    ValidatorInfo, Version, consensus_state::ConsensusState, fast_aggregate_verify_pre_aggregated,
    threshold::threshold,
};
use alloc::collections::BTreeMap;
use tracing::{debug, info};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[derive(thiserror::Error, Debug)]
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
    #[error("Bls error: {0}")]
    BlsError(BlsError),
    #[error("Bitfield error: {0:?}")]
    BitfieldError(ssz::BitfieldError),
    #[error("State reader error: {0}")]
    StateReaderError(String),
    #[error("Verify error: {0}")]
    Other(String),
}

impl From<ssz::BitfieldError> for VerifyError {
    fn from(e: ssz::BitfieldError) -> Self {
        VerifyError::BitfieldError(e)
    }
}
impl From<BlsError> for VerifyError {
    fn from(e: BlsError) -> Self {
        VerifyError::BlsError(e)
    }
}

pub fn verify<S: StateReader>(
    state_reader: &S,
    input: Input,
) -> Result<ConsensusState, VerifyError> {
    let Input {
        consensus_state,
        link,
        attestations,
        ..
    } = input;
    if link.len() != attestations.len() {
        return Err(VerifyError::Other(
            "Link and attestations must be the same length".to_string(),
        ));
    }
    // TODO(ec2): I think we need to enforce here that the trusted state is less than or equal to state.finalized_checkpoint epoch
    // TODO(ec2): We can also bound the number of state patches to the k in k-finality case
    let context = state_reader.context();

    let trusted_epoch = consensus_state.finalized_checkpoint.epoch;

    // 1. Attestation processing
    let mut validator_cache: BTreeMap<Epoch, BTreeMap<ValidatorIndex, &ValidatorInfo>> =
        BTreeMap::new();

    let mut committee_caches: BTreeMap<Epoch, CommitteeCache> = BTreeMap::new();
    for (link, attestations) in link.iter().zip(attestations.into_iter()) {
        let attesting_balance: u64 = attestations
            .into_iter()
            .filter(|a| a.data.source == link.source && a.data.target == link.target)
            .map(|attestation| {
                let data = &attestation.data;
                debug!("Processing attestation: {:?}", data);

                assert_eq!(data.index, 0);

                let attestation_epoch = data.target.epoch;

                let committee_cache =
                    committee_caches
                        .entry(attestation_epoch)
                        .or_insert_with(|| {
                            get_shufflings_for_epoch(
                                state_reader,
                                attestation_epoch,
                                attestation_epoch,
                            )
                            .unwrap()
                        });

                let attesting_indices =
                    attestation.get_attesting_indices(context, committee_cache)?;

                let state_validators =
                    validator_cache.entry(attestation_epoch).or_insert_with(|| {
                        state_reader
                            .active_validators(attestation_epoch, attestation_epoch)
                            .map_err(|e| VerifyError::StateReaderError(e.to_string()))
                            .unwrap()
                            .collect()
                    });

                let attesting_validators = attesting_indices
                    .iter()
                    .map(|i| *state_validators.get(i).expect("Missing validator info"))
                    .collect::<Vec<_>>();

                if !is_valid_indexed_attestation(
                    state_reader,
                    attesting_validators.iter().copied(),
                    &data,
                    attestation.signature,
                )? {
                    return Err(VerifyError::InvalidAttestation(
                        "Invalid indexed attestation".to_string(),
                    ));
                }

                Ok(attesting_validators
                    .iter()
                    .fold(0u64, |acc, e| acc + e.effective_balance))
            })
            .sum::<Result<u64, VerifyError>>()?;

        let total_active_balance = state_reader
            .get_total_active_balance(link.target.epoch)
            .map_err(|e| VerifyError::StateReaderError(e.to_string()))?;

        // In the worst case attestations can arrive one epoch after their target and because we don't have information about which epoch they belong to in the chain
        // (if any) we need to assume the worst case
        let lookahead = link.target.epoch + 1 - trusted_epoch;
        let threshold = threshold(lookahead, total_active_balance);

        if attesting_balance < threshold {
            return Err(VerifyError::ThresholdNotMet {
                lookahead,
                attesting_balance,
                threshold,
            });
        }
    }

    /////////// 2. State update calculation  //////////////
    info!("2. State update calculation start");
    if !consensus_state.is_consistent() {
        return Err(VerifyError::InconsistentState);
    }

    let mut state = consensus_state;

    for link in link.iter() {
        state = state.state_transition(link)?;
    }
    Ok(state)
}

fn is_valid_indexed_attestation<'a, S: StateReader>(
    state_reader: &S,
    attesting_validators: impl IntoIterator<Item = &'a ValidatorInfo>,
    data: &AttestationData,
    signature: Signature,
) -> Result<bool, VerifyError> {
    let pubkeys = attesting_validators
        .into_iter()
        .map(|validator| &validator.pubkey)
        .collect::<Vec<_>>();
    if pubkeys.is_empty() {
        return Ok(false);
    }
    let domain = beacon_attester_signing_domain(state_reader, data.target.epoch)?;
    let signing_root = compute_signing_root(data, domain);

    let agg_pk = PublicKey::aggregate(&pubkeys)?;

    fast_aggregate_verify_pre_aggregated(&agg_pk, signing_root.as_ref(), &signature)
        .map(|_| true)
        .map_err(|e| VerifyError::BlsError(e))
}

// this can compute validators for up to
// 1 epoch ahead of the epoch the state_reader can read from
pub fn get_shufflings_for_epoch<S: StateReader>(
    state_reader: &S,
    state: Epoch,
    epoch: Epoch,
) -> Result<CommitteeCache, VerifyError> {
    info!("Getting shufflings for epoch: {}", state);

    let indices = state_reader
        .get_active_validator_indices(state, epoch)
        .map_err(|e| VerifyError::StateReaderError(e.to_string()))?
        .collect();
    let seed = state_reader
        .get_seed(state, epoch, BEACON_ATTESTER_DOMAIN.into())
        .map_err(|e| VerifyError::StateReaderError(e.to_string()))?;

    let committees_per_slot = state_reader
        .get_committee_count_per_slot(state, epoch)
        .map_err(|e| VerifyError::StateReaderError(e.to_string()))?;

    CommitteeCache::initialized(
        ShuffleData {
            seed,
            indices,
            committees_per_slot,
        },
        state,
        state_reader.context(),
    )
    .map_err(Into::into)
}

fn beacon_attester_signing_domain<S: StateReader>(
    state_reader: &S,
    epoch: Epoch,
) -> Result<[u8; 32], VerifyError> {
    let domain_type = BEACON_ATTESTER_DOMAIN;
    let fork_data_root =
        fork_data_root(state_reader, state_reader.genesis_validators_root(), epoch)?;
    let mut domain = [0_u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_data_root.as_slice()[..28]);
    Ok(domain)
}

fn compute_signing_root<T: TreeHash>(ssz_object: &T, domain: Domain) -> Root {
    let object_root = ssz_object.tree_hash_root();

    #[derive(TreeHash)]
    pub struct SigningData {
        pub object_root: Root,
        pub domain: Domain,
    }

    let s = SigningData {
        object_root,
        domain,
    };
    s.tree_hash_root()
}

fn fork_data_root<S: StateReader>(
    state_reader: &S,
    genesis_validators_root: Root,
    epoch: Epoch,
) -> Result<Root, VerifyError> {
    #[derive(TreeHash)]
    struct ForkData {
        pub current_version: Version,
        pub genesis_validators_root: Root,
    }
    Ok(ForkData {
        current_version: state_reader
            .fork_current_version(epoch)
            .map_err(|e| VerifyError::StateReaderError(e.to_string()))?,
        genesis_validators_root,
    }
    .tree_hash_root())
}
