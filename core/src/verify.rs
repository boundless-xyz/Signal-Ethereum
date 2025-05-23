use std::collections::BTreeSet;

use crate::{
    Attestation, AttestationData, BEACON_ATTESTER_DOMAIN, CommitteeCache, ConsensusState, Domain,
    Epoch, Input, Link, MAX_COMMITTEES_PER_SLOT, MAX_VALIDATORS_PER_COMMITTEE, PublicKey, Root,
    ShuffleData, Signature, StateReader, ValidatorIndex, ValidatorInfo, Version,
    fast_aggregate_verify_pre_aggregated,
};
use alloc::collections::BTreeMap;
use ssz_rs::prelude::*;
use thiserror::Error;
use tracing::{debug, info};

pub fn verify<S: StateReader>(state_reader: &S, input: Input) -> ConsensusState {
    let Input {
        state,
        link,
        attestations,
        ..
    } = input;
    // TODO(ec2): I think we need to enforce here that the trusted state is less than or equal to state.finalized_checkpoint epoch
    // TODO(ec2): We can also bound the number of state patches to the k in k-finality case
    let context = state_reader.context();

    // 1. Attestation processing
    let mut validator_cache: BTreeMap<Epoch, BTreeMap<ValidatorIndex, &ValidatorInfo>> =
        BTreeMap::new();
    let mut committee_caches: BTreeMap<Epoch, CommitteeCache> = BTreeMap::new();

    let attesting_balance: u64 = attestations
        .into_iter()
        .filter(|a| a.data.source == link.source && a.data.target == input.link.target)
        .map(|attestation| {
            let data = attestation.data;
            debug!("Processing attestation: {:?}", data);

            assert_eq!(data.index, 0);

            let attestation_epoch = data.target.epoch;

            let committee_cache = committee_caches
                .entry(attestation_epoch)
                .or_insert_with(|| {
                    get_shufflings_for_epoch(state_reader, attestation_epoch, attestation_epoch)
                });

            // get_attesting_indices
            // see: https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#modified-get_attesting_indices
            let mut attesting_indices: BTreeSet<usize> = BTreeSet::new();

            // get_committee_indices
            let committee_indices = attestation
                .committee_bits
                .iter()
                .enumerate()
                .filter_map(|(index, bit)| bit.then_some(index));

            let mut committee_offset = 0;
            for committee_index in committee_indices {
                assert!(committee_index < committee_cache.get_committee_count_per_slot());

                let committee = committee_cache
                    .get_beacon_committee(data.slot, committee_index, context)
                    .unwrap();
                let mut committee_attesters = committee
                    .iter()
                    .enumerate()
                    .filter_map(|(i, attester_index)| {
                        attestation.aggregation_bits[committee_offset + i]
                            .then_some(*attester_index)
                    })
                    .peekable();
                assert!(committee_attesters.peek().is_some());
                attesting_indices.extend(committee_attesters);

                committee_offset += committee.len();
            }

            // Bitfield length matches total number of participants
            assert_eq!(attestation.aggregation_bits.len(), committee_offset);

            let state_validators = validator_cache.entry(attestation_epoch).or_insert_with(|| {
                state_reader
                    .active_validators(attestation_epoch, attestation_epoch)
                    .unwrap()
                    .collect()
            });
            let attesting_validators = attesting_indices
                .iter()
                .map(|i| *state_validators.get(i).unwrap())
                .collect::<Vec<_>>();

            assert!(is_valid_indexed_attestation(
                state_reader,
                attesting_validators.iter().copied(),
                &data,
                attestation.signature
            ));

            attesting_validators
                .iter()
                .fold(0u64, |acc, e| acc + e.effective_balance)
        })
        .sum();

    let total_active_balance = state_reader
        .get_total_active_balance(link.target.epoch)
        .unwrap();

    assert!(attesting_balance * 3 >= &total_active_balance * 2);

    /////////// 2. State update calculation  //////////////
    info!("2. State update calculation start");

    state_transition(&state, &link).expect("State transition failed")
}

#[derive(Debug, Error, PartialEq)]
enum StateTransitionError {
    #[error("Invalid state transition")]
    CannotEvolveState,
}

/// Apply a supermajority link to the current consensus state to obtain a new consensus state.
fn state_transition(
    state: &ConsensusState,
    link: &Link,
) -> Result<ConsensusState, StateTransitionError> {
    match link {
        // Case 1: 1-finality. Finalizes and justifies the source and target checkpoints respectively
        // where they are adjacent checkpoints.
        // This applies when the source checkpoint is the current justified checkpoint or the previous justified checkpoint
        Link { source, target }
            if target.epoch == source.epoch + 1
                && (*source == state.current_justified_checkpoint
                    || *source == state.previous_justified_checkpoint) =>
        {
            Ok(ConsensusState {
                finalized_checkpoint: link.source,
                current_justified_checkpoint: link.target,
                previous_justified_checkpoint: link.source,
            })
        }
        // Case 2: Justification only. This occurs when the source is an already finalized checkpoint
        Link { source, target }
            if *source == state.finalized_checkpoint
                && target.epoch == state.current_justified_checkpoint.epoch + 1 =>
        {
            Ok(ConsensusState {
                finalized_checkpoint: state.finalized_checkpoint, // no change
                current_justified_checkpoint: link.target,
                previous_justified_checkpoint: state.current_justified_checkpoint,
            })
        }
        // Case 3: 2-finality. Finalizes the source checkpoint and justifies the target checkpoint
        // with a link that skips over an intermediate justified checkpoint
        Link { source, target }
            if target.epoch == source.epoch + 2
                && *source == state.previous_justified_checkpoint =>
        {
            Ok(ConsensusState {
                finalized_checkpoint: link.source,
                current_justified_checkpoint: link.target,
                previous_justified_checkpoint: state.current_justified_checkpoint,
            })
        }
        _ => Err(StateTransitionError::CannotEvolveState),
    }
}

fn is_valid_indexed_attestation<'a, S: StateReader>(
    state_reader: &S,
    attesting_validators: impl IntoIterator<Item = &'a ValidatorInfo>,
    data: &AttestationData,
    signature: Signature,
) -> bool {
    let pubkeys = attesting_validators
        .into_iter()
        .map(|validator| &validator.pubkey)
        .collect::<Vec<_>>();
    if pubkeys.is_empty() {
        return false;
    }
    let domain = beacon_attester_signing_domain(state_reader, data.target.epoch);
    let signing_root = compute_signing_root(data, domain);

    let agg_pk = PublicKey::aggregate(&pubkeys).unwrap();

    fast_aggregate_verify_pre_aggregated(&agg_pk, signing_root.as_ref(), &signature).is_ok()
}

// this can compute validators for up to
// 1 epoch ahead of the epoch the state_reader can read from
pub fn get_shufflings_for_epoch<S: StateReader>(
    state_reader: &S,
    state: Epoch,
    epoch: Epoch,
) -> CommitteeCache {
    info!("Getting shufflings for epoch: {}", state);

    let indices = state_reader
        .get_active_validator_indices(state, epoch)
        .unwrap()
        .collect();
    let seed = state_reader
        .get_seed(state, epoch, BEACON_ATTESTER_DOMAIN.into())
        .unwrap();
    let committees_per_slot = state_reader
        .get_committee_count_per_slot(state, epoch)
        .unwrap();

    CommitteeCache::initialized(
        ShuffleData {
            seed,
            indices,
            committees_per_slot,
        },
        state,
        state_reader.context(),
    )
    .unwrap()
}

pub fn get_attesting_indices(
    committee: &[usize],
    attestation: &Attestation<
        { MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT },
        MAX_COMMITTEES_PER_SLOT,
    >,
) -> Vec<usize> {
    committee
        .iter()
        .enumerate()
        .filter(|(i, _)| attestation.aggregation_bits[*i])
        .map(|(_, validator_index)| *validator_index)
        .collect()
}

fn beacon_attester_signing_domain<S: StateReader>(state_reader: &S, epoch: Epoch) -> [u8; 32] {
    // let domain_type = Self::DomainBeaconAttester::to_u32().to_le_bytes();
    let domain_type = BEACON_ATTESTER_DOMAIN;
    let fork_data_root =
        fork_data_root(state_reader, state_reader.genesis_validators_root(), epoch);
    let mut domain = [0_u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_data_root.as_slice()[..28]);
    domain
}

pub fn compute_signing_root<T: SimpleSerialize>(ssz_object: &T, domain: Domain) -> Root {
    let object_root = ssz_object.hash_tree_root().unwrap();

    #[derive(SimpleSerialize)]
    pub struct SigningData {
        pub object_root: Root,
        pub domain: Domain,
    }

    let s = SigningData {
        object_root,
        domain,
    };
    s.hash_tree_root().unwrap()
}

fn fork_data_root<S: StateReader>(
    state_reader: &S,
    genesis_validators_root: ssz_rs::Node,
    epoch: Epoch,
) -> ssz_rs::Node {
    #[derive(SimpleSerialize)]
    struct ForkData {
        pub current_version: Version,
        pub genesis_validators_root: Root,
    }
    ForkData {
        current_version: state_reader.fork_current_version(epoch).unwrap(),
        genesis_validators_root,
    }
    .hash_tree_root()
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Checkpoint;
    use alloy_primitives::B256;

    const fn cp(epoch: Epoch) -> Checkpoint {
        Checkpoint {
            epoch,
            root: B256::ZERO,
        }
    }

    /// Test cases for the state transition function.
    /// (pre-state, link, expected post-state)
    const TEST_CASES: &[(
        ConsensusState,
        Link,
        Result<ConsensusState, StateTransitionError>,
    )] = &[
        // Simple 1-finality case
        //  F   C   C'           F   C
        // [0]-[1]-[2]  ->  [0]-[1]-[2]
        //      └───┘
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(1),
                previous_justified_checkpoint: cp(1),
            },
            Link {
                source: cp(1),
                target: cp(2),
            },
            Ok(ConsensusState {
                finalized_checkpoint: cp(1),
                current_justified_checkpoint: cp(2),
                previous_justified_checkpoint: cp(2),
            }),
        ),
        // Other 1-finality case
        //  F   P   C   C'               F   C
        // [0]-[1]-[2]-[3]  ->  [0]-[1]-[2]-[3]
        //          └───┘
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(2),
                previous_justified_checkpoint: cp(1),
            },
            Link {
                source: cp(2),
                target: cp(3),
            },
            Ok(ConsensusState {
                finalized_checkpoint: cp(2),
                current_justified_checkpoint: cp(3),
                previous_justified_checkpoint: cp(3),
            }),
        ),
        // Justify only case
        //  F   C   C'       F   P   C
        // [0]-[1]-[2]  ->  [0]-[1]-[2]
        //  └───────┘
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(1),
                previous_justified_checkpoint: cp(1),
            },
            Link {
                source: cp(0),
                target: cp(2),
            },
            Ok(ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(2),
                previous_justified_checkpoint: cp(1),
            }),
        ),
        // 2-finality case (other variant)
        //  F   P   C   C'       F       P   C
        // [0]-[1]-[2]-[3]  ->  [0]-[1]-[2]-[3]
        //  └───────────┘
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(2),
                previous_justified_checkpoint: cp(1),
            },
            Link {
                source: cp(0),
                target: cp(3),
            },
            Ok(ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(3),
                previous_justified_checkpoint: cp(2),
            }),
        ),
        // 2-finality case
        //  F   P   C   C'           F   P   C
        // [0]-[1]-[2]-[3]  ->  [0]-[1]-[2]-[3]
        //      └───────┘
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(2),
                previous_justified_checkpoint: cp(1),
            },
            Link {
                source: cp(1),
                target: cp(3),
            },
            Ok(ConsensusState {
                finalized_checkpoint: cp(1),
                current_justified_checkpoint: cp(3),
                previous_justified_checkpoint: cp(2),
            }),
        ),
    ];

    #[test]
    fn test_state_transition() {
        for (state, link, expected) in TEST_CASES {
            let result = state_transition(state, link);
            assert_eq!(result, *expected);
        }
    }
}
