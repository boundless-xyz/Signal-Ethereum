use std::collections::BTreeSet;

use crate::{
    Attestation, AttestationData, BEACON_ATTESTER_DOMAIN, CommitteeCache, Domain, Epoch, Input,
    MAX_COMMITTEES_PER_SLOT, MAX_VALIDATORS_PER_COMMITTEE, PublicKey, Root, ShuffleData, Signature,
    StateReader, ValidatorIndex, ValidatorInfo, Version, consensus_state::ConsensusState,
    fast_aggregate_verify_pre_aggregated,
};
use alloc::collections::BTreeMap;
use ssz_rs::prelude::*;
use tracing::{debug, info};

pub fn verify<S: StateReader>(state_reader: &S, input: Input) -> ConsensusState {
    let Input {
        consensus_state,
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

    consensus_state
        .state_transition(&link)
        .expect("State transition failed")
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
