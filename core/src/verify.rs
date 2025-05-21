use std::collections::BTreeSet;

use crate::{
    Attestation, AttestationData, BEACON_ATTESTER_DOMAIN, CommitteeCache, Ctx, Domain, Epoch,
    Input, Link, MAX_COMMITTEES_PER_SLOT, MAX_VALIDATORS_PER_COMMITTEE, PublicKey, Root,
    ShuffleData, Signature, StateReader, ValidatorIndex, ValidatorInfo, Version,
    fast_aggregate_verify_pre_aggregated,
};
use alloc::collections::BTreeMap;
use ssz_rs::prelude::*;
use tracing::{debug, error, info, trace, warn};

pub fn verify<S: StateReader>(state_reader: &S, input: Input) -> bool {
    // 0. pre-conditions
    assert_eq!(
        input.candidate_checkpoint.epoch,
        input.trusted_checkpoint.epoch + 1,
        "Candidate must be direct successor of trusted checkpoint"
    );

    let context = state_reader.context();

    // 1. Attestation processing
    let mut validator_cache: BTreeMap<Epoch, BTreeMap<ValidatorIndex, &ValidatorInfo>> =
        BTreeMap::new();
    let mut committee_caches: BTreeMap<Epoch, CommitteeCache> = BTreeMap::new();

    let mut balances: BTreeMap<Link, u64> = BTreeMap::new();
    input
        .attestations
        .into_iter()
        .filter(|a| context.compute_epoch_at_slot(a.data.slot) >= input.trusted_checkpoint.epoch)
        .for_each(|attestation| {
            let data = attestation.data;
            debug!("Processing attestation: {:?}", data);

            assert_eq!(data.target.epoch, context.compute_epoch_at_slot(data.slot));
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
                let committee_attesters: BTreeSet<_> = committee
                    .iter()
                    .enumerate()
                    .filter_map(|(i, attester_index)| {
                        attestation.aggregation_bits[committee_offset + i]
                            .then_some(*attester_index)
                    })
                    .collect();
                assert!(!committee_attesters.is_empty());
                committee_offset += committee.len();

                attesting_indices.extend(&committee_attesters);
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

            let attesting_balance = attesting_validators
                .iter()
                .fold(0u64, |acc, e| acc + e.effective_balance);

            let attestation_link = Link(data.source, data.target);
            balances
                .entry(attestation_link)
                .and_modify(|balance| *balance += attesting_balance)
                .or_insert(attesting_balance);
        });
    debug!("Links and balances: {:#?}", balances);

    /////////// 2. Finality calculation  //////////////
    info!("2. Finality calculation start");
    let sm_links = get_supermajority_links(state_reader, input.trusted_checkpoint.epoch, balances);
    debug!("Supermajority links: {:#?}", sm_links);

    // Because by definition the trusted CP is finalized we know that:
    // - All checkpoints prior to trusted_cp are finalized
    // - The candidate is justified (since to finalize requires a link forward to the tip of a chain of justified CPs which must include the direct successor)
    // so all we really need to look at is finalizing the candidate or (in the case of delayed finality) one of its successors.
    // we will ignore the delayed finality case for now

    // by definition the trusted and candidate checkpoints are justified
    let mut highest_justified_epoch = input.candidate_checkpoint.epoch;
    info!("Highest justified epoch: {}", highest_justified_epoch);
    for epoch in input.candidate_checkpoint.epoch + 1.. {
        // if we can justify the checkpoint at that epoch then do it or else abort
        if sm_links
            .iter()
            .any(|link| link.0.epoch <= highest_justified_epoch && link.1.epoch == epoch)
        {
            highest_justified_epoch = epoch;
            info!("Successfully justified epoch: {}", epoch);
        } else {
            // no way to finalize if we have a gap in the sequence of justified checkpoints
            warn!(
                "Non-contiguous sequence of finalized checkpoints prohibits finalizing candidate"
            );
            return false;
        }
        // see if we can now finalize the candidate by linking to the end of a sequence of justified checkpoints
        if sm_links.iter().any(|link| {
            link.0 == input.candidate_checkpoint && link.1.epoch <= highest_justified_epoch
        }) {
            info!("Successfully finalized candidate");
            return true;
        }
    }
    true
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

// process attestations to produce supermajority links. A supermajority link is defined as a
// (source, target) pair with:
// - valid signatures by enough validators to comprise 2/3 of the total active balance in the validator set
// - a justified source
fn get_supermajority_links<S: StateReader>(
    state_reader: &S,
    epoch: u64,
    balances: BTreeMap<Link, u64>,
) -> Vec<Link> {
    let total_active_balance = state_reader.get_total_active_balance(epoch).unwrap();

    balances
        .into_iter()
        .filter(|(_, attesting_balance)| *attesting_balance * 3 >= &total_active_balance * 2) // check enough participation
        .map(|(link, _)| link)
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
