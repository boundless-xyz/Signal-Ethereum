use std::collections::BTreeSet;

use crate::{
    Attestation, BEACON_ATTESTER_DOMAIN, CommitteeCache, CommitteeIndex, Ctx, Domain, Epoch, Input,
    Link, MAX_COMMITTEES_PER_SLOT, MAX_VALIDATORS_PER_COMMITTEE, PublicKey, Root, ShuffleData,
    StateReader, Version, fast_aggregate_verify_pre_aggregated,
};
use alloc::collections::BTreeMap;
use sha2::Digest;
use ssz_rs::prelude::*;
use tracing::{debug, error, info, trace, warn};
pub fn verify<S: StateReader, C: Ctx>(state_reader: &mut S, input: Input, context: &C) -> bool {
    // 0. pre-conditions
    assert_eq!(
        input.candidate_checkpoint.epoch,
        input.trusted_checkpoint.epoch + 1,
        "Candidate must be direct successor of trusted checkpoint"
    );

    // 1. Attestation processing
    let mut committee_caches: BTreeMap<Epoch, CommitteeCache> = BTreeMap::new();

    let mut balances: BTreeMap<Link, u64> = BTreeMap::new();
    input
        .attestations
        .into_iter()
        .filter(|a| context.compute_epoch_at_slot(a.data.slot) >= input.trusted_checkpoint.epoch)
        .for_each(|attestation| {
            debug!(
                "Checking attestation for slot: {} committee: {}",
                attestation.data.slot, attestation.data.index
            );

            let attestation_epoch = context.compute_epoch_at_slot(attestation.data.slot);
            debug!("Attestation epoch: {}", attestation_epoch);

            let committee_cache = committee_caches
                .entry(attestation_epoch)
                .or_insert_with(|| {
                    get_shufflings_for_epoch(state_reader, attestation_epoch, context)
                });

            let committee_indices: Vec<CommitteeIndex> = attestation
                .committee_bits
                .iter()
                .enumerate()
                .flat_map(|(i, bit)| bit.then_some(i))
                .collect();
            trace!("Committee indices: {:?}", committee_indices);

            let mut attesting_indices = vec![];
            let committees = committee_cache
                .get_beacon_committees_at_slot(attestation.data.slot, context)
                .unwrap();
            let mut committee_offset = 0;

            let committee_count_per_slot = committees.len();
            for committee_index in committee_indices {
                let beacon_committee = committees
                    .get(committee_index as usize)
                    .expect("No committee found");

                if committee_index >= committee_count_per_slot {
                    error!("Invalid committee index: {}", committee_index);
                }

                let committee_attesters = beacon_committee
                    .iter()
                    .enumerate()
                    .filter_map(|(i, &index)| {
                        if attestation
                            .aggregation_bits
                            .get(committee_offset + i)
                            .unwrap_or(false)
                        {
                            Some(index)
                        } else {
                            None
                        }
                    })
                    .collect::<BTreeSet<usize>>();

                if committee_attesters.is_empty() {
                    error!("Empty Committee");
                }

                attesting_indices.extend(committee_attesters);
                committee_offset += beacon_committee.len();
            }
            attesting_indices.sort_unstable();
            debug!("Attestation has {} participants", attesting_indices.len());

            // check if attestation has a valid aggregate signature
            let (pubkeys, attesting_balance) = state_reader
                .aggregate_validator_keys_and_balance(attesting_indices)
                .unwrap();

            let domain = beacon_attester_signing_domain(state_reader);
            let signing_root = compute_signing_root(&attestation.data, domain);
            let agg_pk = PublicKey::aggregate(&pubkeys).unwrap();

            if let Err(e) = fast_aggregate_verify_pre_aggregated(
                &agg_pk,
                signing_root.as_ref(),
                &attestation.signature,
            ) {
                warn!("Signature verification failed: {:?}", e);
            } else {
                let attestation_link = Link(attestation.data.source, attestation.data.target);
                balances
                    .entry(attestation_link)
                    .and_modify(|balance| *balance += attesting_balance)
                    .or_insert(attesting_balance);
            }
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

fn get_seed<S: StateReader>(state_reader: &S, epoch: u64, domain_type: [u8; 4]) -> [u8; 32] {
    let mix = state_reader.get_randao(epoch).unwrap().unwrap();

    let mut h = sha2::Sha256::new();
    Digest::update(&mut h, domain_type);
    Digest::update(&mut h, epoch.to_le_bytes());
    Digest::update(&mut h, mix);

    h.finalize().into()
}

// this can compute validators for up to
// 1 epoch ahead of the epoch the state_reader can read from
pub fn get_shufflings_for_epoch<S: StateReader, C: Ctx>(
    state_reader: &S,
    epoch: u64,
    context: &C,
) -> CommitteeCache {
    info!("Getting shufflings for epoch: {}", epoch);
    // first up lets compute and cache the committee shufflings for this epoch
    let len_total_validators: usize = state_reader.get_validator_count(epoch).unwrap().unwrap();
    info!("Valdator count: {}", len_total_validators);

    let active_validator_indices = state_reader.get_active_validator_indices(epoch).unwrap();

    let seed = get_seed(state_reader, epoch, BEACON_ATTESTER_DOMAIN);

    CommitteeCache::initialized(
        ShuffleData {
            seed: seed.into(),
            active_validator_indices,
            len_total_validators,
        },
        epoch,
        context,
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

fn beacon_attester_signing_domain<S: StateReader>(state_reader: &S) -> [u8; 32] {
    // let domain_type = Self::DomainBeaconAttester::to_u32().to_le_bytes();
    let domain_type = BEACON_ATTESTER_DOMAIN;
    let fork_data_root = fork_data_root(state_reader, state_reader.genesis_validators_root());
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
) -> ssz_rs::Node {
    #[derive(SimpleSerialize)]
    struct ForkData {
        pub current_version: Version,
        pub genesis_validators_root: Root,
    }
    ForkData {
        current_version: state_reader.fork_version(),
        genesis_validators_root,
    }
    .hash_tree_root()
    .unwrap()
}
