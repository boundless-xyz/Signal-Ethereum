use core::panic;
use std::collections::BTreeSet;

use crate::{
    Attestation, BEACON_ATTESTER_DOMAIN, Checkpoint, CommitteeCache, CommitteeIndex, Ctx, Domain,
    Epoch, Input, MAX_COMMITTEES_PER_SLOT, MAX_VALIDATORS_PER_COMMITTEE, PublicKey, Root,
    ShuffleData, StateReader, Version, fast_aggregate_verify_pre_aggregated,
};
use alloc::collections::BTreeMap;
use sha2::Digest;
use ssz_rs::prelude::*;
use tracing::{debug, info, warn};
pub fn verify<S: StateReader, C: Ctx>(state_reader: &mut S, input: Input, context: &C) -> bool {
    // 0. pre-conditions
    assert_eq!(
        input.candidate_checkpoint.epoch,
        input.trusted_checkpoint.epoch + 1,
        "Candidate must be direct successor of trusted checkpoint"
    );

    // 1. Attestation processing
    let mut committee_caches: BTreeMap<Epoch, CommitteeCache> = BTreeMap::new();

    let mut links: Vec<(Checkpoint, Checkpoint)> = vec![];
    let mut balances: BTreeMap<usize, u64> = BTreeMap::new();
    input
        .attestations
        .iter()
        .filter(|a| context.compute_epoch_at_slot(a.data.slot) >= input.trusted_checkpoint.epoch)
        .for_each(|attestation| {
            debug!(
                "Checking attestation for slot: {} committee: {}",
                attestation.data.slot, attestation.data.index
            );
            let source = attestation.data.source.clone();
            let target = attestation.data.target.clone();
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

            let mut attesting_indices = BTreeSet::new();

            for (committee_offset, index) in committee_indices.clone().into_iter().enumerate() {
                let committee = committee_cache
                    .get_beacon_committee(attestation.data.slot, index, context)
                    .unwrap();
                for (i, validator_index) in committee.iter().enumerate() {
                    if attestation.aggregation_bits[committee_offset + i] {
                        attesting_indices.insert(*validator_index);
                    }
                }
            }

            debug!("Attestation has {} participants", attesting_indices.len());

            // TODO(ec2): We definitely can get around having to copy the indices
            let attesting_indices: Vec<usize> = attesting_indices.into_iter().collect();

            let (pubkeys, attesting_balance) = state_reader
                .aggregate_validator_keys_and_balance(&attesting_indices)
                .unwrap();

            let domain = beacon_attester_signing_domain(state_reader);
            let signing_root = compute_signing_root(&attestation.data, domain);
            let agg_pk = PublicKey::aggregate(&pubkeys).unwrap();

            if let Err(_e) = fast_aggregate_verify_pre_aggregated(
                &agg_pk,
                signing_root.as_ref(),
                &attestation.signature,
            ) {
                // TODO(ec2): Dont actually need to panic here i dont think... we can just continue
                panic!("Signature verification failed");
            }
            if let Some(idx) = links.iter().position(|x| x.0 == source && x.1 == target) {
                balances
                    .get_mut(&idx)
                    .map(|c| *c += attesting_balance)
                    .expect("should already exist");
            } else {
                balances.insert(links.len(), attesting_balance);
            }
            if !links.contains(&(source.clone(), target.clone())) {
                links.push((source.clone(), target.clone()));
            }
        });
    let balances = balances.values().copied().collect::<Vec<_>>();
    debug!(
        "Links and balances: {:#?}",
        balances.iter().zip(links.iter()).collect::<Vec<_>>()
    );
    /////////// 2. Finality calculation  //////////////
    info!("2. Finality calculation start");
    let sm_links = get_supermajority_links(
        state_reader,
        input.trusted_checkpoint.epoch,
        &links,
        &balances,
    );
    debug!("Supermajority links: {:#?}", sm_links);

    // Because by definition the trusted CP is finalized we know that:
    // - All checkpoints prior to trusted_cp are finalized
    // - The candidate is justified (since to finalize requires a link forward to the tip of a chain of justified CPs which must include the direct successor)
    // so all we really need to look at is finalizing the candidate or (in the case of delayed finality) one of its successors.
    // we will ignore the delayed finality case for now

    // by definition the trusted and candidate checkpoints are justified
    let mut hightest_justified_epoch = input.candidate_checkpoint.epoch;
    info!("Highest justified epoch: {}", hightest_justified_epoch);
    for epoch in input.candidate_checkpoint.epoch + 1.. {
        // if we can justify the checkpoint at that epoch then do it or else abort
        if sm_links
            .iter()
            .any(|link| link.0.epoch <= hightest_justified_epoch && link.1.epoch == epoch)
        {
            hightest_justified_epoch = epoch;
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
            link.0 == input.candidate_checkpoint && link.1.epoch <= hightest_justified_epoch
        }) {
            info!("Successfully finalized candidate");
            return true;
        }
    }
    true
}

fn get_seed<S: StateReader>(state_reader: &S, epoch: u64, domain_type: [u8; 4]) -> [u8; 32] {
    let mix = state_reader.get_randao(epoch).unwrap().unwrap();
    let mut input = [0u8; 44];
    input[..4].copy_from_slice(&domain_type);
    input[4..12].copy_from_slice(&epoch.to_le_bytes());
    input[12..].copy_from_slice(mix.as_ref());
    sha2::Sha256::digest(input).as_slice().try_into().unwrap()
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
    links: &[(Checkpoint, Checkpoint)],
    balances: &[u64],
) -> Vec<(Checkpoint, Checkpoint)> {
    let total_active_balance = state_reader.get_total_active_balance(epoch).unwrap();
    let sm_links = links
        .iter()
        .zip(balances.iter())
        .filter(|(_, attesting_balance)| **attesting_balance * 3 >= &total_active_balance * 2) // check enough participation
        .map(|(link, _)| link.clone())
        .collect();
    sm_links
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
