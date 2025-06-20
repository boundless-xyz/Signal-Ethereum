// use std::collections::BTreeSet;

use std::collections::BTreeSet;

use beacon_types::EthSpec;
pub use beacon_types::{Attestation, AttestationData};

use crate::committee_cache;
/// Return the set of attesting indices corresponding to `aggregation_bits` and `committee_bits`.
///
/// See: https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#modified-get_attesting_indices
pub fn get_attesting_indices<E: EthSpec>(
    attn: &Attestation<E>,
    committee_cache: &committee_cache::CommitteeCache<E>,
) -> Result<BTreeSet<usize>, committee_cache::Error> {
    let committee_indices = attn.get_committee_indices_map();
    let mut attesting_indices: BTreeSet<usize> = BTreeSet::new();
    let mut committee_offset = 0;
    for committee_index in committee_indices {
        assert!(committee_index < committee_cache.get_committee_count_per_slot() as u64);

        let committee =
            committee_cache.get_beacon_committee(attn.data().slot, committee_index as usize)?;

        let mut committee_attesters = committee
            .iter()
            .enumerate()
            .filter_map(|(i, attester_index)| {
                attn.aggregation_bits_electra()
                    .expect("fail to get aggregation bits")
                    .get(committee_offset + i)
                    .expect("aggregation_bits access out of bounds")
                    .then_some(*attester_index)
            })
            .peekable();
        assert!(committee_attesters.peek().is_some(), "empty committee");
        attesting_indices.extend(committee_attesters);

        committee_offset += committee.len();
    }
    // Bitfield length matches total number of participants
    assert_eq!(
        attn.aggregation_bits_electra()
            .expect("fauked ti get aggregation bits")
            .len(),
        committee_offset
    );
    Ok(attesting_indices.into_iter().collect())
}

#[cfg(feature = "host")]
pub fn conv_attestation<
    E: EthSpec,
    const MAX_VALIDATORS_PER_SLOT: usize,
    const MAX_COMMITTEES_PER_SLOT: usize,
>(
    attestation: ethereum_consensus::electra::Attestation<
        MAX_VALIDATORS_PER_SLOT,
        MAX_COMMITTEES_PER_SLOT,
    >,
) -> Attestation<E> {
    use beacon_types::AttestationElectra;
    use ssz::Decode;

    let a = AttestationElectra {
        aggregation_bits: ssz_types::BitList::from_bytes(
            ssz_rs::serialize(&attestation.aggregation_bits)
                .expect("Failed to serialize aggregation bits")
                .into(),
        )
        .expect("Failed to deserialize aggregation bits"),
        data: conv_attestation_data(attestation.data),
        signature: beacon_types::AggregateSignature::from_ssz_bytes(
            &ssz_rs::serialize(&attestation.signature).expect("Failed to serialize signature"),
        )
        .expect("Failed to deserialize signature"),
        committee_bits: ssz_types::BitVector::from_bytes(
            ssz_rs::serialize(&attestation.committee_bits)
                .expect("Failed to serialize committee bits")
                .into(),
        )
        .expect("Failed to deserialize committee bits"),
    };
    Attestation::Electra(a)
}

#[cfg(feature = "host")]
fn conv_attestation_data(data: ethereum_consensus::electra::AttestationData) -> AttestationData {
    AttestationData {
        slot: data.slot.into(),
        index: data.index as u64,
        beacon_block_root: data.beacon_block_root,
        source: conv_checkpoint(data.source),
        target: conv_checkpoint(data.target),
    }
}

#[cfg(feature = "host")]
pub fn conv_checkpoint(
    checkpoint: ethereum_consensus::electra::Checkpoint,
) -> beacon_types::Checkpoint {
    beacon_types::Checkpoint {
        epoch: checkpoint.epoch.into(),
        root: checkpoint.root,
    }
}
