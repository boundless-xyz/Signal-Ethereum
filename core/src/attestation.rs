use std::collections::BTreeSet;

use beacon_types::EthSpec;
use tree_hash_derive::TreeHash;

use crate::{
    Checkpoint, CommitteeIndex, MaxCommitteesPerSlot, MaxValidatorsPerSlot, Root, Signature, Slot,
    committee_cache,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, TreeHash)]
pub struct AttestationData {
    pub slot: Slot,
    pub index: CommitteeIndex,
    pub beacon_block_root: Root,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

// Note: This is was updated in electra.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Attestation {
    pub aggregation_bits: ssz_types::BitList<MaxValidatorsPerSlot>,
    pub data: AttestationData,
    pub signature: Signature,
    pub committee_bits: ssz_types::BitVector<MaxCommitteesPerSlot>,
}

impl Attestation {
    /// Return the set of committee indices corresponding to `committee_bits`.
    ///
    /// See: https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#new-get_committee_indices
    pub fn get_committee_indices(&self) -> Vec<CommitteeIndex> {
        self.committee_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| if bit { Some(index) } else { None })
            .collect()
    }

    /// Return the set of attesting indices corresponding to `aggregation_bits` and `committee_bits`.
    ///
    /// See: https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#modified-get_attesting_indices
    pub fn get_attesting_indices<E: EthSpec>(
        &self,
        ctx: &C,
        committee_cache: &committee_cache::CommitteeCache,
    ) -> Result<BTreeSet<usize>, committee_cache::Error> {
        let committee_indices = self.get_committee_indices();
        let mut attesting_indices: BTreeSet<usize> = BTreeSet::new();
        let mut committee_offset = 0;
        for committee_index in committee_indices {
            assert!(committee_index < committee_cache.get_committee_count_per_slot());

            let committee = committee_cache.get_beacon_committee(
                self.data.slot,
                committee_index as usize,
                ctx,
            )?;

            let mut committee_attesters = committee
                .iter()
                .enumerate()
                .filter_map(|(i, attester_index)| {
                    self.aggregation_bits
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
        assert_eq!(self.aggregation_bits.len(), committee_offset);
        Ok(attesting_indices.into_iter().collect())
    }
}

#[cfg(feature = "host")]
impl From<ethereum_consensus::electra::AttestationData> for AttestationData {
    fn from(data: ethereum_consensus::electra::AttestationData) -> Self {
        Self {
            slot: data.slot,
            index: data.index,
            beacon_block_root: data.beacon_block_root,
            source: data.source.into(),
            target: data.target.into(),
        }
    }
}

#[cfg(feature = "host")]
impl<const MAX_VALIDATORS_PER_SLOT: usize, const MAX_COMMITTEES_PER_SLOT: usize>
    From<ethereum_consensus::electra::Attestation<MAX_VALIDATORS_PER_SLOT, MAX_COMMITTEES_PER_SLOT>>
    for Attestation
{
    fn from(
        attestation: ethereum_consensus::electra::Attestation<
            MAX_VALIDATORS_PER_SLOT,
            MAX_COMMITTEES_PER_SLOT,
        >,
    ) -> Self {
        let agg_bits_ser = ssz_rs::serialize(&attestation.aggregation_bits)
            .expect("Failed to serialize aggregation bits");
        let committee_bits_ser = ssz_rs::serialize(&attestation.committee_bits)
            .expect("Failed to serialize committee bits");

        Self {
            aggregation_bits: ssz_types::BitList::from_bytes(agg_bits_ser.into())
                .expect("Failed to deserialize aggregation bits"),
            data: attestation.data.into(),
            signature: attestation.signature.into(),
            committee_bits: ssz_types::BitVector::from_bytes(committee_bits_ser.into())
                .expect("Failed to deserialize committee bits"),
        }
    }
}
