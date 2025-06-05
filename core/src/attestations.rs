use std::collections::BTreeMap;

use crate::{Attestation, AttestationData, Link, MaxCommitteesPerSlot, Root, Signature, Slot};

pub fn compress(
    attestations: &[Attestation],
) -> Vec<(Link, Vec<SparseAttestation<MinimalAttestationData>>)> {
    let grouped = factor_by_link(attestations);
    grouped
        .into_iter()
        .map(|(link, attestations)| (link, attestations.into_iter().map(Into::into).collect()))
        .collect()
}

pub fn decompress(
    compressed_attestations: &[(Link, Vec<SparseAttestation<MinimalAttestationData>>)],
) -> Vec<Attestation> {
    compressed_attestations
        .into_iter()
        .cloned()
        .flat_map(|(link, sparse_attestations)| {
            sparse_attestations
                .into_iter()
                .map(|attestation| {
                    // Expand the minimal AttestationData back into full AttestationData
                    SparseAttestation::<AttestationData> {
                        data: attestation.data.expand(link.clone()), // happens here
                        non_attesting_indices: attestation.non_attesting_indices,
                        n_aggregators: attestation.n_aggregators,
                        signature: attestation.signature,
                        committee_bits: attestation.committee_bits,
                    }
                })
                .map(Into::into) // Convert SparseAttestation back to Attestation
                .collect::<Vec<_>>()
        })
        .collect()
}

fn factor_by_link(attestations: &[Attestation]) -> BTreeMap<Link, Vec<Attestation>> {
    // Group attestations by their source and target checkpoints (links)
    attestations
        .iter()
        .cloned()
        .fold(BTreeMap::new(), |mut grouped, attestation| {
            let link = Link {
                source: attestation.data.source,
                target: attestation.data.target,
            };
            grouped
                .entry(link)
                .or_insert_with(Vec::new)
                .push(attestation);
            grouped
        })
}

/// Similar to an indexed attestation but it only includes the validator indices that did not sign in a particular committee
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SparseAttestation<A> {
    /// This is a sparse inverse representation of `aggregation_bits`
    /// In other words, it contains the indices of validators that did not sign the attestation
    /// indexed relative to the start of the bitvec. Not their global ValidatorIndex.
    pub non_attesting_indices: Vec<u16>,
    pub n_aggregators: u16,
    pub data: A,
    pub signature: Signature,
    pub committee_bits: ssz_types::BitVector<MaxCommitteesPerSlot>,
}

impl<A> From<Attestation> for SparseAttestation<A>
where
    A: From<AttestationData>,
{
    fn from(attestation: Attestation) -> Self {
        Self {
            non_attesting_indices: attestation
                .aggregation_bits
                .iter()
                .enumerate()
                .filter_map(|(i, bit)| if bit { None } else { Some(i as u16) })
                .collect(),
            n_aggregators: attestation.aggregation_bits.len() as u16,
            data: attestation.data.into(),
            signature: attestation.signature,
            committee_bits: attestation.committee_bits,
        }
    }
}

impl<A> From<SparseAttestation<A>> for Attestation
where
    AttestationData: From<A>,
{
    fn from(attestation: SparseAttestation<A>) -> Self {
        let mut aggregation_bits =
            ssz_types::BitList::with_capacity(attestation.n_aggregators as usize).unwrap();

        for i in 0..attestation.n_aggregators as usize {
            aggregation_bits.set(i, true).unwrap();
        }

        for non_attesting_index in attestation.non_attesting_indices {
            aggregation_bits
                .set(non_attesting_index as usize, false)
                .unwrap();
        }

        Self {
            aggregation_bits,
            data: attestation.data.into(),
            signature: attestation.signature,
            committee_bits: attestation.committee_bits,
        }
    }
}

/// This skips the index field as it is always zero in Electra
/// It also moves the source and target fields out so they can be grouped together
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MinimalAttestationData {
    pub slot: Slot,
    pub beacon_block_root: Root,
}

impl From<AttestationData> for MinimalAttestationData {
    fn from(data: AttestationData) -> Self {
        Self {
            slot: data.slot,
            beacon_block_root: data.beacon_block_root,
        }
    }
}

impl MinimalAttestationData {
    pub fn expand(self, link: Link) -> AttestationData {
        AttestationData {
            index: 0, // Index is always zero in Electra
            slot: self.slot,
            beacon_block_root: self.beacon_block_root,
            source: link.source,
            target: link.target,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Attestation, AttestationData, Checkpoint, Root, Signature};
    use ssz_types::{BitList, BitVector};

    const VALID_SIG: [u8; 96] = [
        // a random valid signature from the beacon chain
        0x8b, 0x5d, 0x2b, 0x0c, 0x5d, 0x07, 0x78, 0x2e, 0xf8, 0xb6, 0x91, 0x1f, 0x9c, 0xfb, 0xa4,
        0x28, 0x19, 0x9c, 0x9a, 0xbe, 0xe8, 0x75, 0xe2, 0x5f, 0xb2, 0x86, 0x7f, 0x6f, 0x21, 0xa5,
        0xf3, 0x81, 0xef, 0xd0, 0x3d, 0x57, 0xf4, 0x61, 0xa9, 0xf9, 0x61, 0xec, 0xbc, 0x99, 0xa1,
        0xf1, 0xdb, 0x82, 0x18, 0xf1, 0xad, 0x47, 0x4f, 0xbf, 0x20, 0x41, 0xfe, 0x96, 0xe0, 0x5b,
        0x7c, 0x3e, 0xfd, 0x86, 0xc3, 0xb4, 0x24, 0xbb, 0xfd, 0x41, 0x34, 0xdf, 0x0b, 0xa9, 0x00,
        0x5f, 0x24, 0x95, 0xce, 0x39, 0x04, 0x0b, 0x19, 0x83, 0x1e, 0x04, 0x8f, 0x0f, 0x5e, 0x0c,
        0x9c, 0x93, 0x9f, 0xfc, 0xca, 0x6d,
    ];

    #[test]
    fn test_roundtrip_attestation() {
        let attestations = vec![Attestation {
            aggregation_bits: BitList::with_capacity(0).unwrap(),
            data: AttestationData {
                slot: 1,
                index: 0,
                beacon_block_root: Root::default(),
                source: Checkpoint {
                    epoch: 0,
                    root: Root::default(),
                },
                target: Checkpoint {
                    epoch: 0,
                    root: Root::default(),
                },
            },
            signature: Signature::from_bytes(&VALID_SIG).unwrap(),
            committee_bits: BitVector::new(),
        }];

        let original_size = bincode::serialize(&attestations).unwrap().len();
        println!("Original size: {}", original_size);

        let compressed = compress(&attestations);

        let compressed_size = bincode::serialize(&compressed).unwrap().len();
        println!("Compressed size: {}", compressed_size);

        let decompressed = decompress(&compressed);

        assert_eq!(decompressed, attestations);
    }
}
