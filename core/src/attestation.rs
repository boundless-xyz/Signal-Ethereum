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
    let attn = attn.as_electra().expect("attestation is not electra type");
    let committee_indices = attn.get_committee_indices();

    let mut attesting_indices: BTreeSet<usize> = BTreeSet::new();
    let mut committee_offset = 0;

    for committee_index in committee_indices {
        assert!(committee_index < committee_cache.get_committee_count_per_slot() as u64);

        let committee =
            committee_cache.get_beacon_committee(attn.data.slot, committee_index as usize)?;

        let mut committee_attesters = committee
            .iter()
            .enumerate()
            .filter_map(|(i, attester_index)| {
                attn.aggregation_bits
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
    assert_eq!(attn.aggregation_bits.len(), committee_offset);
    Ok(attesting_indices.into_iter().collect())
}
