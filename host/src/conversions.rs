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

use z_core::{Attestation, AttestationData, EthSpec};

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

fn conv_attestation_data(data: ethereum_consensus::electra::AttestationData) -> AttestationData {
    AttestationData {
        slot: data.slot.into(),
        index: data.index as u64,
        beacon_block_root: data.beacon_block_root,
        source: conv_checkpoint(data.source),
        target: conv_checkpoint(data.target),
    }
}

pub fn conv_checkpoint(
    checkpoint: ethereum_consensus::electra::Checkpoint,
) -> beacon_types::Checkpoint {
    beacon_types::Checkpoint {
        epoch: checkpoint.epoch.into(),
        root: checkpoint.root,
    }
}
