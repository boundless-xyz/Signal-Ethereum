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

use anyhow::{Context, Result, anyhow};
use bls::PublicKey;
use z_core::{Attestation, AttestationData, EthSpec, ValidatorInfo};

/// An extension trait for failable conversions into `beacon_types`.
pub(crate) trait TryAsBeaconType<T> {
    /// Tries to perform the conversion into a `beacon_types` equivalent.
    fn try_as_beacon_type(&self) -> Result<T>;
}

impl<E: EthSpec, const MAX_VALIDATORS_PER_SLOT: usize, const MAX_COMMITTEES_PER_SLOT: usize>
    TryAsBeaconType<Attestation<E>>
    for ethereum_consensus::electra::Attestation<MAX_VALIDATORS_PER_SLOT, MAX_COMMITTEES_PER_SLOT>
{
    fn try_as_beacon_type(&self) -> Result<Attestation<E>> {
        use ssz::Decode;
        use ssz_rs::Serialize;

        let mut buf = Vec::new();
        self.serialize(&mut buf)
            .context("failed to SSZ-serialize source attestation")?;

        Ok(Attestation::Electra(
            beacon_types::AttestationElectra::from_ssz_bytes(&buf).map_err(|err| {
                anyhow!("failed to SSZ-deserialize into target Electra attestation: {err:?}")
            })?,
        ))
    }
}

impl TryAsBeaconType<AttestationData> for ethereum_consensus::electra::AttestationData {
    fn try_as_beacon_type(&self) -> Result<AttestationData> {
        Ok(AttestationData {
            slot: self.slot.into(),
            index: self.index as u64,
            beacon_block_root: self.beacon_block_root,
            source: self.source.try_as_beacon_type()?,
            target: self.target.try_as_beacon_type()?,
        })
    }
}

impl TryAsBeaconType<beacon_types::Checkpoint> for ethereum_consensus::electra::Checkpoint {
    fn try_as_beacon_type(&self) -> Result<beacon_types::Checkpoint> {
        Ok(beacon_types::Checkpoint {
            epoch: self.epoch.into(),
            root: self.root,
        })
    }
}

impl TryAsBeaconType<ValidatorInfo> for ethereum_consensus::phase0::Validator {
    fn try_as_beacon_type(&self) -> Result<ValidatorInfo> {
        let pubkey = PublicKey::deserialize(&self.public_key)
            .map_err(|_| anyhow!("failed to deserialize BLS public key"))?;
        Ok(ValidatorInfo {
            pubkey,
            effective_balance: self.effective_balance,
            slashed: self.slashed,
            activation_epoch: self.activation_epoch.into(),
            activation_eligibility_epoch: self.activation_eligibility_epoch.into(),
            exit_epoch: self.exit_epoch.into(),
        })
    }
}

impl TryAsBeaconType<z_core::BeaconBlockHeader> for ethereum_consensus::phase0::BeaconBlockHeader {
    fn try_as_beacon_type(&self) -> Result<z_core::BeaconBlockHeader> {
        Ok(z_core::BeaconBlockHeader {
            slot: self.slot,
            proposer_index: self.proposer_index as u64,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body_root: self.body_root,
        })
    }
}
