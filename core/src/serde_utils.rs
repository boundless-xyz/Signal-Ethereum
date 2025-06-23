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

use crate::{Epoch, Slot};
use beacon_types::EthSpec;
use bls::{PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN, PublicKey};
use serde::{Deserialize, Deserializer, Serializer};
use serde_with::{DeserializeAs, SerializeAs};
use ssz::{Decode, Encode};

pub struct UncompressedPublicKey;

impl SerializeAs<PublicKey> for UncompressedPublicKey {
    #[inline]
    fn serialize_as<S: Serializer>(pk: &PublicKey, serializer: S) -> Result<S::Ok, S::Error> {
        let raw: [u8; PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN] = pk.serialize_uncompressed();
        // delegate to serde_arrays to emit a fixed-length array
        serde_arrays::serialize(&raw, serializer)
    }
}

impl<'de> DeserializeAs<'de, PublicKey> for UncompressedPublicKey {
    #[inline]
    fn deserialize_as<D: Deserializer<'de>>(deserializer: D) -> Result<PublicKey, D::Error> {
        let raw: [u8; PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN] = serde_arrays::deserialize(deserializer)?;
        PublicKey::deserialize_uncompressed(&raw)
            .map_err(|err| serde::de::Error::custom(format!("{:?}", err)))
    }
}

pub struct U64;

impl SerializeAs<Epoch> for U64 {
    #[inline]
    fn serialize_as<S: Serializer>(source: &Epoch, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(source.as_u64())
    }
}

impl<'de> DeserializeAs<'de, Epoch> for U64 {
    #[inline]
    fn deserialize_as<D: Deserializer<'de>>(deserializer: D) -> Result<Epoch, D::Error> {
        Ok(Epoch::new(u64::deserialize(deserializer)?))
    }
}

impl SerializeAs<Slot> for U64 {
    #[inline]
    fn serialize_as<S: Serializer>(source: &Slot, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(source.as_u64())
    }
}

impl<'de> DeserializeAs<'de, Slot> for U64 {
    #[inline]
    fn deserialize_as<D: Deserializer<'de>>(deserializer: D) -> Result<Slot, D::Error> {
        Ok(Slot::new(u64::deserialize(deserializer)?))
    }
}

pub struct DiskAttestation;
impl<E: EthSpec> SerializeAs<beacon_types::Attestation<E>> for DiskAttestation {
    #[inline]
    fn serialize_as<S: Serializer>(
        source: &beacon_types::Attestation<E>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let source = beacon_types::attestation::AttestationRefOnDisk::<E>::from(source.to_ref());
        let bytes = source.as_ssz_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, E: EthSpec> DeserializeAs<'de, beacon_types::Attestation<E>> for DiskAttestation {
    #[inline]
    fn deserialize_as<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<beacon_types::Attestation<E>, D::Error> {
        let bytes = serde_with::Bytes::deserialize_as(deserializer)?;
        Ok(
            beacon_types::attestation::AttestationOnDisk::<E>::from_ssz_bytes(bytes)
                .map_err(|err| serde::de::Error::custom(format!("{:?}", err)))?
                .into(),
        )
    }
}
