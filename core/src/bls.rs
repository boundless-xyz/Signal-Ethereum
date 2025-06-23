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

use beacon_types::PublicKey;
use bls::PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN;
use serde_with::{DeserializeAs, SerializeAs};

#[inline]
pub fn has_compressed_chunks(pk: &PublicKey, chunk1: &[u8; 32], chunk2: &[u8; 32]) -> bool {
    let public_key_bytes = pk.serialize();

    &public_key_bytes[0..32] == chunk1
        && public_key_bytes[32..48] == chunk2[0..16]
        && chunk2[16..32] == [0u8; 16]
}

pub struct UncompressedPublicKey;

impl SerializeAs<PublicKey> for UncompressedPublicKey {
    #[inline]
    fn serialize_as<S>(pk: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let raw: [u8; PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN] = pk.serialize_uncompressed();
        // delegate to serde_arrays to emit a fixed-length array
        serde_arrays::serialize(&raw, serializer)
    }
}

impl<'de> DeserializeAs<'de, PublicKey> for UncompressedPublicKey {
    #[inline]
    fn deserialize_as<D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw: [u8; PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN] = serde_arrays::deserialize(deserializer)?;
        PublicKey::deserialize_uncompressed(&raw)
            .map_err(|err| serde::de::Error::custom(format!("{:?}", err)))
    }
}
