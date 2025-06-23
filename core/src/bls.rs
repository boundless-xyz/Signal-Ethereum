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

#[inline]
pub fn has_compressed_chunks(pk: &PublicKey, chunk1: &[u8; 32], chunk2: &[u8; 32]) -> bool {
    let public_key_bytes = pk.serialize();

    &public_key_bytes[0..32] == chunk1
        && public_key_bytes[32..48] == chunk2[0..16]
        && chunk2[16..32] == [0u8; 16]
}
