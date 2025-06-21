use beacon_types::PublicKey;

#[inline]
pub fn has_compressed_chunks(pk: &PublicKey, chunk1: &[u8; 32], chunk2: &[u8; 32]) -> bool {
    let public_key_bytes = pk.serialize();

    &public_key_bytes[0..32] == chunk1
        && public_key_bytes[32..48] == chunk2[0..16]
        && chunk2[16..32] == [0u8; 16]
}
pub(crate) mod pubkey {
    use super::*;
    pub fn serialize<S>(public_key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = public_key.serialize_uncompressed();
        serde_arrays::serialize(&bytes, serializer)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: [u8; 96] = serde_arrays::deserialize(deserializer)?;
        Ok(PublicKey::deserialize_uncompressed(&bytes).unwrap())
    }
}
