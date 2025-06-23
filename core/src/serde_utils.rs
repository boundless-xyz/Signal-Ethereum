use crate::{Epoch, Slot};
use bls::{PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN, PublicKey};
use serde::{Deserialize, Deserializer, Serializer};
use serde_with::{DeserializeAs, SerializeAs};

pub struct UncompressedPublicKey;

impl SerializeAs<PublicKey> for UncompressedPublicKey {
    #[inline]
    fn serialize_as<S>(pk: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
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

pub struct U64;

impl SerializeAs<Epoch> for U64 {
    #[inline]
    fn serialize_as<S>(source: &Epoch, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(source.as_u64())
    }
}

impl<'de> DeserializeAs<'de, Epoch> for U64 {
    #[inline]
    fn deserialize_as<D>(deserializer: D) -> Result<Epoch, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Epoch::new(u64::deserialize(deserializer)?))
    }
}

impl SerializeAs<Slot> for U64 {
    #[inline]
    fn serialize_as<S>(source: &Slot, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(source.as_u64())
    }
}

impl<'de> DeserializeAs<'de, Slot> for U64 {
    #[inline]
    fn deserialize_as<D>(deserializer: D) -> Result<Slot, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Slot::new(u64::deserialize(deserializer)?))
    }
}
