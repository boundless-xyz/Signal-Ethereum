use alloc::string::{String, ToString};
use alloc::vec::Vec;
use blst::BLST_ERROR;
use blst::min_pk as bls;
use serde::{Deserialize, Serialize};

// domain string, must match what is used in signing. This one should be good for beacon chain
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub const BLS_SIGNATURE_BYTES_LEN: usize = 96;

#[derive(Debug)]
pub enum BlsError {
    InvalidSignature,
    Other(String),
}

impl From<BLST_ERROR> for BlsError {
    fn from(value: BLST_ERROR) -> Self {
        assert!(value != BLST_ERROR::BLST_SUCCESS);
        Self::Other(format_args!("{:?}", value).to_string())
    }
}

impl From<String> for BlsError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}
impl core::fmt::Display for BlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlsError::InvalidSignature => write!(f, "Invalid signature"),
            BlsError::Other(err) => write!(f, "BLS error: {}", err),
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct PublicKey(pub bls::PublicKey);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        Ok(PublicKey(bls::PublicKey::from_bytes(bytes).unwrap()))
    }

    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_bytes()
    }
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: PublicKey) -> Self {
        let mut aggkey = bls::AggregatePublicKey::from_public_key(&self.0);
        aggkey.add_public_key(&other.0, false).unwrap();
        Self(aggkey.to_public_key())
    }

    pub fn aggregate(public_keys: &[PublicKey]) -> Result<Self, BlsError> {
        let public_keys = public_keys.iter().map(|k| &k.0).collect::<Vec<_>>();

        let aggkey = bls::AggregatePublicKey::aggregate(&public_keys, false)?;

        Ok(Self(aggkey.to_public_key()))
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Signature(bls::Signature);

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        Ok(Signature(bls::Signature::from_bytes(bytes)?))
    }
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }
}

pub fn verify_signature(
    public_key: &PublicKey,
    msg: &[u8],
    signature: &Signature,
) -> Result<(), BlsError> {
    let res = signature.0.verify(true, msg, DST, &[], &public_key.0, true);
    if res == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(BlsError::InvalidSignature)
    }
}

pub fn fast_aggregate_verify_pre_aggregated(
    public_key: &PublicKey,
    msg: &[u8],
    signature: &Signature,
) -> Result<(), BlsError> {
    let res = signature
        .0
        .fast_aggregate_verify_pre_aggregated(true, msg, DST, &public_key.0);
    if res == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(BlsError::InvalidSignature)
    }
}

pub fn fast_aggregate_verify(
    public_keys: &[PublicKey],
    msg: &[u8],
    signature: &Signature,
) -> Result<(), BlsError> {
    let public_keys = public_keys.iter().map(|k| &k.0).collect::<Vec<_>>();

    let res = signature
        .0
        .fast_aggregate_verify(true, msg, DST, &public_keys);
    if res == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(BlsError::InvalidSignature)
    }
}

// This is verification for the case where multiple messages were signed and an aggregate signature obtained by aggregating the resulting signatures.
// TODO: BLST won't do this out of the box but it should be fairly easy to implement with their lower level operations
pub fn multi_message_verify(
    _messages: &[&[u8]],
    _public_key: &PublicKey,
    _signature: &Signature,
) -> Result<(), BlsError> {
    Ok(())
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();

        serde_arrays::serialize(&bytes, serializer)
    }
}
impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: [u8; BLS_SIGNATURE_BYTES_LEN] = serde_arrays::deserialize(deserializer)?;
        Signature::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use std::ops::Deref;
    impl From<ethereum_consensus::crypto::Signature> for Signature {
        fn from(signature: ethereum_consensus::crypto::Signature) -> Self {
            let bytes = signature.deref().as_ref();
            Signature(bls::Signature::from_bytes(bytes).unwrap())
        }
    }

    impl From<ethereum_consensus::crypto::PublicKey> for PublicKey {
        fn from(public_key: ethereum_consensus::crypto::PublicKey) -> Self {
            let bytes = public_key.deref().as_ref();
            PublicKey(bls::PublicKey::from_bytes(bytes).unwrap())
        }
    }
}
