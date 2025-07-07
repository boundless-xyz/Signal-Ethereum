use std::fmt::{Debug, Display};

use beacon_types::EthSpec;

use crate::LocatedAttestation;

pub trait AttestationInclusionVerifier {
    type Error: Display + Debug;
    type Spec: EthSpec;

    /// Verifies that the given `attestation` is included known blocks
    ///
    /// Returns `true` if the attestation is included, `false` otherwise.
    fn verify_inclusion(
        &self,
        attestation: &LocatedAttestation<Self::Spec>,
    ) -> Result<bool, Self::Error>;
}

/// A dummy implementation of `AttestationInclusionVerifier` that always returns `true`.
/// This can be used if checking for attestation inclusion is not required or desired.
pub struct DummyAttestationInclusionVerifier<E: EthSpec> {
    _phantom: std::marker::PhantomData<E>,
}

impl<E: EthSpec> DummyAttestationInclusionVerifier<E> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<E: EthSpec> AttestationInclusionVerifier for DummyAttestationInclusionVerifier<E> {
    type Error = anyhow::Error;
    type Spec = E;

    fn verify_inclusion(
        &self,
        _attestation: &LocatedAttestation<Self::Spec>,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
