use std::marker::PhantomData;

use ethereum_consensus::types::mainnet::BeaconBlock;
use ssz_rs::HashTreeRoot;
use tokio::runtime::Handle;
use tree_hash::TreeHash;
use z_core::{AttestationInclusionVerifier, EthSpec};

use crate::ChainReader;

#[derive(thiserror::Error, Debug)]
pub enum AttestationInclusionVerifierError {}
pub struct HostAttestationInclusionVerifier<CR, E> {
    chain_reader: CR,
    _phantom: PhantomData<E>,
}

impl<CR: ChainReader, E: EthSpec> AttestationInclusionVerifier
    for HostAttestationInclusionVerifier<CR, E>
{
    type Error = anyhow::Error;
    type Spec = E;

    fn verify_inclusion(
        &self,
        attestation: &z_core::LocatedAttestation<Self::Spec>,
    ) -> Result<bool, Self::Error> {
        let block: BeaconBlock = tokio::task::block_in_place(|| {
            Handle::current().block_on(self.chain_reader.get_block(attestation.slot.to_string()))
        })?
        .ok_or(anyhow::anyhow!(
            "Failed to get block for attestation at slot {}",
            attestation.slot
        ))?;

        let block_attestation_root = block
            .body()
            .electra()
            .unwrap()
            .attestations
            .get(attestation.attestation_index as usize)
            .unwrap()
            .hash_tree_root()?;

        Ok(block_attestation_root == attestation.inner.tree_hash_root())
    }
}
