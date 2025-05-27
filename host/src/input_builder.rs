use std::{collections::BTreeMap, ops::Range};

use ethereum_consensus::{
    electra::mainnet::MAX_VALIDATORS_PER_SLOT,
    phase0::mainnet::{MAX_COMMITTEES_PER_SLOT, SLOTS_PER_EPOCH},
};
use z_core::{Attestation, Checkpoint, ConsensusState, Epoch, Input, Link, Root, Slot};

use crate::beacon_client::{BeaconClient, Error as BeaconNodeError};

#[derive(thiserror::Error, Debug)]
pub enum InputBuilderError {
    #[error("Failed calling beacon API: {0}")]
    BeaconNodeError(#[from] BeaconNodeError),
    #[error("Failed to find enough attestations. Required: {required}")]
    InsufficientAttestations { required: usize },
}

/// Given the current ConsensusState, query a beacon node to build an input that can be
/// used to evolve this state to a new state
pub async fn build_input(
    beacon_client: &BeaconClient,
    consensus_state: ConsensusState,
) -> Result<Input, InputBuilderError> {
    // This block root is an EBB (epoch block boundary) that has been previously finalized
    // and is trusted by the consensus client.
    let trusted_block_root = consensus_state.finalized_checkpoint.root;
    let trusted_block_header = beacon_client.get_block_header(trusted_block_root).await?;
    let trusted_state_root = trusted_block_header.message.state_root;
    // This trusted state is used to root the SSZ proofs of all inputs to verify
    let trusted_beacon_state = beacon_client.get_beacon_state(trusted_state_root).await?;

    let (link, attestations) = get_next_supermajority_link(
        beacon_client,
        &consensus_state,
        32, // We require 32 blocks worth of attestations most likely..
    )
    .await?;

    Ok(Input {
        consensus_state,
        link,
        attestations,
        trusted_checkpoint_state_root: trusted_state_root,
    })
}

/// Search for a supermajority link that can be used to evolve the consensus state.
///
async fn get_next_supermajority_link(
    beacon_client: &BeaconClient,
    consensus_state: &ConsensusState,
    min_attestations: usize,
) -> Result<
    (
        Link,
        Vec<Attestation<MAX_VALIDATORS_PER_SLOT, MAX_COMMITTEES_PER_SLOT>>,
    ),
    InputBuilderError,
> {
    // First search for the simple case, 1-finality
    let source = consensus_state.current_justified_checkpoint;
    let target_epoch = source.epoch + 1;

    // Get attestations for the next epoch
    let attestations = get_grouped_attestations(
        beacon_client,
        ((source.epoch + 1) * SLOTS_PER_EPOCH)..((source.epoch + 3) * SLOTS_PER_EPOCH), // Check the next 2 epochs from the source
        source,
        target_epoch,
    )
    .await?;

    tracing::debug!(
        "Found {} attestations for source {:?} and target epoch {}",
        attestations.iter().map(|(_, a)| a.len()).sum::<usize>(),
        source,
        target_epoch
    );

    attestations
        .iter()
        .find_map(|(_, attestations)| {
            if attestations.len() < min_attestations as usize {
                None
            } else {
                let a = attestations[0].clone();
                Some((
                    Link {
                        source: a.data.source.into(),
                        target: a.data.target.into(),
                    },
                    attestations.clone(),
                ))
            }
        })
        .ok_or(InputBuilderError::InsufficientAttestations {
            required: min_attestations,
        })
}

/// Over a range of slots, query a beacon node for attestations with
///  - The given source checkpoint (root and epoch)
///  - The given target epoch (root is not yet known)
/// and return them grouped by their target root.
async fn get_grouped_attestations(
    beacon_client: &BeaconClient,
    slots: Range<Slot>,
    source: Checkpoint,
    target_epoch: Epoch,
) -> Result<
    BTreeMap<Root, Vec<Attestation<MAX_VALIDATORS_PER_SLOT, MAX_COMMITTEES_PER_SLOT>>>,
    InputBuilderError,
> {
    let mut blocks = Vec::new();
    for slot in slots {
        let block = beacon_client.get_block(slot).await;
        match block {
            Ok(block) => blocks.push(block),
            Err(e) => tracing::warn!("Failed to get block (maybe missed slot) {}: {}", slot, e),
        }
    }

    let attestations = blocks
        .iter()
        .flat_map(|b| match b.body() {
            ethereum_consensus::types::BeaconBlockBodyRef::Electra(body) => {
                body.attestations.iter().cloned().collect::<Vec<_>>()
            }
            _ => unimplemented!("Electra Only!"),
        })
        .filter(|a| a.data.source.epoch == source.epoch && a.data.source.root == source.root)
        .filter(|a| a.data.target.epoch == target_epoch)
        // group remaining attesations by their target root
        .fold(BTreeMap::new(), |mut acc, a| {
            acc.entry(a.data.target.root)
                .or_insert_with(Vec::new)
                .push(a.into());
            acc
        });

    Ok(attestations)
}
