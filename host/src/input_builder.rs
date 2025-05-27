use ethereum_consensus::{
    electra::mainnet::MAX_VALIDATORS_PER_SLOT,
    phase0::mainnet::{MAX_COMMITTEES_PER_SLOT, SLOTS_PER_EPOCH},
};
use std::{collections::BTreeMap, ops::Range};
use z_core::{Attestation, Checkpoint, ConsensusState, Epoch, Input, Link, Root, Slot};

use crate::beacon_client::{BeaconClient, Error as BeaconNodeError};

#[derive(thiserror::Error, Debug)]
pub enum InputBuilderError {
    #[error("Failed calling beacon API: {0}")]
    BeaconNodeError(#[from] BeaconNodeError),
    #[error("Failed to find enough attestations. Required: {required}")]
    InsufficientAttestations { required: usize },
    #[error("Failed to find a supermajority link")]
    FailedToFindLink,
}

/// Given the current ConsensusState, query a beacon node to build an input that can be
/// used to evolve this state to a new state in the "best" way possible
pub async fn build_input(
    beacon_client: &BeaconClient,
    consensus_state: ConsensusState,
) -> Result<Input, InputBuilderError> {
    let trusted_block_root = consensus_state.finalized_checkpoint.root;
    let trusted_block_header = beacon_client.get_block_header(trusted_block_root).await?;
    let trusted_state_root = trusted_block_header.message.state_root;

    let (link, attestations) = find_next_supermajoriy_link(
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
/// This is trivial most of the time but also must be able to handle tricky edge cases.
///
/// The most basic case will be to find enough attestations to support a link from the
/// state current_justified_checkpoint to a checkpoint in the very next epoch (1-finality).
///
/// Failing this it should look for one from `previous_justified_checkpoint` to `current_justified_checkpoint.epoch` + 1 (2-finality)
///
/// Failing this there are some other non-finalizing cases. CURRENTLY NOT IMPLEMENTED
async fn find_next_supermajoriy_link(
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
    // 1-finality case
    let source = consensus_state.current_justified_checkpoint;
    let target_epoch = source.epoch + 1;

    if let Some(res) = find_supermajority_link(
        beacon_client,
        source,
        target_epoch,
        (target_epoch * SLOTS_PER_EPOCH)..((target_epoch + 3) * SLOTS_PER_EPOCH), // Check the next 2 epochs from the target
        min_attestations,
    )
    .await?
    {
        tracing::info!("Found a 1-finality link: {:?}", res.0);
        return Ok(res);
    }

    // 2-finality case
    let source = consensus_state.previous_justified_checkpoint;
    let target_epoch = source.epoch + 2;

    if let Some(res) = find_supermajority_link(
        beacon_client,
        source,
        target_epoch,
        (target_epoch * SLOTS_PER_EPOCH)..((target_epoch + 3) * SLOTS_PER_EPOCH), // Check the next 2 epochs from the target
        min_attestations,
    )
    .await?
    {
        tracing::info!("Found a 2-finality link: {:?}", res.0);
        return Ok(res);
    }

    Err(InputBuilderError::FailedToFindLink)
}

/// Find a supermajorty link and its attestations with the given source checkpoint and target epoch.
/// Returns `None` if not enough attestations are found.
async fn find_supermajority_link(
    beacon_client: &BeaconClient,
    source: Checkpoint,
    target_epoch: Epoch,
    slots: Range<Slot>,
    min_attestations: usize,
) -> Result<
    Option<(
        Link,
        Vec<Attestation<MAX_VALIDATORS_PER_SLOT, MAX_COMMITTEES_PER_SLOT>>,
    )>,
    InputBuilderError,
> {
    // Get attestations for the next epoch
    let attestations = get_grouped_attestations(beacon_client, slots, source, target_epoch).await?;

    Ok(attestations.iter().find_map(|(_, attestations)| {
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
    }))
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
            Err(e) => tracing::warn!("Failed to get block (maybe a missed slot?) {}: {}", slot, e),
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
        // group remaining attestations by their target root
        .fold(BTreeMap::new(), |mut acc, a| {
            acc.entry(a.data.target.root)
                .or_insert_with(Vec::new)
                .push(a.into());
            acc
        });

    Ok(attestations)
}
