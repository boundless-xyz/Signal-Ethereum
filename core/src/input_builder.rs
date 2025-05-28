use crate::{Attestation, ConsensusState, Input, Link, Slot};
use ethereum_consensus::{
    electra::mainnet::{BeaconBlockHeader, MAX_VALIDATORS_PER_SLOT, SignedBeaconBlockHeader},
    phase0::mainnet::MAX_COMMITTEES_PER_SLOT,
    types::mainnet::BeaconBlock,
};
use futures::stream::{self, StreamExt};
use std::fmt::Display;
use tracing::{debug, info};

/// A trait to abstract reading data from an instance of a beacon chain
/// This could be an RPC to a node or something else (e.g. test harness)
pub trait ChainReader {
    #[allow(async_fn_in_trait)]
    async fn get_block_header(
        &self,
        block_id: impl Display,
    ) -> Result<SignedBeaconBlockHeader, anyhow::Error>;

    #[allow(async_fn_in_trait)]
    async fn get_block(&self, block_id: impl Display) -> Result<BeaconBlock, anyhow::Error>;

    #[allow(async_fn_in_trait)]
    async fn get_consensus_state(
        &self,
        state_id: impl Display,
    ) -> Result<ConsensusState, anyhow::Error>;
}

#[derive(thiserror::Error, Debug)]
pub enum InputBuilderError {
    #[error("Failed to find enough attestations. Required: {required}")]
    InsufficientAttestations { required: usize },
    #[error("Failed to find a supermajority link")]
    FailedToFindLink,
    #[error("Chain reader error: {0}")]
    ChainReader(#[from] anyhow::Error),
}

/// Given the current ConsensusState, query a beacon node to build an input that can be
/// used to evolve this state to a new state in the "best" way possible
pub async fn build_input<CR: ChainReader>(
    chain_reader: &CR,
    consensus_state: ConsensusState,
) -> Result<Input, InputBuilderError> {
    let trusted_block_root = consensus_state.finalized_checkpoint.root;
    let trusted_block_header = chain_reader.get_block_header(trusted_block_root).await?;
    let trusted_state_root = trusted_block_header.message.state_root;

    let (states, start_slot, end_slot) = get_next_finalization(
        chain_reader,
        &trusted_block_header.message,
        &consensus_state,
    )
    .await?;
    info!("Consensus States: {:#?}", states);

    // We now have a list of at least 2 consensus states (one being the initial one).
    // We now need to compute the links that take us from the first state to the finalized one.
    let links = generate_links(&states)?;
    info!("Links: {:#?}", links);

    let links_and_attestations =
        collect_attestations_for_links(chain_reader, &links, start_slot, end_slot).await?;
    panic!("PANIC");

    for (link, attestations) in links_and_attestations.iter() {
        debug!("Link: {:?}, Attestations: {}", link, attestations.len());
    }

    // TODO(ec2): Make this work for when we have multiple links
    let (link, attestations) = links_and_attestations[0].clone();

    Ok(Input {
        consensus_state,
        link,
        attestations,
        trusted_checkpoint_state_root: trusted_state_root,
    })
}

/// Starting at the trusted block header and the consensus state in which it is finalized,
/// find the chain of consensus states that lead to the next finalized state. Also returns
/// a start and end slot hints of where to find their attestations.
async fn get_next_finalization<CR: ChainReader>(
    chain_reader: &CR,
    trusted_block_header: &BeaconBlockHeader,
    consensus_state: &ConsensusState,
) -> Result<(Vec<ConsensusState>, Slot, Slot), InputBuilderError> {
    let start_slot = trusted_block_header.slot;
    let mut states = vec![consensus_state.clone()];

    // I think technically we can start from a later slot, but its ok this should still work.
    // We might just be doing more work than necessary, but this is the host.
    let mut slot = start_slot;

    // Iterate over the chain from the trusted slot to find where the consensus state changes saving each one until
    // we find a new finality event.
    // TODO(ec2): Should limit this maybe... Theoretically can go for a long time if chain is inactive
    loop {
        slot += 1;
        let curr_consensus_state = states.last().unwrap().clone();

        let next_consensus_state = chain_reader
            .get_consensus_state(slot)
            .await
            .map_err(InputBuilderError::ChainReader)?;

        // Found the next consensus state
        if curr_consensus_state != next_consensus_state {
            // There can be the case where the the consensus state changes, but there is no new justification or finalization,
            // so we can skip it.
            if curr_consensus_state.previous_justified_checkpoint.epoch
                < next_consensus_state.previous_justified_checkpoint.epoch
                || curr_consensus_state.current_justified_checkpoint.epoch
                    < next_consensus_state.current_justified_checkpoint.epoch
            {
                states.push(next_consensus_state.clone());
                // New finality event
                if curr_consensus_state.finalized_checkpoint
                    != next_consensus_state.finalized_checkpoint
                {
                    break;
                }
            }
        }
    }

    Ok((states, start_slot, slot))
}

/// Gathers the attestations for links, looking at block in the range [start_slot, end_slot].
async fn collect_attestations_for_links(
    chain_reader: &impl ChainReader,
    links: &[Link],
    start_slot: Slot,
    end_slot: Slot,
) -> Result<
    Vec<(
        Link,
        Vec<Attestation<MAX_VALIDATORS_PER_SLOT, MAX_COMMITTEES_PER_SLOT>>,
    )>,
    InputBuilderError,
> {
    let blocks = stream::iter(start_slot..=end_slot)
        .filter_map(async |slot| {
            let block = chain_reader.get_block(slot).await;
            match block {
                Ok(block) => Some(block),
                Err(e) => {
                    tracing::warn!("Failed to get block (maybe a missed slot?) {}: {}", slot, e);
                    None
                }
            }
        })
        .collect::<Vec<_>>()
        .await;

    let all_attestations = blocks
        .iter()
        .flat_map(|b| match b.body() {
            ethereum_consensus::types::BeaconBlockBodyRef::Electra(body) => {
                body.attestations.iter().cloned().collect::<Vec<_>>()
            }
            _ => unimplemented!("Electra Only!"),
        })
        .collect::<Vec<_>>();

    let mut result = Vec::new();

    // group attestations with their links
    for link in links {
        let matching_attestations = all_attestations
            .iter()
            .filter(|attestation| {
                attestation.data.source.root == link.source.root
                    && attestation.data.target.epoch == link.target.epoch
            })
            .cloned()
            .map(Into::into)
            .collect::<Vec<_>>();

        result.push((link.clone(), matching_attestations));
    }
    Ok(result)
}

// Given a list of consensus states, generate the links that can be used to evolve the state
// to the next finalized state. This assumes the states are sorted
fn generate_links(states: &[ConsensusState]) -> Result<Vec<Link>, InputBuilderError> {
    let mut links = Vec::new();

    assert!(
        states.len() >= 2,
        "Must have at least 2 states to create links"
    );
    // check that all except the last state have the same finalized checkpoint
    let finalized_checkpoint = &states[0].finalized_checkpoint;
    for state in &states[1..states.len() - 1] {
        if state.finalized_checkpoint != *finalized_checkpoint {
            return Err(InputBuilderError::FailedToFindLink);
        }
    }

    // TODO(ec2): This is still not exactly correct. Only for 1 finality right now. Will fix.
    for i in 0..states.len() {
        let prev_state = &states[i];
        let curr_state = &states[i + 1];

        // This is the end case
        if curr_state.finalized_checkpoint == prev_state.current_justified_checkpoint
            || curr_state.finalized_checkpoint == prev_state.previous_justified_checkpoint
        {
            assert!(
                i == states.len() - 1,
                "Last state must be the finalized one"
            );
            links.push(Link {
                source: curr_state.finalized_checkpoint.into(),
                target: curr_state.current_justified_checkpoint.into(),
            });
            break;
        }

        // This is the case where we dont have any justification
        if curr_state.current_justified_checkpoint == prev_state.current_justified_checkpoint
            || curr_state.current_justified_checkpoint == prev_state.previous_justified_checkpoint
        {
            continue;
        }

        links.push(Link {
            source: prev_state.current_justified_checkpoint.into(),
            target: curr_state.current_justified_checkpoint.into(),
        });
    }

    assert!(
        !links.is_empty(),
        "Must have at least one link to evolve the state"
    );
    Ok(links)
}
