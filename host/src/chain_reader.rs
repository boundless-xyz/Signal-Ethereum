use ethereum_consensus::{electra::mainnet::SignedBeaconBlockHeader, types::mainnet::BeaconBlock};
use std::fmt::Display;
use z_core::ConsensusState;

/// A trait to abstract reading data from an instance of a beacon chain
/// This could be an RPC to a node or something else (e.g. test harness)
pub trait ChainReader {
    #[allow(async_fn_in_trait)]
    async fn get_block_header(
        &self,
        block_id: impl Display,
    ) -> Result<Option<SignedBeaconBlockHeader>, anyhow::Error>;

    #[allow(async_fn_in_trait)]
    async fn get_block(&self, block_id: impl Display)
    -> Result<Option<BeaconBlock>, anyhow::Error>;

    #[allow(async_fn_in_trait)]
    async fn get_consensus_state(
        &self,
        state_id: impl Display,
    ) -> Result<ConsensusState, anyhow::Error>;
}
