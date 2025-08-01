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
