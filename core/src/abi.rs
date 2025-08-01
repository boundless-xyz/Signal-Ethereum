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

use alloy_sol_types::SolValue;

use crate::{ConsensusError, ConsensusState, ensure};

// Defines the Solidity struct layouts for public types
alloy_sol_types::sol! {
    struct Checkpoint {
        uint64 epoch;
        bytes32 root;
    }

    struct State {
        Checkpoint current_justified;
        Checkpoint finalized;
    }

    struct Journal {
        State pre_state;
        State post_state;
        uint64 finalized_slot;
    }
}

// ABI conversions for Checkpoint.
impl From<&crate::Checkpoint> for Checkpoint {
    fn from(value: &crate::Checkpoint) -> Self {
        Self {
            epoch: value.0.epoch.as_u64(),
            root: value.0.root,
        }
    }
}

impl From<Checkpoint> for crate::Checkpoint {
    fn from(checkpoint: Checkpoint) -> Self {
        Self(beacon_types::Checkpoint {
            epoch: crate::Epoch::new(checkpoint.epoch),
            root: checkpoint.root,
        })
    }
}

// ABI conversions for ConsensusState.
impl From<&crate::ConsensusState> for State {
    fn from(value: &crate::ConsensusState) -> Self {
        Self {
            current_justified: (&value.current_justified_checkpoint()).into(),
            finalized: (&value.finalized_checkpoint()).into(),
        }
    }
}

impl TryFrom<State> for crate::ConsensusState {
    type Error = ConsensusError;

    fn try_from(state: State) -> Result<Self, Self::Error> {
        let state = ConsensusState::new(state.current_justified.into(), state.finalized.into());
        ensure!(state.is_valid(), ConsensusError::InvalidState);
        Ok(state)
    }
}

impl Journal {
    pub fn new(
        pre_state: &crate::ConsensusState,
        post_state: &crate::ConsensusState,
        finalized_slot: u64,
    ) -> Self {
        Self {
            pre_state: pre_state.into(),
            post_state: post_state.into(),
            finalized_slot,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.abi_encode()
    }

    pub fn encoded_size(&self) -> usize {
        self.abi_encoded_size()
    }
}
