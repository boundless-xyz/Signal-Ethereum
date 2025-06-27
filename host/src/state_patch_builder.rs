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

use alloy_primitives::B256;
use z_core::{RandaoMixIndex, StatePatch};

use std::sync::Arc;

use crate::beacon_state::mainnet::BeaconState;
use beacon_types::EthSpec;
use ethereum_consensus::phase0::Validator;
use tracing::debug;

type StateRef = Arc<BeaconState>;

pub struct StatePatchBuilder {
    state: StateRef,
    patch: StatePatch,
}

impl StatePatchBuilder {
    pub fn new(state: StateRef) -> Self {
        Self {
            state,
            patch: StatePatch::new(),
        }
    }

    pub fn randao_mix(&mut self, idx: RandaoMixIndex) {
        let randao = self.state.randao_mixes().get(idx as usize).unwrap().clone();
        self.patch
            .randao_mixes
            .insert(idx, B256::from_slice(randao.as_slice()));
    }

    pub fn validator_diff<'a>(&mut self, validators: impl IntoIterator<Item = &'a Validator>) {
        for (idx, (a, b)) in self.state.validators().iter().zip(validators).enumerate() {
            // store validator exits
            if a.exit_epoch != b.exit_epoch {
                self.patch.validator_exits.insert(idx, a.exit_epoch.into());
            }
        }
    }

    pub fn build<E: EthSpec>(self) -> StatePatch {
        debug!(
            epoch = self.state.slot() * E::slots_per_epoch(),
            randao_mixes = self.patch.randao_mixes.len(),
            validator_exits = self.patch.validator_exits.len(),
            "Created state patch",
        );
        self.patch
    }
}
