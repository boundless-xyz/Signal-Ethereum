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

use crate::serde_utils;
use alloy_primitives::B256;
use serde_with::serde_as;
use std::collections::BTreeMap;

#[serde_as]
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StatePatch {
    pub randao_mixes: BTreeMap<RandaoMixIndex, B256>,
    #[serde_as(as = "BTreeMap<_, serde_utils::U64>")]
    pub validator_exits: BTreeMap<ValidatorIndex, Epoch>,
}

impl StatePatch {
    /// Checks if the validator is active at the given epoch.
    #[inline]
    pub fn is_active_validator(
        &self,
        idx: &ValidatorIndex,
        validator: &ValidatorInfo,
        epoch: Epoch,
    ) -> bool {
        match self.validator_exits.get(idx) {
            Some(exit_epoch) => epoch < *exit_epoch && validator.is_active_at(epoch),
            None => validator.is_active_at(epoch),
        }
    }
}

use crate::{Epoch, RandaoMixIndex, ValidatorIndex, ValidatorInfo};
#[cfg(feature = "host")]
pub use host::StatePatchBuilder;

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::{RandaoMixIndex, StateRef};
    use beacon_types::EthSpec;
    use ethereum_consensus::phase0::Validator;
    use tracing::debug;

    pub struct StatePatchBuilder {
        state: StateRef,
        patch: StatePatch,
    }

    impl StatePatchBuilder {
        pub fn new(state: StateRef) -> Self {
            Self {
                state,
                patch: Default::default(),
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
}
