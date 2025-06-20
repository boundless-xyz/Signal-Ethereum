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
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatePatch {
    pub randao_mixes: BTreeMap<RandaoMixIndex, B256>,
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
    use crate::{Ctx, RandaoMixIndex, StateRef};
    use ethereum_consensus::phase0::Validator;
    use tracing::debug;

    pub struct StatePatchBuilder<'a, CTX> {
        state: StateRef,
        context: &'a CTX,
        patch: StatePatch,
    }

    impl<'a, CTX> StatePatchBuilder<'a, CTX>
    where
        CTX: Ctx,
    {
        pub fn new(state: StateRef, context: &'a CTX) -> Self {
            Self {
                state,
                context,
                patch: Default::default(),
            }
        }

        pub fn randao_mix(&mut self, idx: RandaoMixIndex) {
            let randao = self.state.randao_mixes().get(idx as usize).unwrap().clone();
            self.patch
                .randao_mixes
                .insert(idx, B256::from_slice(randao.as_slice()));
        }

        pub fn validator_diff(&mut self, validators: impl IntoIterator<Item = &'a Validator>) {
            for (idx, (a, b)) in self.state.validators().iter().zip(validators).enumerate() {
                // store validator exits
                if a.exit_epoch != b.exit_epoch {
                    self.patch.validator_exits.insert(idx, a.exit_epoch);
                }
            }
        }

        pub fn build(self) -> StatePatch {
            debug!(
                "Created patch for epoch {}: #randao_mixes={}",
                self.context.compute_epoch_at_slot(self.state.slot()),
                self.patch.randao_mixes.len(),
            );
            self.patch
        }
    }
}
