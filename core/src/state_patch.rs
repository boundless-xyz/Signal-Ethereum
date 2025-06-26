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
use crate::{Epoch, RandaoMixIndex, ValidatorIndex, ValidatorInfo, serde_utils};

use alloy_primitives::B256;
use serde_with::serde_as;
use std::collections::BTreeMap;

pub static EMPTY_STATE_PATCH: StatePatch = StatePatch::new();

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StatePatch {
    pub randao_mixes: BTreeMap<RandaoMixIndex, B256>,
    #[serde_as(as = "BTreeMap<_, serde_utils::U64>")]
    pub validator_exits: BTreeMap<ValidatorIndex, Epoch>,
}

impl StatePatch {
    /// Makes a new, empty `StatePatch`.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            randao_mixes: BTreeMap::new(),
            validator_exits: BTreeMap::new(),
        }
    }

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

impl Default for StatePatch {
    fn default() -> Self {
        Self::new()
    }
}
