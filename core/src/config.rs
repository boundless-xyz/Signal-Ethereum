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

use crate::Epoch;
use beacon_types::ForkName;

/// ZKasper's internal configuration struct.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub min_version: ForkName,
    pub max_version: ForkName,

    pub epoch_lookahead_limit: Epoch,

    // Defines the threshold for justification:
    // target_balance * justification_threshold_quotient >= total_active_balance * justification_threshold_factor
    pub justification_threshold_factor: u64,
    pub justification_threshold_quotient: u64,
}

/// The default configuration.
pub static DEFAULT_CONFIG: Config = Config {
    min_version: ForkName::Electra,
    max_version: ForkName::Electra,
    epoch_lookahead_limit: Epoch::new(4),
    justification_threshold_factor: 85,
    justification_threshold_quotient: 100,
};

impl Config {
    pub fn is_supported_version(&self, fork_name: ForkName) -> bool {
        self.min_version <= fork_name && fork_name <= self.max_version
    }
}
