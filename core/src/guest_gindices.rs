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

// Beacon block indices
pub const fn state_root_gindex() -> u64 {
    11u64
}

// Beacon state indices
pub const fn slot_gindex() -> u64 {
    66u64
}
pub const fn genesis_validators_root_gindex() -> u64 {
    65u64
}
pub const fn fork_previous_version_gindex() -> u64 {
    268u64
}
pub const fn fork_current_version_gindex() -> u64 {
    269u64
}
pub const fn fork_epoch_gindex() -> u64 {
    270u64
}
pub const fn validators_gindex() -> u64 {
    75u64
}
pub const fn finalized_checkpoint_epoch_gindex() -> u64 {
    168u64
}
pub const fn earliest_exit_epoch_gindex() -> u64 {
    95u64
}
pub const fn earliest_consolidation_epoch_gindex() -> u64 {
    97u64
}
