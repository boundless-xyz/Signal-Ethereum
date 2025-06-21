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

use crate::{Epoch, Slot};
use alloc::fmt::Debug;

pub use super::guest_context::GuestContext;

pub trait Ctx {
    type Error: Debug;

    fn slots_per_epoch(&self) -> u64;
    fn effective_balance_increment(&self) -> u64;
    fn max_validators_per_committee(&self) -> usize;
    fn max_committees_per_slot(&self) -> usize;

    fn compute_epoch_at_slot(&self, slot: Slot) -> Epoch {
        slot / self.slots_per_epoch()
    }
    fn compute_start_slot_at_epoch(&self, epoch: Epoch) -> Slot {
        epoch * self.slots_per_epoch()
    }
    fn epochs_per_historical_vector(&self) -> u64;
    fn min_seed_lookahead(&self) -> u64;
    fn max_seed_lookahead(&self) -> u64;

    fn shuffle_round_count(&self) -> u64;
    fn target_committee_size(&self) -> u64;
    fn max_deposits(&self) -> usize;
    fn min_activation_balance(&self) -> u64;
}

#[cfg(feature = "host")]
#[derive(Clone)]
#[repr(transparent)]
pub struct HostContext(ethereum_consensus::state_transition::Context);

#[cfg(feature = "host")]
impl From<ethereum_consensus::state_transition::Context> for HostContext {
    fn from(ctx: ethereum_consensus::state_transition::Context) -> Self {
        HostContext(ctx)
    }
}

#[cfg(feature = "host")]
impl Ctx for HostContext {
    type Error = ();

    fn slots_per_epoch(&self) -> u64 {
        self.0.slots_per_epoch
    }

    fn effective_balance_increment(&self) -> u64 {
        self.0.effective_balance_increment
    }

    fn max_validators_per_committee(&self) -> usize {
        self.0.max_validators_per_committee
    }

    fn max_committees_per_slot(&self) -> usize {
        self.0.max_committees_per_slot
    }

    fn epochs_per_historical_vector(&self) -> u64 {
        self.0.epochs_per_historical_vector
    }

    fn min_seed_lookahead(&self) -> u64 {
        self.0.min_seed_lookahead
    }

    fn max_seed_lookahead(&self) -> u64 {
        self.0.max_seed_lookahead
    }

    fn shuffle_round_count(&self) -> u64 {
        self.0.shuffle_round_count
    }

    fn target_committee_size(&self) -> u64 {
        self.0.target_committee_size
    }

    fn max_deposits(&self) -> usize {
        self.0.max_deposits
    }

    fn min_activation_balance(&self) -> u64 {
        self.0.min_activation_balance
    }
}
