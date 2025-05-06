use crate::{Epoch, Slot};
use alloc::fmt::Debug;

use serde::{Deserialize, Serialize};

pub trait Ctx {
    type Error: Debug;

    fn slots_per_epoch(&self) -> u64;
    fn max_validators_per_committee(&self) -> usize;
    fn max_committees_per_slot(&self) -> usize;

    fn compute_epoch_at_slot(&self, slot: Slot) -> Epoch {
        slot / self.slots_per_epoch()
    }
    fn epochs_per_historical_vector(&self) -> u64;
    fn min_seed_lookahead(&self) -> u64;

    fn shuffle_round_count(&self) -> u64;
    fn target_committee_size(&self) -> u64;
    fn max_deposits(&self) -> usize;
}

#[derive(Serialize, Deserialize)]
pub struct GuestContext;

// TODO(ec2): Hardcoded for sepolia
impl Ctx for GuestContext {
    type Error = ();

    fn slots_per_epoch(&self) -> u64 {
        32
    }

    fn max_validators_per_committee(&self) -> usize {
        2048
    }

    fn max_committees_per_slot(&self) -> usize {
        64
    }

    fn epochs_per_historical_vector(&self) -> u64 {
        65536
    }

    fn min_seed_lookahead(&self) -> u64 {
        1
    }

    fn shuffle_round_count(&self) -> u64 {
        90
    }

    fn target_committee_size(&self) -> u64 {
        128
    }

    fn max_deposits(&self) -> usize {
        16
    }
}

#[cfg(feature = "host")]
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

    fn shuffle_round_count(&self) -> u64 {
        self.0.shuffle_round_count
    }

    fn target_committee_size(&self) -> u64 {
        self.0.target_committee_size
    }

    fn max_deposits(&self) -> usize {
        self.0.max_deposits
    }
}
