use crate::{Epoch, Slot};
use alloc::fmt::Debug;

use serde::{Deserialize, Serialize};

pub trait Ctx {
    type Error: Debug;

    const TIMELY_SOURCE_WEIGHT: u64 = 14;
    const TIMELY_TARGET_WEIGHT: u64 = 26;
    const TIMELY_HEAD_WEIGHT: u64 = 14;
    const SYNC_REWARD_WEIGHT: u64 = 2;
    const PROPOSER_WEIGHT: u64 = 8;
    const WEIGHT_DENOMINATOR: u64 = 64;

    fn slots_per_epoch(&self) -> u64;
    fn effective_balance_increment(&self) -> u64;
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

    fn max_effective_balance(&self) -> u64;
    fn ejection_balance(&self) -> u64;

    fn base_reward_factor(&self) -> u64;

    fn sync_committee_size(&self) -> usize;

    fn max_attestations(&self) -> usize;

    fn min_per_epoch_churn_limit(&self) -> u64;
    fn max_per_epoch_activation_exit_churn_limit(&self) -> u64;
    fn churn_limit_quotient(&self) -> u64;

    fn min_validator_withdrawability_delay(&self) -> u64;

    fn min_activation_balance(&self) -> u64;

    fn min_epochs_to_inactivity_penalty(&self) -> u64;
}

#[derive(Serialize, Deserialize)]
pub struct GuestContext;

// TODO(ec2): Hardcoded for sepolia/mainnet. They are both the same. Consider a smarter method if we wanna run the spec-tests
impl Ctx for GuestContext {
    type Error = ();

    fn slots_per_epoch(&self) -> u64 {
        32
    }

    fn effective_balance_increment(&self) -> u64 {
        1_000_000_000
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

    fn max_effective_balance(&self) -> u64 {
        2048_000_000_000
    }

    fn ejection_balance(&self) -> u64 {
        16_000_000_000
    }

    fn base_reward_factor(&self) -> u64 {
        64
    }

    fn sync_committee_size(&self) -> usize {
        512
    }

    fn max_attestations(&self) -> usize {
        8
    }

    fn min_per_epoch_churn_limit(&self) -> u64 {
        128_000_000_000
    }

    fn max_per_epoch_activation_exit_churn_limit(&self) -> u64 {
        256_000_000_000
    }

    fn churn_limit_quotient(&self) -> u64 {
        65536
    }

    fn min_validator_withdrawability_delay(&self) -> u64 {
        256
    }

    fn min_activation_balance(&self) -> u64 {
        32_000_000_000
    }

    fn min_epochs_to_inactivity_penalty(&self) -> u64 {
        4
    }
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

    fn shuffle_round_count(&self) -> u64 {
        self.0.shuffle_round_count
    }

    fn target_committee_size(&self) -> u64 {
        self.0.target_committee_size
    }

    fn max_deposits(&self) -> usize {
        self.0.max_deposits
    }

    fn max_effective_balance(&self) -> u64 {
        self.0.max_effective_balance_electra
    }

    fn ejection_balance(&self) -> u64 {
        self.0.ejection_balance
    }

    fn base_reward_factor(&self) -> u64 {
        self.0.base_reward_factor
    }

    fn sync_committee_size(&self) -> usize {
        self.0.sync_committee_size
    }

    fn max_attestations(&self) -> usize {
        self.0.max_attestations_electra
    }

    fn min_per_epoch_churn_limit(&self) -> u64 {
        self.0.min_per_epoch_churn_limit_electra
    }

    fn max_per_epoch_activation_exit_churn_limit(&self) -> u64 {
        self.0.max_per_epoch_activation_exit_churn_limit
    }

    fn churn_limit_quotient(&self) -> u64 {
        self.0.churn_limit_quotient
    }

    fn min_validator_withdrawability_delay(&self) -> u64 {
        self.0.min_validator_withdrawability_delay
    }

    fn min_activation_balance(&self) -> u64 {
        self.0.min_activation_balance
    }

    fn min_epochs_to_inactivity_penalty(&self) -> u64 {
        self.0.min_epochs_to_inactivity_penalty
    }
}
