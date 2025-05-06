use serde::{Deserialize, Serialize};
use ssz_rs::prelude::*;
use tracing::trace;

use crate::Ctx;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatePatch {
    pub activations: Vec<u32>,
    pub exits: Vec<u32>,
    pub n_deposits_processed: u32,
    pub randao_next: [u8; 32],
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::beacon_state::mainnet::BeaconState;
    use anyhow::{anyhow, ensure};

    impl StatePatch {
        pub fn patch<C: Ctx>(
            context: &C,
            state_a: &BeaconState,
            state_b: &BeaconState,
        ) -> anyhow::Result<Self> {
            let prev_epoch = context.compute_epoch_at_slot(state_a.slot());
            let epoch = context.compute_epoch_at_slot(state_b.slot());
            ensure!(
                prev_epoch + 1 == epoch,
                "state_b epoch: {} must be one ahead of state_a epoch: {}",
                epoch,
                prev_epoch
            );

            let mut activations = Vec::new();
            let mut exits = Vec::new();
            for (i, validator_at_b) in state_b.validators().iter().enumerate() {
                if validator_at_b.activation_epoch == epoch {
                    activations.push(i as u32);
                }
                if validator_at_b.exit_epoch == epoch {
                    exits.push(i as u32);
                }
            }
            let n_deposits_processed = state_b.validators().len() - state_a.validators().len();
            let randao_index =
                (epoch + context.epochs_per_historical_vector() - context.min_seed_lookahead() - 1)
                    % context.epochs_per_historical_vector();

            let randao_next = state_b
                .randao_mixes()
                .get(randao_index as usize)
                .map(|x| {
                    let mut mix = [0u8; 32];
                    mix.copy_from_slice(x.as_ref());
                    mix
                })
                .ok_or_else(|| anyhow!("randao_next index: {} not found", randao_index))?;

            Ok(Self {
                activations,
                exits,
                n_deposits_processed: n_deposits_processed as u32,
                randao_next,
            })
        }
    }
}

impl StatePatch {
    pub fn validate<C: Ctx>(&self, n_active_validators: u32, context: &C) -> bool {
        let churn_limit = get_validator_churn_limit(n_active_validators, context);
        if (self.activations.len() as u32) > churn_limit || (self.exits.len() as u32) > churn_limit
        {
            trace!("patch activations or exits exceeds churn limit");
            return false;
        }

        if self.n_deposits_processed
            > context.max_deposits() as u32 * (context.slots_per_epoch() as u32)
        {
            trace!("patch n_deposits_processed exceeds max");
            return false;
        }

        true
    }
}
fn get_validator_churn_limit<C: Ctx>(_n_active_validators: u32, _context: &C) -> u32 {
    todo!()
}
