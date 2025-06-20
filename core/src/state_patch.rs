use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatePatch {
    pub randao_mixes: BTreeMap<RandaoMixIndex, B256>,
    /// For this epoch, any modifications that should be applied to the exit_epoch field of validators
    pub validator_exit_epoch_updates: BTreeMap<ValidatorIndex, Epoch>,
}

use crate::{Epoch, RandaoMixIndex, ValidatorIndex, ValidatorInfo};
#[cfg(feature = "host")]
pub use host::StatePatchBuilder;

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::beacon_state::mainnet::BeaconState;
    use crate::{Ctx, RandaoMixIndex, ValidatorInfo};
    use std::sync::Arc;
    use tracing::debug;

    pub struct StatePatchBuilder<'a, CTX> {
        state: Arc<BeaconState>,
        context: &'a CTX,
        patch: StatePatch,
    }

    impl<'a, CTX> StatePatchBuilder<'a, CTX>
    where
        CTX: Ctx,
    {
        pub fn new(state: Arc<BeaconState>, context: &'a CTX) -> Self {
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

        /// Given a set of validators, find where their exit_epochs differ and append these to the patch
        pub fn validator_exit_diff(&mut self, val: &BTreeMap<ValidatorIndex, ValidatorInfo>) {
            let epoch = self.context.compute_epoch_at_slot(self.state.slot());
            for (idx, unpatched_validator) in self.state.validators().iter().enumerate() {
                let unpatched_validator = ValidatorInfo::from(unpatched_validator);

                // no need to update a validator that is already inactive
                if !is_active_validator(&unpatched_validator, epoch) {
                    continue;
                }

                if let Some(v) = val.get(&idx) {
                    if unpatched_validator.exit_epoch != v.exit_epoch {
                        self.patch
                            .validator_exit_epoch_updates
                            .insert(idx, v.exit_epoch);
                    }
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

/// Check if `validator` is active.
fn is_active_validator(validator: &ValidatorInfo, epoch: Epoch) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch
}
