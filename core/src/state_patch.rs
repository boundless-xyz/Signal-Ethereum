use crate::{Ctx, ValidatorIndex, ValidatorInfo};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use ssz_rs::prelude::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatePatch {
    pub randao_mixes: BTreeMap<usize, B256>,
    pub validators: BTreeMap<ValidatorIndex, ValidatorInfo>,
}

#[cfg(feature = "host")]
pub use host::StatePatchBuilder;

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::beacon_state::mainnet::BeaconState;
    use crate::{Epoch, HostContext, ValidatorIndex, ValidatorInfo};
    use ethereum_consensus::altair::Validator;
    use tracing::debug;

    pub struct StatePatchBuilder<'a> {
        state: &'a BeaconState,
        context: &'a HostContext,
        patch: StatePatch,
    }

    impl<'a> StatePatchBuilder<'a> {
        pub fn new(state: &'a BeaconState, context: &'a HostContext) -> Self {
            Self {
                state,
                context,
                patch: Default::default(),
            }
        }

        pub fn randao_mix(&mut self, idx: usize) {
            let randao = self.state.randao_mixes().get(idx).unwrap().clone();
            self.patch
                .randao_mixes
                .insert(idx, B256::from_slice(randao.as_slice()));
        }

        pub fn validator_diff(&mut self, val: &BTreeMap<ValidatorIndex, ValidatorInfo>) {
            let epoch = self.context.compute_epoch_at_slot(self.state.slot());
            for (idx, validator) in self.state.validators().iter().enumerate() {
                if !is_active_validator(validator, epoch) {
                    continue;
                }

                let validator = ValidatorInfo::from(validator);
                match val.get(&idx) {
                    None => {
                        self.patch.validators.insert(idx, validator);
                    }
                    Some(b) => {
                        if b != &validator {
                            self.patch.validators.insert(idx, validator);
                        }
                    }
                }
            }
        }

        pub fn build(self) -> StatePatch {
            debug!(
                "Created patch for epoch {}: #randao_mixes={} #validators={}",
                self.context.compute_epoch_at_slot(self.state.slot()),
                self.patch.randao_mixes.len(),
                self.patch.validators.len()
            );
            self.patch
        }
    }

    /// Check if `validator` is active.
    fn is_active_validator(validator: &Validator, epoch: Epoch) -> bool {
        validator.activation_epoch <= epoch && epoch < validator.exit_epoch
    }
}
