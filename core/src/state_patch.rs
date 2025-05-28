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
    use crate::{HostContext, ValidatorIndex, ValidatorInfo};
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

        pub fn validator_diff(
            &mut self,
            indices: impl IntoIterator<Item = &'a ValidatorIndex>,
            validators: &BTreeMap<ValidatorIndex, ValidatorInfo>,
        ) {
            for &idx in indices {
                if let Some(validator) = self.state.validators().get(idx) {
                    let validator = ValidatorInfo::from(validator);
                    match validators.get(&idx) {
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
}
