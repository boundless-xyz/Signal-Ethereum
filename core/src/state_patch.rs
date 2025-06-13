use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatePatch {
    pub randao_mixes: BTreeMap<usize, B256>,
}

#[cfg(feature = "host")]
pub use host::StatePatchBuilder;

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::Ctx;
    use crate::beacon_state::mainnet::BeaconState;
    use tracing::debug;

    pub struct StatePatchBuilder<'a, C> {
        state: BeaconState,
        context: &'a C,
        patch: StatePatch,
    }

    impl<'a, C> StatePatchBuilder<'a, C>
    where
        C: Ctx,
    {
        pub fn new(state: BeaconState, context: &'a C) -> Self {
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
