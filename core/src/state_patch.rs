use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatePatch {
    pub randao_mixes: BTreeMap<RandaoMixIndex, B256>,
}

use crate::RandaoMixIndex;
#[cfg(feature = "host")]
pub use host::StatePatchBuilder;

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::beacon_state::mainnet::BeaconState;
    use crate::{Ctx, RandaoMixIndex};
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
