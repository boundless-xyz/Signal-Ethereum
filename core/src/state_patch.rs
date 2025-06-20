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
    use crate::{RandaoMixIndex, Slot, StateRef};
    use beacon_types::EthSpec;
    use tracing::debug;

    pub struct StatePatchBuilder {
        state: StateRef,
        patch: StatePatch,
    }

    impl StatePatchBuilder {
        pub fn new(state: StateRef) -> Self {
            Self {
                state,
                patch: Default::default(),
            }
        }

        pub fn randao_mix(&mut self, idx: RandaoMixIndex) {
            let randao = self.state.randao_mixes().get(idx as usize).unwrap().clone();
            self.patch
                .randao_mixes
                .insert(idx, B256::from_slice(randao.as_slice()));
        }

        pub fn build<E: EthSpec>(self) -> StatePatch {
            debug!(
                "Created patch for epoch {}: #randao_mixes={}",
                Slot::from(self.state.slot()).epoch(E::slots_per_epoch()),
                self.patch.randao_mixes.len(),
            );
            self.patch
        }
    }
}
