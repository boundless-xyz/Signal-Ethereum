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

use crate::beacon_state::mainnet::BeaconState;
use crate::state_provider::{StateProvider, StateProviderError, StateRef};
use elsa::FrozenMap;
use std::sync::Arc;
use z_core::{Root, Slot};

#[derive(Clone)]
pub struct CacheStateProvider<P> {
    inner: P,
    cache: FrozenMap<Slot, Arc<BeaconState>>,
}

impl<P> CacheStateProvider<P> {
    pub fn new(provider: P) -> Self {
        Self {
            inner: provider,
            cache: FrozenMap::new(),
        }
    }

    #[inline]
    pub fn inner(&self) -> &P {
        &self.inner
    }
}

impl<P: StateProvider> StateProvider for CacheStateProvider<P> {
    type Spec = P::Spec;
    fn genesis_validators_root(&self) -> Result<Root, StateProviderError> {
        let cache = self.cache.clone().into_map();
        match cache.values().next() {
            Some(state) => Ok(state.genesis_validators_root()),
            None => Ok(self.state_at_slot(0u64.into())?.genesis_validators_root()),
        }
    }

    fn state_at_slot(&self, slot: Slot) -> Result<StateRef, StateProviderError> {
        match self.cache.map_get(&slot, Clone::clone) {
            None => {
                let state = self.inner.state_at_slot(slot)?;
                self.cache.insert(slot, state.clone());
                Ok(state)
            }
            Some(beacon_state) => Ok(beacon_state),
        }
    }
}
