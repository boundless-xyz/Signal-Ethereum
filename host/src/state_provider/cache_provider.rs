use elsa::FrozenMap;
use std::sync::Arc;
use z_core::{Root, Slot, mainnet::BeaconState};
use z_core::{StateProvider, StateProviderError, StateRef};

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
