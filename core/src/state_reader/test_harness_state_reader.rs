///
/// A test harness that allows us to write tests using the BeaconChainHarness from sigp/lighthouse
/// and have its data read directly by the verify function
///
use crate::{Epoch, GuestContext, StateReader, ValidatorIndex, ValidatorInfo, Version};
use beacon_chain::{
    BeaconChainError, BeaconChainTypes, StateSkipConfig, test_utils::BeaconChainHarness,
};
use beacon_types::{BeaconState, EthSpec, Validator};
use elsa::FrozenMap;
use thiserror::Error;

pub struct HarnessStateReader<T: BeaconChainTypes> {
    inner: BeaconChainHarness<T>,
    validator_cache: FrozenMap<Epoch, Vec<(ValidatorIndex, ValidatorInfo)>>,
}

impl<T> HarnessStateReader<T>
where
    T: BeaconChainTypes,
{
    fn state_at_epoch(&self, epoch: Epoch) -> Result<BeaconState<T::EthSpec>, BeaconChainError> {
        let slot = epoch * T::EthSpec::slots_per_epoch();
        self.inner
            .chain
            .state_at_slot(slot.into(), StateSkipConfig::WithoutStateRoots)
    }
}

impl<T> From<BeaconChainHarness<T>> for HarnessStateReader<T>
where
    T: BeaconChainTypes,
{
    fn from(inner: BeaconChainHarness<T>) -> Self {
        Self {
            inner,
            validator_cache: FrozenMap::new(),
        }
    }
}

#[derive(Error, Debug)]
pub enum HarnessStateReaderError {
    #[error("yeap")]
    LighthouseError(beacon_chain::BeaconChainError),
}

impl From<beacon_chain::BeaconChainError> for HarnessStateReaderError {
    fn from(err: beacon_chain::BeaconChainError) -> Self {
        HarnessStateReaderError::LighthouseError(err)
    }
}

impl<T> StateReader for HarnessStateReader<T>
where
    T: BeaconChainTypes,
{
    type Error = HarnessStateReaderError;

    type Context = GuestContext;

    fn context(&self) -> &Self::Context {
        &GuestContext
    }

    fn genesis_validators_root(&self) -> alloy_primitives::B256 {
        self.inner.chain.genesis_validators_root
    }

    fn fork_current_version(&self, state_epoch: Epoch) -> Result<Version, Self::Error> {
        let state = self.state_at_epoch(state_epoch)?;
        Ok(state.fork().current_version)
    }

    fn active_validators(
        &self,
        state_epoch: Epoch,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        assert!(state_epoch >= epoch, "Only historical epochs supported");

        let iter = match self.validator_cache.get(&state_epoch) {
            Some(validators) => validators.iter(),
            None => {
                let state = self.state_at_epoch(state_epoch)?;

                let validators: Vec<_> = state
                    .validators()
                    .iter()
                    .enumerate()
                    .filter(move |(_, validator)| is_active_validator(validator, epoch))
                    .map(move |(idx, validator)| (idx, ValidatorInfo::from(validator)))
                    .collect();

                self.validator_cache.insert(state_epoch, validators).iter()
            }
        };
        Ok(iter.map(|(idx, validator)| (*idx, validator)))
    }

    fn randao_mix(
        &self,
        state_epoch: Epoch,
        idx: usize,
    ) -> Result<Option<alloy_primitives::B256>, Self::Error> {
        Ok(self
            .state_at_epoch(state_epoch)?
            .randao_mixes()
            .get(idx)
            .copied())
    }
}

/// Check if `validator` is active.
fn is_active_validator(validator: &Validator, epoch: Epoch) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch.into()
}
