//!
//! A test harness that allows us to write tests using the BeaconChainHarness from sigp/lighthouse
//! and have its data read directly by the verify function
//!
//!
use alloy_primitives::B256;
use beacon_chain::{
    BeaconChainError, BeaconChainTypes, StateSkipConfig, WhenSlotSkipped,
    test_utils::BeaconChainHarness,
};
use beacon_types::{BeaconState, EthSpec, Hash256, Validator};
use elsa::FrozenMap;
use std::str::FromStr;
use thiserror::Error;
use z_core::{
    ChainReader, ConsensusState, Epoch, HostContext, StateProvider, StateReader, ValidatorIndex,
    ValidatorInfo, Version, mainnet::BeaconState as ZKBeaconState,
};

pub struct HarnessStateReader<'a, T: BeaconChainTypes> {
    epoch: Epoch,
    inner: &'a BeaconChainHarness<T>,
    validator_cache: FrozenMap<Epoch, Vec<(ValidatorIndex, ValidatorInfo)>>,
    context: HostContext,
}

impl<T> HarnessStateReader<'_, T>
where
    T: BeaconChainTypes,
{
    fn state_at_epoch(&self, epoch: Epoch) -> Result<BeaconState<T::EthSpec>, BeaconChainError> {
        let slot = epoch * T::EthSpec::slots_per_epoch();
        self.inner
            .chain
            .state_at_slot(slot.into(), StateSkipConfig::WithStateRoots)
    }

    pub fn state_by_root(
        &self,
        state_root: &B256,
    ) -> Result<ZKBeaconState, HarnessStateReaderError> {
        let state = self.inner.chain.get_state(state_root, None, true)?;
        Ok(convert_via_json(state).unwrap())
    }
}

impl<'a, T> HarnessStateReader<'a, T>
where
    T: BeaconChainTypes,
{
    pub fn new(harness: &'a BeaconChainHarness<T>, epoch: Epoch) -> Self {
        Self {
            inner: harness,
            epoch,
            validator_cache: FrozenMap::new(),
            context: HostContext::from(ethereum_consensus::state_transition::Context::for_mainnet()),
        }
    }
}

#[derive(Error, Debug)]
pub enum HarnessStateReaderError {
    #[error("BeaconChainError: {0:?}")]
    LighthouseError(beacon_chain::BeaconChainError),
}

impl From<beacon_chain::BeaconChainError> for HarnessStateReaderError {
    fn from(err: beacon_chain::BeaconChainError) -> Self {
        HarnessStateReaderError::LighthouseError(err)
    }
}

impl<T> StateReader for HarnessStateReader<'_, T>
where
    T: BeaconChainTypes,
{
    type Error = HarnessStateReaderError;

    type Context = HostContext;

    fn epoch(&self) -> Epoch {
        self.epoch
    }

    fn context(&self) -> &Self::Context {
        &self.context
    }

    fn genesis_validators_root(&self) -> alloy_primitives::B256 {
        self.inner.chain.genesis_validators_root
    }

    fn fork_current_version(&self) -> Result<Version, Self::Error> {
        let state = self.state_at_epoch(self.epoch)?;
        Ok(state.fork().current_version)
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        let iter = match self.validator_cache.get(&self.epoch) {
            Some(validators) => validators.iter(),
            None => {
                let state = self.state_at_epoch(self.epoch)?;

                let validators: Vec<_> = state
                    .validators()
                    .iter()
                    .enumerate()
                    .filter(move |(_, validator)| is_active_validator(validator, epoch))
                    .map(move |(idx, validator)| (idx, ValidatorInfo::from(validator)))
                    .collect();

                self.validator_cache.insert(self.epoch, validators).iter()
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

impl<T> ChainReader for HarnessStateReader<'_, T>
where
    T: BeaconChainTypes,
{
    async fn get_block_header(
        &self,
        block_id: impl std::fmt::Display,
    ) -> Result<ethereum_consensus::deneb::SignedBeaconBlockHeader, anyhow::Error> {
        let header = match SlotOrRoot::from_str(&block_id.to_string()) {
            Ok(SlotOrRoot::Slot(slot)) => self
                .inner
                .chain
                .block_at_slot(slot.into(), WhenSlotSkipped::None),
            Ok(SlotOrRoot::Root(root)) => self.inner.chain.get_blinded_block(&root),
            Err(e) => return Err(e),
        }
        .unwrap()
        .unwrap()
        .signed_block_header();

        Ok(convert_via_json(header)?)
    }

    async fn get_block(
        &self,
        block_id: impl std::fmt::Display,
    ) -> Result<ethereum_consensus::types::mainnet::BeaconBlock, anyhow::Error> {
        let root = match SlotOrRoot::from_str(&block_id.to_string()) {
            Ok(SlotOrRoot::Slot(slot)) => self
                .inner
                .chain
                .block_root_at_slot(slot.into(), WhenSlotSkipped::None)
                .map_err(|_| anyhow::anyhow!("Failed to get block"))?
                .ok_or(anyhow::anyhow!("Block not found at slot {}", slot))?,
            Ok(SlotOrRoot::Root(root)) => root,
            Err(e) => return Err(e),
        };

        let signed_block = self
            .inner
            .chain
            .get_block(&root)
            .await
            .transpose()
            .ok_or(anyhow::anyhow!("Block not found at root {}", root))?;

        let (block, _) = signed_block
            .map_err(|e| anyhow::anyhow!("Failed retrieving block: {:?}", e))?
            .deconstruct();
        Ok(convert_via_json(block.as_electra().expect("electra only"))?)
    }

    async fn get_consensus_state(
        &self,
        state_id: impl std::fmt::Display,
    ) -> Result<z_core::ConsensusState, anyhow::Error> {
        let state = match SlotOrRoot::from_str(&state_id.to_string()) {
            Ok(SlotOrRoot::Slot(slot)) => {
                if slot > self.inner.chain.head().head_slot().as_u64() {
                    return Err(anyhow::anyhow!(
                        "Requested slot {} is beyond the head slot {}",
                        slot,
                        self.inner.chain.head().head_slot().as_u64()
                    ));
                }
                self.inner
                    .chain
                    .state_at_slot(slot.into(), StateSkipConfig::WithStateRoots)
            }
            Ok(SlotOrRoot::Root(root)) => self
                .inner
                .chain
                .get_state(&root, None, true)
                .transpose()
                .ok_or(anyhow::anyhow!("State not found at root {}", root))?,
            Err(e) => return Err(e),
        }
        .map_err(|e| anyhow::anyhow!("Failed retrieving state: {:?}", e))?;
        Ok(consensus_state_from_state(&state))
    }
}

impl<T> StateProvider for HarnessStateReader<'_, T>
where
    T: BeaconChainTypes,
{
    fn context(&self) -> &HostContext {
        &self.context
    }

    fn get_state_at_slot(&self, slot: u64) -> Result<Option<ZKBeaconState>, anyhow::Error> {
        let state = self
            .inner
            .chain
            .state_at_slot(slot.into(), StateSkipConfig::WithStateRoots)
            .unwrap();
        Ok(Some(convert_via_json(state)?))
    }
}

enum SlotOrRoot {
    Slot(u64),
    Root(Hash256),
}

fn convert_via_json<T, TT>(value: T) -> Result<TT, serde_json::Error>
where
    T: serde::Serialize,
    TT: serde::de::DeserializeOwned,
{
    let json = serde_json::to_value(value)?;
    serde_json::from_value(json)
}

impl FromStr for SlotOrRoot {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(slot) = u64::from_str_radix(s, 10) {
            Ok(SlotOrRoot::Slot(slot))
        } else if let Ok(root) = Hash256::from_str(s) {
            Ok(SlotOrRoot::Root(root))
        } else {
            Err(anyhow::anyhow!(
                "Invalid format. Must be a slot integer or a 0x prefix hash"
            ))
        }
    }
}

pub fn consensus_state_from_state<T: EthSpec>(
    state: &beacon_types::BeaconState<T>,
) -> ConsensusState {
    ConsensusState {
        finalized_checkpoint: z_core::Checkpoint {
            epoch: state.finalized_checkpoint().epoch.into(),
            root: state.finalized_checkpoint().root.clone(),
        },
        current_justified_checkpoint: z_core::Checkpoint {
            epoch: state.current_justified_checkpoint().epoch.into(),
            root: state.current_justified_checkpoint().root.clone(),
        },
        previous_justified_checkpoint: z_core::Checkpoint {
            epoch: state.previous_justified_checkpoint().epoch.into(),
            root: state.previous_justified_checkpoint().root.clone(),
        },
    }
}
