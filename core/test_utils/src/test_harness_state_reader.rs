//!
//! A test harness that allows us to write tests using the BeaconChainHarness from sigp/lighthouse
//! and have its data read directly by the verify function
//!
//!

use anyhow::anyhow;
use beacon_chain::{
    BeaconChainTypes, StateSkipConfig, WhenSlotSkipped, test_utils::BeaconChainHarness,
};
use beacon_types::{EthSpec, Hash256};
use ethereum_consensus::electra;
use ethereum_consensus::phase0::SignedBeaconBlockHeader;
use ethereum_consensus::types::mainnet::BeaconBlock;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::sync::LazyLock;
use tracing::trace;
use z_core::{
    ChainReader, ConsensusState, HostContext, Root, Slot, StateProvider, StateProviderError,
    StateRef,
};

static CONTEXT: LazyLock<HostContext> = LazyLock::new(|| electra::Context::for_mainnet().into());

pub struct TestHarness<T: BeaconChainTypes>(BeaconChainHarness<T>);

impl<T: BeaconChainTypes> Deref for TestHarness<T> {
    type Target = BeaconChainHarness<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: BeaconChainTypes> DerefMut for TestHarness<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: BeaconChainTypes> From<BeaconChainHarness<T>> for TestHarness<T> {
    fn from(value: BeaconChainHarness<T>) -> Self {
        Self(value)
    }
}

impl<T: BeaconChainTypes> StateProvider for &TestHarness<T> {
    fn context(&self) -> &HostContext {
        &CONTEXT
    }

    fn genesis_validators_root(&self) -> Result<Root, StateProviderError> {
        Ok(self.0.chain.genesis_validators_root)
    }

    fn state_at_slot(&self, slot: Slot) -> Result<StateRef, StateProviderError> {
        let state = self
            .0
            .chain
            .state_at_slot(slot.into(), StateSkipConfig::WithStateRoots)
            .map_err(|e| anyhow!("Failed to get state: {:?}", e))?;
        Ok(convert_via_json(state).unwrap())
    }
}

impl<T: BeaconChainTypes> ChainReader for &TestHarness<T> {
    async fn get_block_header(
        &self,
        block_id: impl std::fmt::Display,
    ) -> Result<Option<SignedBeaconBlockHeader>, anyhow::Error> {
        trace!("ChainReader:get_block_header({})", block_id);
        let block = match SlotOrRoot::from_str(&block_id.to_string())? {
            SlotOrRoot::Slot(slot) => self
                .0
                .chain
                .block_at_slot(slot.into(), WhenSlotSkipped::None),
            SlotOrRoot::Root(root) => self.0.chain.get_blinded_block(&root),
        }
        .map_err(|err| anyhow::anyhow!("Failed to get block: {:?}", err))?;

        match block {
            Some(block) => Ok(convert_via_json(&block.signed_block_header())?),
            None => Ok(None),
        }
    }

    async fn get_block(
        &self,
        block_id: impl std::fmt::Display,
    ) -> Result<Option<BeaconBlock>, anyhow::Error> {
        trace!("ChainReader:get_block({})", block_id);
        let root = match SlotOrRoot::from_str(&block_id.to_string())? {
            SlotOrRoot::Slot(slot) => {
                let root = self
                    .0
                    .chain
                    .block_root_at_slot(slot.into(), WhenSlotSkipped::None)
                    .map_err(|err| anyhow::anyhow!("Failed to get block root: {:?}", err))?;
                match root {
                    None => return Ok(None),
                    Some(root) => root,
                }
            }
            SlotOrRoot::Root(root) => root,
        };

        let signed_block = self
            .0
            .chain
            .get_block(&root)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get block: {:?}", e))?;

        let beacon_block: BeaconBlock = match signed_block {
            None => return Ok(None),
            Some(signed_block) => {
                let (block, _) = signed_block.deconstruct();
                convert_via_json(block.as_electra().expect("electra only"))?
            }
        };

        Ok(Some(beacon_block))
    }

    async fn get_consensus_state(
        &self,
        state_id: impl std::fmt::Display,
    ) -> Result<z_core::ConsensusState, anyhow::Error> {
        let state = match SlotOrRoot::from_str(&state_id.to_string()) {
            Ok(SlotOrRoot::Slot(slot)) => {
                if slot > self.0.chain.head().head_slot().as_u64() {
                    return Err(anyhow::anyhow!(
                        "Requested slot {} is beyond the head slot {}",
                        slot,
                        self.0.chain.head().head_slot().as_u64()
                    ));
                }
                self.0
                    .chain
                    .state_at_slot(slot.into(), StateSkipConfig::WithStateRoots)
            }
            Ok(SlotOrRoot::Root(root)) => self
                .0
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
