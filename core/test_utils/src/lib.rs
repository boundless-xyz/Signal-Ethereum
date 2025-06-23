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

use std::sync::Arc;

pub use assert_state_reader::AssertStateReader;
use beacon_chain::{
    ChainConfig,
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
};
use beacon_types::{
    ChainSpec, Epoch, EthSpec, FixedBytesExtended, Hash256, Keypair, MainnetEthSpec, Slot,
};
use z_core::ConsensusState;

mod assert_state_reader;
mod test_harness_state_reader;

type E = MainnetEthSpec;
pub type TestHarness = test_harness_state_reader::TestHarness<EphemeralHarnessType<E>>;

pub fn get_spec() -> Arc<ChainSpec> {
    let altair_fork_epoch = Epoch::new(0);
    let bellatrix_fork_epoch = Epoch::new(1);
    let capella_fork_epoch = Epoch::new(2);
    let deneb_fork_epoch = Epoch::new(3);
    let electra_fork_epoch = Epoch::new(4);

    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(altair_fork_epoch);
    spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);
    spec.capella_fork_epoch = Some(capella_fork_epoch);
    spec.deneb_fork_epoch = Some(deneb_fork_epoch);
    spec.electra_fork_epoch = Some(electra_fork_epoch);
    Arc::new(spec)
}

pub async fn get_harness(
    keypairs: Vec<Keypair>,
    spec: Arc<ChainSpec>,
    start_slot: Slot,
) -> TestHarness {
    let validator_count = keypairs.len();
    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec.clone())
        .chain_config(ChainConfig {
            reconstruct_historic_states: true,
            ..Default::default()
        })
        .keypairs(keypairs)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let bellatrix_fork_slot = spec
        .bellatrix_fork_epoch
        .unwrap()
        .start_slot(harness.slots_per_epoch());
    let electra_fork_slot = spec
        .electra_fork_epoch
        .unwrap()
        .start_slot(harness.slots_per_epoch());

    harness.extend_to_slot(bellatrix_fork_slot).await;
    // write the terminal EL block to complete Capella upgrade
    harness
        .execution_block_generator()
        .move_to_terminal_block()
        .unwrap();
    harness.extend_to_slot(electra_fork_slot).await;
    harness.advance_slot();
    if start_slot > harness.get_current_slot() {
        let state = harness.get_current_state();
        harness
            .add_attested_blocks_at_slots(
                state,
                Hash256::zero(),
                (harness.get_current_slot().as_u64()..=start_slot.as_u64())
                    .map(Slot::new)
                    .collect::<Vec<_>>()
                    .as_slice(),
                (0..validator_count).collect::<Vec<_>>().as_slice(),
            )
            .await;
    } else {
        panic!(
            "start_slot must be greater than {} or else Electra fork will not be applied",
            harness.get_current_slot()
        );
    }
    harness.advance_slot();
    assert!(
        harness
            .get_current_state()
            .fork_name_unchecked()
            .electra_enabled()
    );
    harness.into()
}

pub fn consensus_state_from_state(
    state: &beacon_types::BeaconState<MainnetEthSpec>,
) -> ConsensusState {
    ConsensusState {
        finalized_checkpoint: z_core::Checkpoint::new(
            state.finalized_checkpoint().epoch.into(),
            state.finalized_checkpoint().root.clone(),
        ),
        current_justified_checkpoint: z_core::Checkpoint::new(
            state.current_justified_checkpoint().epoch.into(),
            state.current_justified_checkpoint().root.clone(),
        ),
        previous_justified_checkpoint: z_core::Checkpoint::new(
            state.previous_justified_checkpoint().epoch.into(),
            state.previous_justified_checkpoint().root.clone(),
        ),
    }
}
