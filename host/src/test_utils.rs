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

use beacon_chain::{
    ChainConfig,
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
};
use beacon_types::{
    ChainSpec, EthSpec, FixedBytesExtended, Hash256, Keypair, MainnetEthSpec, Slot,
};
use z_core::ConsensusState;

type E = MainnetEthSpec;
pub type TestHarness = crate::test_harness_state_reader::TestHarness<EphemeralHarnessType<E>>;

pub async fn get_harness(
    keypairs: Vec<Keypair>,
    spec: &ChainSpec,
    start_slot: Slot,
) -> TestHarness {
    let validator_count = keypairs.len();
    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec.clone().into())
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

pub fn consensus_state_from_state<T: EthSpec>(
    state: &beacon_types::BeaconState<T>,
) -> ConsensusState {
    ConsensusState::new(
        z_core::Checkpoint::new(
            state.current_justified_checkpoint().epoch,
            state.current_justified_checkpoint().root,
        ),
        z_core::Checkpoint::new(
            state.finalized_checkpoint().epoch,
            state.finalized_checkpoint().root,
        ),
    )
}
