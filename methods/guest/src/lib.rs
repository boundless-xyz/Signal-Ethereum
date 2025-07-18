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

use risc0_zkvm::guest::env;
use z_core::{
    ChainSpec, Config, EthSpec, Input, ProcessingConfig, StateInput, do_transition, verify,
};

pub fn entry<E: EthSpec>(spec: ChainSpec, config: &Config) {
    env::log(&format!("Network: {}", spec.config_name.as_ref().unwrap()));

    env::log("Reading frames...");
    let ssz_reader_bytes = env::read_frame();
    let input_bytes = env::read_frame();
    env::log("Deserializing data...");

    let input: Input<E> = bincode::deserialize(&input_bytes).unwrap();
    env::log(&format!("Input deserialized: {} bytes", input_bytes.len()));

    let state_reader = {
        let state_input: StateInput = bincode::deserialize(&ssz_reader_bytes).unwrap();
        env::log(&format!(
            "StateReader deserialized: {} bytes",
            ssz_reader_bytes.len()
        ));

        env::log("Verifying StateReader...");
        state_input.into_state_reader(spec, &input.consensus_state)
    }
    .unwrap();

    // the input bytes are no longer needed
    drop((ssz_reader_bytes, input_bytes));

    env::log("Verifying FFG state transitions...");

    let pre_state = input.consensus_state.clone();
    let post_state = verify(config, &state_reader, input).unwrap();

    env::log(&format!(
        "New finalization: {}",
        &post_state.finalized_checkpoint()
    ));

    // write public output to the journal
    env::commit_slice(&pre_state.abi_encode());
    env::commit_slice(&post_state.abi_encode());
}

pub fn transition_entry<E: EthSpec>(spec: ChainSpec) {
    env::log("Starting guest");
    let pre_state_bytes = env::read_frame();
    env::log(&format!("Pre-state bytes read: {}", pre_state_bytes.len()));
    let block_root_bytes = env::read_frame();
    env::log(&format!(
        "Block root bytes read: {}",
        block_root_bytes.len()
    ));
    let block_bytes = env::read_frame();
    env::log(&format!("Block bytes read: {}", block_bytes.len()));
    let state_root_opt_bytes = env::read_frame();
    env::log(&format!(
        "State root option bytes read: {}",
        state_root_opt_bytes.len()
    ));

    let block_root =
        bincode::deserialize(&block_root_bytes).expect("Failed to deserialize block root");
    env::log("Block root deserialized");

    let state_root_opt = bincode::deserialize(&state_root_opt_bytes)
        .expect("Failed to deserialize state root option");
    env::log("State root option deserialized");

    let block: beacon_types::SignedBeaconBlock<E> =
        serde_json::from_slice(&block_bytes).expect("Failed to deserialize block");
    // from_ssz_bytes(&block_bytes).expect("Failed to deserialize block");
    env::log("Block deserialized");

    let pre_state = beacon_types::BeaconState::<E>::from_ssz_bytes(&pre_state_bytes, &spec)
        .expect("Failed to deserialize pre-state");
    env::log("Pre-state deserialized");

    let mut saved_ctxt: Option<_> = None;

    let config = ProcessingConfig {
        no_signature_verification: false,
        exclude_cache_builds: false,
        exclude_post_block_thc: false,
    };
    env::log("Start transition");
    let mut post_state = do_transition::<E>(
        pre_state,
        block_root,
        block,
        state_root_opt,
        &config,
        // &validator_pubkey_cache,
        &mut saved_ctxt,
        &spec,
    )
    .expect("Failed to apply block");
    env::log("Transition completed");
    let post_state_root = post_state.canonical_root().unwrap();
    env::commit_slice(&bincode::serialize(&post_state_root).unwrap());
}
