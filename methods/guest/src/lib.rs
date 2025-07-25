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
use z_core::{ChainSpec, Config, EthSpec, Input, StateInput, verify};

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
