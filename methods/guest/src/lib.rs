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
use z_core::{ChainSpec, Config, EthSpec, GuestInput, InputReader, abi, verify};

pub fn entry<E: EthSpec>(spec: ChainSpec, config: &Config) {
    env::log(&format!("Network: {}", spec.config_name.as_ref().unwrap()));

    env::log("Reading frames...");
    let ssz_reader_bytes = env::read_frame();
    env::log("Deserializing data...");

    let state_reader = {
        let state_input: GuestInput<E> = bincode::deserialize(&ssz_reader_bytes).unwrap();
        env::log(&format!(
            "InputReader deserialized: {} bytes",
            ssz_reader_bytes.len()
        ));

        env::log("Verifying InputReader...");
        state_input.into_state_reader(spec)
    }
    .unwrap();

    // the input bytes are no longer needed
    drop(ssz_reader_bytes);

    env::log("Verifying FFG state transitions...");

    let pre_state = state_reader.consensus_state().unwrap();
    let (post_state, finalized_slot) = verify(config, &state_reader).unwrap();

    env::log(&format!(
        "New finalization: {}",
        &post_state.finalized_checkpoint()
    ));

    // write public output to the journal
    let journal = abi::Journal::new(&pre_state, &post_state, finalized_slot);
    env::commit_slice(&journal.encode());
}
