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
use z_core::{DEFAULT_CONFIG, EthSpec, Input, MainnetEthSpec, StateInput, verify};

type Spec = MainnetEthSpec;

fn main() {
    let filter = tracing_subscriber::filter::EnvFilter::from_default_env()
        .add_directive(tracing_subscriber::filter::LevelFilter::INFO.into());
    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(filter)
        .init();

    env::log("Reading frames...");
    let ssz_reader_bytes = env::read_frame();
    let input_bytes = env::read_frame();
    env::log("Deserializing data...");

    let input: Input<Spec> = bincode::deserialize(&input_bytes).unwrap();
    env::log(&format!("Input deserialized: {} bytes", input_bytes.len()));

    let state_reader = {
        let state_input: StateInput = bincode::deserialize(&ssz_reader_bytes).unwrap();
        env::log(&format!(
            "StateReader deserialized: {} bytes",
            ssz_reader_bytes.len()
        ));

        env::log("Verifying StateReader...");
        state_input.into_state_reader(Spec::default_spec(), &input.consensus_state)
    }
    .unwrap();

    // the input bytes are no longer needed
    drop((ssz_reader_bytes, input_bytes));

    env::log("Verifying FFG state transitions...");

    let pre_state = input.consensus_state.clone();
    let post_state = verify(&DEFAULT_CONFIG, &state_reader, input).unwrap();

    env::log(&format!(
        "New finalization: {}",
        post_state.finalized_checkpoint
    ));

    // write public output to the journal
    env::commit_slice(&pre_state.abi_encode());
    env::commit_slice(&post_state.abi_encode());
}
