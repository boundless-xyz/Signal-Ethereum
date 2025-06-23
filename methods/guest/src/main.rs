// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use risc0_zkvm::guest::env;
use z_core::{Input, MainnetEthSpec, Output, StateInput, verify};

type Spec = MainnetEthSpec;
fn main() {
    let filter = tracing_subscriber::filter::EnvFilter::from_default_env()
        .add_directive(tracing_subscriber::filter::LevelFilter::INFO.into());
    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(filter)
        .init();

    let ssz_reader_bytes = env::read_frame();
    let input_bytes = env::read_frame();
    env::log("Finished reading frames. Start deserialization...");

    let input: Input<Spec> = bincode::deserialize(&input_bytes).unwrap();
    env::log(&format!("Input deserialized: {} bytes", input_bytes.len()));

    let state_reader = {
        let state_input: StateInput = bincode::deserialize(&ssz_reader_bytes).unwrap();
        env::log(&format!(
            "StateReader deserialized: {} bytes",
            ssz_reader_bytes.len()
        ));

        env::log("Verify and Cache SszStateReader");
        state_input.into_state_reader(input.state.finalized_checkpoint)
    }
    .unwrap();

    // the input bytes are no longer needed
    drop((ssz_reader_bytes, input_bytes));

    env::log("Running FFG state update");

    let pre_state = input.state.clone();
    let post_state = verify(&state_reader, input).unwrap();

    // write public output to the journal
    let output = Output {
        pre_state,
        post_state,
    };
    env::commit_slice(&output.abi_encode())
}
