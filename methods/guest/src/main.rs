// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use risc0_zkvm::guest::env;
use z_core::{
    compute_fork_data_root, verify, GuestContext, Input, Output, Root, StateInput, StateReader,
};

mod config;

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

    let input: Input = bincode::deserialize(&input_bytes).unwrap();
    env::log(&format!("Input deserialized: {} bytes", input_bytes.len()));

    let state_reader = {
        let state_input: StateInput = bincode::deserialize(&ssz_reader_bytes).unwrap();
        env::log(&format!(
            "StateReader deserialized: {} bytes",
            ssz_reader_bytes.len()
        ));

        env::log("Verify and Cache SszStateReader");
        state_input.into_state_reader(&GuestContext, input.state.finalized_checkpoint)
    }
    .unwrap();

    assert_eq!(
        state_reader
            .fork_data_root(input.state.finalized_checkpoint.epoch)
            .unwrap(),
        compute_fork_data_root(
            config::VERSION,
            Root::from_slice(&config::GENESIS_VALIDATORS_ROOT)
        ),
        "Fork data root mismatch. State is not consistent with the expected chain"
    );

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
