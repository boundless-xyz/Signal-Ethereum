use risc0_zkvm::guest::env;
use z_core::{verify, GuestContext, Input, StateInput};

fn main() {
    let filter = tracing_subscriber::filter::EnvFilter::from_default_env()
        .add_directive(tracing_subscriber::filter::LevelFilter::INFO.into());
    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(filter)
        .init();

    let ssz_reader_bytes = env::read_frame();
    let input_bytes = env::read_frame();
    let _context = env::read_frame();
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
        state_input.into_state_reader(input.trusted_checkpoint_state_root.into(), &GuestContext)
    };

    // the input bytes are no longer needed
    drop((ssz_reader_bytes, input_bytes));

    let candidate_epoch = input.candidate_checkpoint.epoch;

    env::log("Running FFG Verification");
    let t = verify(&state_reader, input);

    if t {
        env::log("FFG Verification passed");
    } else {
        env::log("FFG Verification failed");
    }

    // write public output to the journal
    env::commit(&candidate_epoch.to_le_bytes());
}
