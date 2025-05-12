use risc0_zkvm::guest::env;
use z_core::{verify, GuestContext, Input, SszStateReader};
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
    let mut state_reader: SszStateReader = bincode::deserialize(&ssz_reader_bytes).unwrap();
    env::log(&format!(
        "StateReader deserialized: {} bytes",
        ssz_reader_bytes.len()
    ));
    let input: Input = bincode::deserialize(&input_bytes).unwrap();
    env::log(&format!("Input deserialized: {} bytes", input_bytes.len()));
    let candidate_epoch = input.candidate_checkpoint.epoch;
    let context = GuestContext;
    env::log("Verify and Cache SszStateReader");
    state_reader.verify_and_cache(*input.trusted_checkpoint_state_root);

    env::log("Running FFG Verification");
    let t = verify(&mut state_reader, input, &context);

    if t {
        env::log("FFG Verification passed");
    } else {
        env::log("FFG Verification failed");
    }

    // write public output to the journal
    env::commit(&candidate_epoch.to_le_bytes());
}
