use risc0_zkvm::guest::env;
use z_core::{ChainSpec, DEFAULT_CONFIG, Input, MainnetEthSpec, StateInput, verify};

type Spec = MainnetEthSpec;

pub fn entry(chain_spec: ChainSpec) {
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
        state_input.into_state_reader(chain_spec, &input.consensus_state)
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
