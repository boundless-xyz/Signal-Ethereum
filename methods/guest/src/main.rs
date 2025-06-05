use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};
use z_core::{verify, GuestContext, Input, StateInput};

fn print_mem() {
    const STACK_TOP: usize = 0x0020_0400;
    const TEXT_START: usize = 0x0020_0800;
    extern "C" {
        static _end: u8;
    }
    let heap_start = unsafe { (&_end) as *const u8 as usize };
    println!("code size: {}", heap_start - TEXT_START);
    let x: u32 = 0;
    let ptr = &x as *const u32 as usize;
    println!("stack: {ptr:x}, usage: {}", STACK_TOP - ptr);
    let a = Box::new(1);
    let heap_pos = Box::into_raw(a) as *mut i32 as usize;
    println!("heap:  {heap_pos:x}, usage: {}", heap_pos - heap_start,);
}

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
        state_input.into_state_reader(input.trusted_checkpoint_state_root.into(), &GuestContext)
    }
    .unwrap();

    // the input bytes are no longer needed
    drop((ssz_reader_bytes, input_bytes));

    env::commit(&input.trusted_checkpoint_state_root);

    env::log("Running FFG state update");

    let trusted_state_root = input.trusted_checkpoint_state_root;

    let pre_state_bytes = bincode::serialize(&input.consensus_state).unwrap();
    let pre_state_hash = Sha256::digest(&pre_state_bytes);

    let post_state = verify(&state_reader, input).unwrap();
    let post_state_bytes = bincode::serialize(&post_state).unwrap();
    let post_state_hash = Sha256::digest(&post_state_bytes);

    // write public output to the journal
    env::commit_slice(trusted_state_root.as_slice());
    env::commit_slice(&pre_state_hash);
    env::commit_slice(&post_state_hash);

    print_mem();
}
