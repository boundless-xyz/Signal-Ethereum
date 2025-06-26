#![no_main]

use chainspec::TEST_HARNESS_SPEC;
risc0_zkvm::guest::entry!(main);

fn main() {
    beacon_guest::entry(TEST_HARNESS_SPEC.clone());
}
