#![no_main]

use chainspec::SEPOLIA_SPEC;
risc0_zkvm::guest::entry!(main);

fn main() {
    beacon_guest::entry(SEPOLIA_SPEC.clone());
}
