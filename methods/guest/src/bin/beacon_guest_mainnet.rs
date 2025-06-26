#![no_main]

use chainspec::MAINNET_SPEC;
risc0_zkvm::guest::entry!(main);

fn main() {
    beacon_guest::entry(MAINNET_SPEC.clone());
}
