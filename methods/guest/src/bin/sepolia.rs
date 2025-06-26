#![no_main]

use z_core::{DEFAULT_CONFIG, MainnetEthSpec};

risc0_zkvm::guest::entry!(main);

fn main() {
    beacon_guest::entry::<MainnetEthSpec>(chainspec::sepolia_spec(), &DEFAULT_CONFIG);
}
