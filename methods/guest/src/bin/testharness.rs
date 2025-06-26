#![no_main]

use chainspec::{ChainSpec, Config as ChainConfig};
use risc0_zkvm::guest::env;
use z_core::{Config, MainnetEthSpec};

risc0_zkvm::guest::entry!(main);

fn main() {
    // for the tests we load the chain spec and config
    let config: ChainConfig = serde_cbor::from_slice(&env::read_frame()).unwrap();
    let spec = ChainSpec::from_config::<MainnetEthSpec>(&config).unwrap();
    let config: Config = serde_cbor::from_slice(&env::read_frame()).unwrap();

    beacon_guest::entry::<MainnetEthSpec>(spec, &config);
}
