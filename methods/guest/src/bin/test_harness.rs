// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
