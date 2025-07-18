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

use beacon_types::ssz_tagged_signed_beacon_block::decode::from_ssz_bytes;
use chainspec::{ChainSpec, Config as ChainConfig};
use risc0_zkvm::guest::env;
use z_core::{Config, MainnetEthSpec, ProcessingConfig, do_transition};

risc0_zkvm::guest::entry!(main);

fn main() {
    env::log("Starting guest");
    let pre_state_bytes = env::read_frame();
    env::log(&format!("Pre-state bytes read: {}", pre_state_bytes.len()));
    let block_root_bytes = env::read_frame();
    env::log(&format!(
        "Block root bytes read: {}",
        block_root_bytes.len()
    ));
    let block_bytes = env::read_frame();
    env::log(&format!("Block bytes read: {}", block_bytes.len()));
    let state_root_opt_bytes = env::read_frame();
    env::log(&format!(
        "State root option bytes read: {}",
        state_root_opt_bytes.len()
    ));
    let spec = chainspec::mainnet_spec();

    let block_root =
        bincode::deserialize(&block_root_bytes).expect("Failed to deserialize block root");
    env::log("Block root deserialized");

    let state_root_opt = bincode::deserialize(&state_root_opt_bytes)
        .expect("Failed to deserialize state root option");
    env::log("State root option deserialized");

    let block: beacon_types::SignedBeaconBlock<MainnetEthSpec> =
        serde_json::from_slice(&block_bytes).expect("Failed to deserialize block");
    // from_ssz_bytes(&block_bytes).expect("Failed to deserialize block");
    env::log("Block deserialized");

    let pre_state: beacon_types::BeaconState<MainnetEthSpec> =
        serde_json::from_slice(&pre_state_bytes).expect("Failed to deserialize pre-state");
    env::log("Pre-state deserialized");

    let mut saved_ctxt: Option<_> = None;

    let config = ProcessingConfig {
        no_signature_verification: false,
        exclude_cache_builds: false,
        exclude_post_block_thc: false,
    };
    env::log("Start transition");
    let mut post_state = do_transition::<MainnetEthSpec>(
        pre_state,
        block_root,
        block,
        state_root_opt,
        &config,
        // &validator_pubkey_cache,
        &mut saved_ctxt,
        &spec,
    )
    .expect("Failed to apply block");
    env::log("Transition completed");
    let post_state_root = post_state.canonical_root().unwrap();
    env::commit_slice(&bincode::serialize(&post_state_root).unwrap());
}
