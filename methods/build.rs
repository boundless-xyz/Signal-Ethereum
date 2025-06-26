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

use std::{collections::HashMap, env};

use risc0_build::{GuestOptionsBuilder, embed_methods_with_options};

fn main() {
    let guest_features = match (
        env::var("CARGO_FEATURE_MAINNET").is_ok(),
        env::var("CARGO_FEATURE_SEPOLIA").is_ok(),
        env::var("CARGO_FEATURE_TESTHARNESS").is_ok(),
    ) {
        (true, false, false) => {
            vec!["mainnet".to_string()]
        }
        (false, true, false) => {
            vec!["sepolia".to_string()]
        }
        (false, false, true) => {
            vec!["testharness".to_string()]
        }
        (false, false, false) => {
            println!("cargo:warning=No network config features enabled, defaulting to mainnet");
            vec!["mainnet".to_string()]
        }
        _ => {
            println!(
                "cargo:warning=features mainnet={}, sepolia={}, testharness={}",
                env::var("CARGO_FEATURE_MAINNET").is_ok(),
                env::var("CARGO_FEATURE_SEPOLIA").is_ok(),
                env::var("CARGO_FEATURE_TESTHARNESS").is_ok()
            );
            panic!(
                "Exactly one of the features mainnet, sepolia, or testharness must be enabled to build the guest"
            );
        }
    };

    println!(
        "cargo:warning=building guest with features: {:?}",
        guest_features
    );

    // Generate Rust source files for the methods crate.
    embed_methods_with_options(HashMap::from([(
        "beacon_guest",
        GuestOptionsBuilder::default()
            .features(guest_features)
            .build()
            .unwrap(),
    )]));
}
