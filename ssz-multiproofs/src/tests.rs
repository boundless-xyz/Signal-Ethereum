// Copyright 2024 RISC Zero, Inc.
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

use crate::*;
use ethereum_consensus::phase0::presets::mainnet::BeaconState;
use postcard::{from_bytes, to_stdvec};
use ssz_rs::prelude::*;

#[test]
fn test_proving_validator_fields() {
    let beacon_state = BeaconState::default();

    let builder = MultiproofBuilder::new();
    let multiproof = builder
        .with_path::<BeaconState>(&["validators".into()])
        .build(&beacon_state)
        .unwrap();

    let serialized = to_stdvec(&multiproof).unwrap();
    let multiproof: Multiproof = from_bytes(&serialized).unwrap();

    multiproof
        .verify(&beacon_state.hash_tree_root().unwrap())
        .unwrap();

    // Add a validator to the state
    let mut beacon_state = BeaconState::default();
    beacon_state.validators.push(Default::default());

    let gindex = BeaconState::generalized_index(&[
        "validators".into(),
        0.into(),
        "withdrawal_credentials".into(),
    ])
    .expect("Invalid path for state_roots");

    let multiproof = MultiproofBuilder::new()
        .with_gindex(gindex)
        .build(&beacon_state)
        .unwrap();

    let serialized = to_stdvec(&multiproof).unwrap();
    let multiproof: Multiproof = from_bytes(&serialized).unwrap();

    multiproof
        .verify(&beacon_state.hash_tree_root().unwrap())
        .unwrap();

    assert_eq!(
        multiproof.values::<32>().next(),
        Some((
            gindex as u64,
            beacon_state.validators[0]
                .withdrawal_credentials
                .as_slice()
                .try_into()
                .unwrap()
        ))
    );
}

#[test]
fn test_proving_state_roots() {
    let beacon_state = BeaconState::default();

    let gindex = BeaconState::generalized_index(&["state_roots".into(), 10.into()])
        .expect("Invalid path for state_roots");

    let multiproof = MultiproofBuilder::new()
        .with_gindex(gindex)
        .build(&beacon_state)
        .unwrap();

    let serialized = to_stdvec(&multiproof).unwrap();
    let multiproof: Multiproof = from_bytes(&serialized).unwrap();

    multiproof
        .verify(&beacon_state.hash_tree_root().unwrap())
        .unwrap();

    assert_eq!(
        multiproof.values().next(),
        Some((gindex as u64, &beacon_state.state_roots[10].into()))
    );
}
