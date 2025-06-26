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

//! Select the chainspec to use based on feature flags

use std::sync::LazyLock;

use z_core::{ChainSpec, Epoch};

pub static MAINNET_SPEC: LazyLock<ChainSpec> = LazyLock::new(|| ChainSpec::mainnet());

pub static TEST_HARNESS_SPEC: LazyLock<ChainSpec> = LazyLock::new(|| {
    let mut spec = ChainSpec::mainnet();
    spec.config_name = Some("test".to_string());
    spec.altair_fork_epoch = Some(Epoch::new(0));
    spec.bellatrix_fork_epoch = Some(Epoch::new(1));
    spec.capella_fork_epoch = Some(Epoch::new(2));
    spec.deneb_fork_epoch = Some(Epoch::new(3));
    spec.electra_fork_epoch = Some(Epoch::new(4));

    spec
});

pub static SEPOLIA_SPEC: LazyLock<ChainSpec> = LazyLock::new(|| {
    let mut spec = ChainSpec::mainnet();

    spec.config_name = Some("sepolia".to_string());

    spec.altair_fork_epoch = Some(Epoch::new(50));
    spec.altair_fork_version = [0x90, 0x00, 0x00, 0x70];

    spec.bellatrix_fork_epoch = Some(Epoch::new(100));
    spec.bellatrix_fork_version = [0x90, 0x00, 0x00, 0x71];

    spec.capella_fork_epoch = Some(Epoch::new(56832));
    spec.capella_fork_version = [0x90, 0x00, 0x00, 0x72];

    spec.deneb_fork_epoch = Some(Epoch::new(132608));
    spec.deneb_fork_version = [0x90, 0x00, 0x00, 0x73];

    spec.electra_fork_epoch = Some(Epoch::new(222464));
    spec.electra_fork_version = [0x90, 0x00, 0x00, 0x74];

    spec
});
