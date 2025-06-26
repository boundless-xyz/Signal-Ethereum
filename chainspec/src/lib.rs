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

//! A crate for loading Ethereum beacon chain configurations.

pub use beacon_types::{ChainSpec, Config, MainnetEthSpec};

#[cfg(feature = "mainnet")]
/// Returns the mainnet `ChainSpec`.
pub fn mainnet_spec() -> ChainSpec {
    let config_bytes = include_bytes!("../configs/mainnet.yaml");
    let config: Config =
        serde_yaml::from_slice(config_bytes).expect("Failed to deserialize config");
    ChainSpec::from_config::<MainnetEthSpec>(&config).expect("Failed to create chainspec")
}

#[cfg(feature = "sepolia")]
/// Returns the sepolia `ChainSpec`.
pub fn sepolia_spec() -> ChainSpec {
    let config_bytes = include_bytes!("../configs/sepolia.yaml");
    let config: Config =
        serde_yaml::from_slice(config_bytes).expect("Failed to deserialize config");
    ChainSpec::from_config::<MainnetEthSpec>(&config).expect("Failed to create chainspec")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "mainnet")]
    fn test_mainnet_spec_loads() {
        let spec = mainnet_spec();
        assert_eq!(spec.config_name, Some("mainnet".to_string()));
    }

    #[test]
    #[cfg(feature = "sepolia")]
    fn test_sepolia_spec_loads() {
        let spec = sepolia_spec();
        assert_eq!(spec.config_name, Some("sepolia".to_string()));
    }
}
