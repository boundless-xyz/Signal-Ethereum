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
        let spec = mainnet_spec();
        assert_eq!(spec.config_name, Some("sepolia".to_string()));
    }
}
