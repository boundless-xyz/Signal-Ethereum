//! Select the chainspec to use based on feature flags

use std::sync::LazyLock;

use z_core::ChainSpec;

pub static CHAINSPEC: LazyLock<ChainSpec> = LazyLock::new(|| {
    if cfg!(feature = "mainnet") {
        ChainSpec::mainnet()
    } else if cfg!(feature = "sepolia") {
        use z_core::Epoch;

        let mut spec = ChainSpec::mainnet();

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
    } else if cfg!(feature = "testharness") {
        use z_core::Epoch;

        let mut spec = ChainSpec::mainnet();
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.bellatrix_fork_epoch = Some(Epoch::new(1));
        spec.capella_fork_epoch = Some(Epoch::new(2));
        spec.deneb_fork_epoch = Some(Epoch::new(3));
        spec.electra_fork_epoch = Some(Epoch::new(4));

        spec
    } else {
        unreachable!("No valid feature flag set for chainspec");
    }
});
