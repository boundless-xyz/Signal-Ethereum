use std::sync::LazyLock;

use beacon_chain::{
    StateSkipConfig,
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy},
};
use beacon_types::{EthSpec, Keypair, MainnetEthSpec};
use z_core::HarnessStateReader;

pub const VALIDATOR_COUNT: usize = 16;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| beacon_types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

/// This test builds a chain that is just long enough to finalize an epoch (epoch 2)
/// 100% validator participation
#[tokio::test]
async fn simple_finalize_epoch() {
    let num_blocks_produced = MainnetEthSpec::slots_per_epoch() * 4;

    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[..].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let chain = &harness.chain;

    for slot in 0..=num_blocks_produced {
        if slot > 0 && slot <= num_blocks_produced {
            harness.advance_slot();

            harness
                .extend_chain(
                    1,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;

            let state = chain
                .state_at_slot(slot.into(), StateSkipConfig::WithStateRoots)
                .expect("should get state");
            println!(
                "Slot: {}\nF: {:?}\nCJ: {:?}\nPJ: {:?}\n",
                state.slot(),
                state.finalized_checkpoint(),
                state.current_justified_checkpoint(),
                state.previous_justified_checkpoint()
            );
        }
    }
}
