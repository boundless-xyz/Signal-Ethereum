use std::sync::Arc;

use beacon_chain::{
    ChainConfig,
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
};
use beacon_types::{ChainSpec, Epoch, EthSpec, Keypair, MainnetEthSpec};
use z_core::ConsensusState;

type E = MainnetEthSpec;
pub type TestHarness = BeaconChainHarness<EphemeralHarnessType<E>>;

pub const VALIDATOR_COUNT: usize = 16;

pub fn get_spec() -> Arc<ChainSpec> {
    let altair_fork_epoch = Epoch::new(0);
    let bellatrix_fork_epoch = Epoch::new(1);
    let capella_fork_epoch = Epoch::new(2);
    let deneb_fork_epoch = Epoch::new(3);
    let electra_fork_epoch = Epoch::new(4);

    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(altair_fork_epoch);
    spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);
    spec.capella_fork_epoch = Some(capella_fork_epoch);
    spec.deneb_fork_epoch = Some(deneb_fork_epoch);
    spec.electra_fork_epoch = Some(electra_fork_epoch);
    Arc::new(spec)
}

pub async fn get_harness(keypairs: Vec<Keypair>, spec: Arc<ChainSpec>) -> TestHarness {
    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec.clone())
        .chain_config(ChainConfig {
            reconstruct_historic_states: true,
            ..Default::default()
        })
        .keypairs(keypairs)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let bellatrix_fork_slot = spec
        .bellatrix_fork_epoch
        .unwrap()
        .start_slot(harness.slots_per_epoch());
    let electra_fork_slot = spec
        .electra_fork_epoch
        .unwrap()
        .start_slot(harness.slots_per_epoch());

    harness.extend_to_slot(bellatrix_fork_slot).await;
    // write the terminal EL block to complete Capella upgrade
    harness
        .execution_block_generator()
        .move_to_terminal_block()
        .unwrap();
    // grow the chain past the Electra fork upgrade by 3 epochs so we don't accidentally
    // read prior to the fork
    harness
        .extend_to_slot(electra_fork_slot + harness.slots_per_epoch() * 3)
        .await;

    harness.advance_slot();

    harness
}

pub fn consensus_state_from_state(
    state: &beacon_types::BeaconState<MainnetEthSpec>,
) -> ConsensusState {
    ConsensusState {
        finalized_checkpoint: z_core::Checkpoint {
            epoch: state.finalized_checkpoint().epoch.into(),
            root: state.finalized_checkpoint().root.clone(),
        },
        current_justified_checkpoint: z_core::Checkpoint {
            epoch: state.current_justified_checkpoint().epoch.into(),
            root: state.current_justified_checkpoint().root.clone(),
        },
        previous_justified_checkpoint: z_core::Checkpoint {
            epoch: state.previous_justified_checkpoint().epoch.into(),
            root: state.previous_justified_checkpoint().root.clone(),
        },
    }
}
