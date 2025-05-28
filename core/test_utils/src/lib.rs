use std::{num::NonZeroUsize, sync::Arc};

use beacon_chain::{
    store::{self, StoreConfig, database::interface::BeaconNodeBackend},
    test_utils::{BeaconChainHarness, DiskHarnessType},
};
use beacon_types::{ChainSpec, Epoch, EthSpec, Keypair, MainnetEthSpec};
use sloggers::{Build, null::NullLoggerBuilder};
use tempfile::TempDir;
use z_core::ConsensusState;

type E = MainnetEthSpec;
type TestHarness = BeaconChainHarness<DiskHarnessType<E>>;
type HotColdDB = store::HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>;

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

pub fn get_store(db_path: &TempDir, spec: Arc<ChainSpec>) -> Arc<HotColdDB> {
    let hot_path = db_path.path().join("hot_db");
    let cold_path = db_path.path().join("cold_db");
    let blobs_path = db_path.path().join("blobs_db");
    let config = StoreConfig {
        state_cache_size: NonZeroUsize::new(9999).unwrap(),
        historic_state_cache_size: NonZeroUsize::new(9999).unwrap(),
        block_cache_size: NonZeroUsize::new(9999).unwrap(),
        ..Default::default()
    };
    let log = NullLoggerBuilder.build().expect("logger should build");
    HotColdDB::open(
        &hot_path,
        &cold_path,
        &blobs_path,
        |_, _, _| Ok(()),
        config,
        spec,
        log,
    )
    .expect("disk store should initialize")
}

pub async fn get_harness(
    keypairs: Vec<Keypair>,
    store: Arc<HotColdDB>,
    spec: Arc<ChainSpec>,
) -> TestHarness {
    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec.clone())
        .keypairs(keypairs)
        .fresh_disk_store(store)
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
