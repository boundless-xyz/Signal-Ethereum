use crate::PublicKey;
use alloy_primitives::{B256, b256};
use ssz_rs::prelude::*;

use crate::Epoch;

use thiserror::Error;
#[cfg(feature = "host")]
mod host_state_reader;
#[cfg(feature = "host")]
mod tracking_state_reader;

#[cfg(feature = "host")]
pub use self::{host_state_reader::*, tracking_state_reader::*};

mod ssz_state_reader;
pub use ssz_state_reader::*;

#[derive(Error, Debug)]
pub enum StateReaderError {
    #[error("any")]
    Any,
}

pub trait StateReader {
    type Error: alloc::fmt::Debug;

    fn get_randao(&self, epoch: Epoch) -> Result<Option<[u8; 32]>, Self::Error>;
    fn aggregate_validator_keys_and_balance(
        &self,
        indices: impl IntoIterator<Item = usize>,
    ) -> Result<(Vec<PublicKey>, u64), Self::Error>;
    fn get_validator_activation_and_exit_epochs(
        &self,
        epoch: Epoch,
        validator_index: usize,
    ) -> Result<(u64, u64), Self::Error>;
    // TODO(ec2): This should probably be a u64...
    fn get_validator_count(&self, epoch: Epoch) -> Result<Option<usize>, Self::Error>;
    fn get_total_active_balance(&self, epoch: Epoch) -> Result<u64, Self::Error>;
    fn get_active_validator_indices(&self, epoch: Epoch) -> Result<Vec<usize>, Self::Error>;

    // TODO(ec2): This is hardcoded for sepola. We can get this from the state.
    fn genesis_validators_root(&self) -> B256 {
        #[cfg(feature = "sepolia")]
        return b256!("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078");
        #[cfg(not(feature = "sepolia"))]
        return b256!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95");
    }

    // TODO(ec2): This is hardcoded for sepolia electra. We can get this from the state.
    fn fork_version(&self) -> [u8; 4] {
        #[cfg(feature = "sepolia")]
        return [144, 0, 0, 116];

        #[cfg(not(feature = "sepolia"))]
        return [5, 0, 0, 0];
    }
}
