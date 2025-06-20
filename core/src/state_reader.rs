use crate::{
    Ctx, Domain, DomainType, Epoch, RandaoMixIndex, Root, ValidatorIndex, ValidatorInfo, Version,
};
use alloy_primitives::B256;
use alloy_primitives::aliases::B32;
use beacon_types::EthSpec;
use sha2::Digest;
use std::cmp::{max, min};
use thiserror::Error;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[cfg(feature = "host")]
mod host_state_reader;
#[cfg(feature = "host")]
mod preflight_state_reader;
mod ssz_state_reader;
#[cfg(feature = "host")]
mod state_provider;

#[cfg(feature = "host")]
pub use self::{host_state_reader::*, preflight_state_reader::*, state_provider::*};
pub use ssz_state_reader::*;

#[derive(Error, Debug)]
pub enum StateReaderError {
    #[error("any")]
    Any,
}

pub trait StateReader {
    type Error: std::error::Error;
    type Spec: EthSpec;

    /// Return `state.genesis_validators_root`.
    fn genesis_validators_root(&self) -> Result<Root, Self::Error>;

    /// Return `state.fork.current_version`.
    // TODO(ec2): This should be handled in such a way that things won't break in the event of hardfork.
    fn fork_current_version(&self, epoch: Epoch) -> Result<Version, Self::Error>;

    /// Return the sequence of active validators at `epoch`.
    ///
    /// Returns the subset of all validators that are active in the given epoch. The returned validators are ordered by their index.
    /// This is equivalent to `state.validators.enumerate().filter(|(i,v)| is_active_validator(v, epoch))`.
    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error>;

    /// Return `state.randao_mixes[idx]`.
    fn randao_mix(&self, epoch: Epoch, idx: RandaoMixIndex) -> Result<Option<B256>, Self::Error>;

    /// Return the RANDAO mix at a recent `epoch`.
    fn get_randao_mix(&self, state_epoch: Epoch, epoch: Epoch) -> Result<B256, Self::Error> {
        let idx: RandaoMixIndex = (epoch % self.context().epochs_per_historical_vector())
            .try_into()
            .unwrap();

        Ok(self
            .randao_mix(state_epoch, idx)?
            .expect("randao_mix should be present"))
    }

    /// Return the sequence of active validator indices at `epoch`.
    fn get_active_validator_indices(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = ValidatorIndex>, Self::Error> {
        Ok(self.active_validators(epoch)?.map(|(index, _)| index))
    }

    /// Return the seed at `epoch`.
    fn get_seed(&self, epoch: Epoch, domain_type: B32) -> Result<B256, Self::Error> {
        let ctx = self.context();

        // the seed for epoch is based on the RANDAO from the epoch MIN_SEED_LOOKAHEAD + 1 ago
        let mix = self.get_randao_mix(
            epoch,
            epoch
                .checked_add(ctx.epochs_per_historical_vector() - ctx.min_seed_lookahead() - 1)
                .unwrap(),
        )?;

        let mut h = sha2::Sha256::new();
        Digest::update(&mut h, domain_type);
        Digest::update(&mut h, uint64_to_bytes(epoch));
        Digest::update(&mut h, mix);

        Ok(<[u8; 32]>::from(h.finalize()).into())
    }

    /// Return the number of committees in each slot for the given `epoch`.
    fn get_committee_count_per_slot(&self, epoch: Epoch) -> Result<u64, Self::Error> {
        Ok(max(
            1u64,
            min(
                self.context().max_committees_per_slot() as u64,
                self.get_active_validator_indices(epoch)?.count() as u64
                    / self.context().slots_per_epoch()
                    / self.context().target_committee_size(),
            ),
        ))
    }

    /// Return the combined effective balance of the active validators.
    fn get_total_active_balance(&self, epoch: Epoch) -> Result<u64, Self::Error> {
        Ok(max(
            self.context().effective_balance_increment(),
            self.active_validators(epoch)?
                .map(|(_, validator)| validator.effective_balance)
                .sum(),
        ))
    }

    fn get_domain(&self, domain_type: DomainType, epoch: Epoch) -> Result<Domain, Self::Error> {
        // TODO: fork_version = state.fork.previous_version if epoch < state.fork.epoch else state.fork.current_version
        let fork_version = self.fork_current_version(epoch)?;
        Ok(compute_domain(
            domain_type,
            fork_version,
            self.genesis_validators_root()?,
        ))
    }
}

/// Return the domain for the ``domain_type`` and ``fork_version``.
fn compute_domain(
    domain_type: DomainType,
    fork_version: Version,
    genesis_validators_root: Root,
) -> Domain {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);

    let mut domain = [0_u8; 32];
    domain[..4].copy_from_slice(domain_type.as_slice());
    domain[4..].copy_from_slice(&fork_data_root.as_slice()[..28]);

    domain.into()
}

/// Return the 32-byte fork data root for the `current_version` and `genesis_validators_root`.
/// This is used primarily in signature domains to avoid collisions across forks/chains.
fn compute_fork_data_root(current_version: Version, genesis_validators_root: Root) -> Root {
    #[derive(TreeHash)]
    struct ForkData {
        current_version: Version,
        genesis_validators_root: Root,
    }
    ForkData {
        current_version,
        genesis_validators_root,
    }
    .tree_hash_root()
}

#[inline]
pub fn uint64_to_bytes(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}
