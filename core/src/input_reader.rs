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

use crate::{ConsensusState, Epoch, RandaoMixIndex, Root, ValidatorIndex, ValidatorInfo};
use alloy_primitives::{B256, aliases::B32};
use beacon_types::{Attestation, ChainSpec, EthSpec, Unsigned};
use safe_arith::{ArithError, SafeArith};
use sha2::Digest;

mod guest_input_reader;
pub use guest_input_reader::*;

pub trait InputReader {
    type Error: std::error::Error + From<ArithError>;
    type Spec: EthSpec;

    fn chain_spec(&self) -> &ChainSpec;

    /// Return `state.genesis_validators_root`.
    fn genesis_validators_root(&self) -> Result<Root, Self::Error>;

    /// Return `state.fork`.
    fn fork(&self, epoch: Epoch) -> Result<beacon_types::Fork, Self::Error>;

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

    /// Return an iterator over the attestations for this input
    fn attestations(&self) -> Result<impl Iterator<Item = &Attestation<Self::Spec>>, Self::Error>;

    /// The trusted consensus state that serves as the starting point.
    ///
    /// Any state transitions resulting from the verification of the `attestations` will be applied
    /// relative to this state.
    fn consensus_state(&self) -> Result<ConsensusState, Self::Error>;

    /// Return the root of the block that is finalized by the attestations
    fn slot_for_block(&self, block_root: &Root) -> Result<u64, Self::Error>;

    /// Return the RANDAO mix at a recent `epoch`.
    fn get_randao_mix(&self, state_epoch: Epoch, epoch: Epoch) -> Result<B256, Self::Error> {
        let idx = epoch
            .as_usize()
            .safe_rem(Self::Spec::epochs_per_historical_vector())?;

        Ok(self
            .randao_mix(state_epoch, idx as RandaoMixIndex)?
            .expect("randao_mix should be present"))
    }

    /// Return the seed at `epoch`.
    fn get_seed(&self, epoch: Epoch, domain_type: B32) -> Result<B256, Self::Error> {
        // the seed for epoch is based on the RANDAO from the epoch MIN_SEED_LOOKAHEAD + 1 ago
        let i = epoch
            .safe_add(<Self::Spec as EthSpec>::EpochsPerHistoricalVector::to_u64())?
            .safe_sub(self.chain_spec().min_seed_lookahead)?
            .safe_sub(1)?;
        let mix = self.get_randao_mix(epoch, i)?;

        let mut h = sha2::Sha256::new();
        Digest::update(&mut h, domain_type);
        Digest::update(&mut h, uint64_to_bytes(epoch.into()));
        Digest::update(&mut h, mix);

        Ok(<[u8; 32]>::from(h.finalize()).into())
    }
}

/// Returns the combined effective balance of the `validators`.
///
/// See: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#get_total_balance
pub fn get_total_balance<I>(spec: &ChainSpec, validators: I) -> Result<u64, ArithError>
where
    I: IntoIterator,
    I::Item: AsRef<ValidatorInfo>,
{
    let total_balance = validators.into_iter().try_fold(0u64, |acc, validator| {
        acc.safe_add(validator.as_ref().effective_balance)
    })?;

    Ok(std::cmp::max(
        total_balance,
        spec.effective_balance_increment,
    ))
}

fn uint64_to_bytes(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}
