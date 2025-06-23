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

use alloy_primitives::B256;
use beacon_types::EthSpec;
use std::iter;
use z_core::{Epoch, RandaoMixIndex, Root, StateReader, ValidatorIndex, ValidatorInfo};

/// A simple state reader used for debugging and testing.
pub struct AssertStateReader<'a, S, R> {
    reader_a: &'a S,
    reader_b: &'a R,
}

impl<'a, S: StateReader, R: StateReader> AssertStateReader<'a, S, R> {
    pub fn new(inner: &'a S, reader: &'a R) -> Self {
        Self {
            reader_a: inner,
            reader_b: reader,
        }
    }
}

impl<E: EthSpec, S: StateReader<Spec = E>, R: StateReader<Spec = E>> StateReader
    for AssertStateReader<'_, S, R>
{
    type Spec = E;
    type Error = S::Error;

    fn genesis_validators_root(&self) -> Result<Root, Self::Error> {
        let a = self.reader_a.genesis_validators_root()?;
        let b = self.reader_b.genesis_validators_root().unwrap();
        assert_eq!(a, b);
        Ok(a)
    }

    fn fork(&self, epoch: Epoch) -> Result<beacon_types::Fork, Self::Error> {
        let a = self.reader_a.fork(epoch)?;
        let b = self.reader_b.fork(epoch).unwrap();
        assert_eq!(a, b);
        Ok(a)
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        let mut iter_a = self.reader_a.active_validators(epoch)?;
        let mut iter_b = self.reader_b.active_validators(epoch).unwrap();
        Ok(iter::from_fn(move || {
            match (iter_a.next(), iter_b.next()) {
                (None, None) => None,
                (Some(a), Some(b)) => {
                    assert_eq!(a.0, b.0);
                    // only compare the public key
                    assert_eq!(a.1.pubkey, b.1.pubkey);
                    Some(a)
                }
                (a, b) => panic!(
                    "One active validator iterator ended while the other has remaining validators. Left={:?}, Right={:?}",
                    a.map(|v| v.0),
                    b.map(|v| v.0)
                ),
            }
        }))
    }

    fn randao_mix(&self, epoch: Epoch, index: RandaoMixIndex) -> Result<Option<B256>, Self::Error> {
        let a = self.reader_a.randao_mix(epoch, index)?;
        let b = self.reader_b.randao_mix(epoch, index).unwrap();
        assert_eq!(a, b);
        Ok(a)
    }
}
