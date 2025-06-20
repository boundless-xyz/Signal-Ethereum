use alloy_primitives::B256;
use beacon_types::EthSpec;
use std::iter;
use z_core::{Epoch, RandaoMixIndex, Root, StateReader, ValidatorIndex, ValidatorInfo, Version};

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

    fn fork_current_version(&self, epoch: Epoch) -> Result<Version, Self::Error> {
        let a = self.reader_a.fork_current_version(epoch)?;
        let b = self.reader_b.fork_current_version(epoch).unwrap();
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
                (a, b) => panic!("Wrong size: empty={}, empty={}", a.is_none(), b.is_none()),
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
