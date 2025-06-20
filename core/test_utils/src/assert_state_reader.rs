use alloy_primitives::B256;
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

impl<S: StateReader, R: StateReader> StateReader for AssertStateReader<'_, S, R> {
    type Error = S::Error;
    type Context = S::Context;

    fn context(&self) -> &S::Context {
        self.reader_a.context()
    }

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
                    // do not compare the effective_balance as it is allowed to be incorrect
                    let mut validator = a.1.clone();
                    validator.effective_balance = b.1.effective_balance;
                    // TODO: Remove once that is supported
                    validator.exit_epoch = b.1.exit_epoch;
                    assert_eq!(&validator, b.1);

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
