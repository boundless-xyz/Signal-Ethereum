use alloy_primitives::B256;
use std::iter;
use z_core::{Epoch, StateReader, ValidatorIndex, ValidatorInfo, Version};

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

    fn genesis_validators_root(&self) -> B256 {
        let a = self.reader_a.genesis_validators_root();
        let b = self.reader_b.genesis_validators_root();
        assert_eq!(a, b);
        a
    }

    fn fork_current_version(&self, state: Epoch) -> Result<Version, Self::Error> {
        let a = self.reader_a.fork_current_version(state)?;
        let b = self.reader_b.fork_current_version(state).unwrap();
        assert_eq!(a, b);
        Ok(a)
    }

    fn active_validators(
        &self,
        state: Epoch,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        let mut iter_a = self.reader_a.active_validators(state, epoch)?;
        let mut iter_b = self.reader_b.active_validators(state, epoch).unwrap();
        Ok(iter::from_fn(move || {
            match (iter_a.next(), iter_b.next()) {
                (None, None) => None,
                (Some(a), Some(b)) => {
                    assert_eq!(a.0, b.0); // only ensure the same validators are returned, do not check the validator info
                    Some(a)
                }
                (a, b) => panic!(
                    "Activate validator set size mismatch. Left={:?}, Right={:?}",
                    a.map(|v| v.0),
                    b.map(|v| v.0)
                ),
            }
        }))
    }

    fn randao_mix(&self, state: Epoch, index: usize) -> Result<Option<B256>, Self::Error> {
        let a = self.reader_a.randao_mix(state, index)?;
        let b = self.reader_b.randao_mix(state, index).unwrap();
        assert_eq!(a, b);
        Ok(a)
    }
}
