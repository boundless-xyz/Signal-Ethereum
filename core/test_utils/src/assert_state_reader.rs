use alloy_primitives::B256;
use std::iter;
use z_core::{Epoch, StateReader, ValidatorIndex, ValidatorInfo, Version};

/// Merge two state readers into one and assert that their results are equal.
/// Useful for testing that two implementations of `StateReader` yield the same results
/// when used in a particular context
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

    fn epoch(&self) -> Epoch {
        assert_eq!(self.reader_a.epoch(), self.reader_b.epoch());
        self.reader_a.epoch()
    }

    fn context(&self) -> &S::Context {
        self.reader_a.context()
    }

    fn genesis_validators_root(&self) -> B256 {
        let a = self.reader_a.genesis_validators_root();
        let b = self.reader_b.genesis_validators_root();
        assert_eq!(a, b, "Genesis validators root mismatch");
        a
    }

    fn fork_current_version(&self) -> Result<Version, Self::Error> {
        let a = self.reader_a.fork_current_version()?;
        let b = self.reader_b.fork_current_version().unwrap();
        assert_eq!(a, b, "Fork version mismatch");
        Ok(a)
    }

    fn active_validators(
        &self,
        epoch: Epoch,
    ) -> Result<impl Iterator<Item = (ValidatorIndex, &ValidatorInfo)>, Self::Error> {
        let mut iter_a = self.reader_a.active_validators(epoch)?;
        let mut iter_b = self.reader_b.active_validators(epoch).unwrap().enumerate();
        Ok(iter::from_fn(move || {
            match (iter_a.next(), iter_b.next()) {
                (None, None) => None,
                (Some(a), Some((i, b))) => {
                    assert_eq!(
                        a, b,
                        "Active validator mismatch for validator {i} at epoch {epoch}"
                    );
                    Some(a)
                }
                (a, b) => panic!("Wrong size: empty={}, empty={}", a.is_none(), b.is_none()),
            }
        }))
    }

    fn randao_mix(&self, state: Epoch, index: usize) -> Result<Option<B256>, Self::Error> {
        let a = self.reader_a.randao_mix(state, index)?;
        let b = self.reader_b.randao_mix(state, index).unwrap();
        assert_eq!(
            a, b,
            "Randao mix mismatch for epoch {state} and index {index}",
        );
        Ok(a)
    }
}
