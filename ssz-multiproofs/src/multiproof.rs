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

use std::borrow::Cow;

use bitvec::prelude::*;
use sha2::{Digest, Sha256};

use crate::Descriptor;
use crate::error::{Error, Result};

/// An abstraction around a SSZ merkle multi-proof
///
/// This is deserializable and borrows its data to supports zero-copy deserialization.
///
/// The most efficient way to consume a multiproof is via its IntoIterator implementation.
/// It will iterate over (gindex, value) tuples for all gindices added when building.
/// Note this will iterate over the values/gindices in depth-first left-to-right order as they appear in the SSZ merkle tree.
/// This will NOT be the order they were added or increasing order of gindex, it will depend on the shape of the data structure.
///
#[derive(Clone, Debug, PartialEq, Default, serde::Deserialize, serde::Serialize)]
pub struct Multiproof<'a> {
    /// The merkle tree nodes corresponding to both leaves and internal proof nodes
    #[serde(borrow)]
    pub(crate) data: Cow<'a, [u8]>,

    /// mask indicating which nodes are values (1) or proof supporting nodes (0)
    pub(crate) value_mask: BitVec<u32, Lsb0>,

    /// bitvector describing the shape of the proof. See https://github.com/ethereum/consensus-specs/pull/3148
    pub(crate) descriptor: Descriptor,

    /// hint for the depth of the stack needed to verify this proof, useful for preallocation and computing this can be done outside the ZKVM
    pub(crate) max_stack_depth: usize,
}

impl Multiproof<'_> {
    /// Verify this multi-proof against a given root
    #[tracing::instrument(skip(self))]
    pub fn verify<const CHUNK_SIZE: usize>(&self, root: &[u8; CHUNK_SIZE]) -> Result<()> {
        if self.calculate_root::<CHUNK_SIZE>()? == *root {
            Ok(())
        } else {
            Err(Error::RootMismatch)
        }
    }

    /// Calculate the root of this multi-proof
    pub fn calculate_root<const CHUNK_SIZE: usize>(&self) -> Result<[u8; CHUNK_SIZE]> {
        calculate_compact_multi_merkle_root::<CHUNK_SIZE>(
            &self.data,
            &self.descriptor,
            self.max_stack_depth,
        )
    }

    /// Creates an iterator the nodes in this proof along with their gindices
    pub fn nodes<const CHUNK_SIZE: usize>(&self) -> impl Iterator<Item = (u64, &[u8; CHUNK_SIZE])> {
        let nodes = self.data.chunks_exact(CHUNK_SIZE).map(|chunk| {
            let array: &[u8; CHUNK_SIZE] = chunk.try_into().expect("Chunk size mismatch");
            array
        });
        GIndexIterator::new(&self.descriptor).zip(nodes)
    }

    /// Creates an iterator the values in this proof along with their gindices
    pub fn values<const CHUNK_SIZE: usize>(
        &self,
    ) -> ValueIterator<impl Iterator<Item = (u64, &[u8; CHUNK_SIZE])>, CHUNK_SIZE> {
        ValueIterator::new(
            self.nodes::<CHUNK_SIZE>()
                .zip(self.value_mask.iter())
                .filter_map(|(node, is_value)| if *is_value { Some(node) } else { None }),
        )
    }

    /// Finds the node corresponding to a given gindex.
    /// Returns None if the gindex is not in the proof.
    ///
    /// Note this is a linear search, so it's not efficient for large proofs.
    /// If there are a lot of values and you want to use them all it is much more efficient to use the iterator instead
    pub fn get<const CHUNK_SIZE: usize>(&self, gindex: u64) -> Option<&[u8; CHUNK_SIZE]> {
        self.values::<CHUNK_SIZE>()
            .find(|(g, _)| *g == gindex)
            .map(|(_, node)| node)
    }
}

/// An iterator over the values in a multiproof along with their gindices
pub struct ValueIterator<'a, I, const CHUNK_SIZE: usize>
where
    I: Iterator<Item = (u64, &'a [u8; CHUNK_SIZE])>,
{
    inner: I,
}

impl<'a, I, const CHUNK_SIZE: usize> ValueIterator<'a, I, CHUNK_SIZE>
where
    I: Iterator<Item = (u64, &'a [u8; CHUNK_SIZE])>,
{
    fn new(inner: I) -> Self {
        ValueIterator { inner }
    }

    pub fn next_assert_gindex(&mut self, gindex: u64) -> Result<&'a [u8; CHUNK_SIZE]> {
        let (g, node) = self.inner.next().ok_or(Error::MissingValue)?;
        if g == gindex {
            Ok(node)
        } else {
            Err(Error::GIndexMismatch {
                expected: gindex,
                actual: g,
            })
        }
    }
}

impl<'a, I, const CHUNK_SIZE: usize> Iterator for ValueIterator<'a, I, CHUNK_SIZE>
where
    I: Iterator<Item = (u64, &'a [u8; CHUNK_SIZE])>,
{
    type Item = (u64, &'a [u8; CHUNK_SIZE]);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

/// Given a descriptor, iterate over the gindices it describes
struct GIndexIterator<'a> {
    descriptor: &'a Descriptor,
    descriptor_index: usize,
    current_gindex: u64,
    stack: Vec<u64>, // Stack to simulate the traversal
}

impl<'a> GIndexIterator<'a> {
    fn new(descriptor: &'a Descriptor) -> Self {
        GIndexIterator {
            descriptor,
            descriptor_index: 0,
            current_gindex: 1,
            stack: vec![1],
        }
    }
}

impl Iterator for GIndexIterator<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        while self.descriptor_index < self.descriptor.len() {
            let bit = self.descriptor[self.descriptor_index];
            self.descriptor_index += 1;
            if !bit {
                self.stack.push(self.current_gindex);
                self.current_gindex *= 2;
            } else {
                let result = self.current_gindex;
                self.current_gindex = self.stack.pop()? * 2 + 1;
                return Some(result);
            }
        }
        None
    }
}

enum TreeNode<'a, const CHUNK_SIZE: usize> {
    Leaf(&'a [u8]),
    Computed([u8; CHUNK_SIZE]),
    Internal,
}

impl<const CHUNK_SIZE: usize> TreeNode<'_, CHUNK_SIZE> {
    fn has_value(&self) -> bool {
        matches!(self, TreeNode::Leaf(_)) || matches!(self, TreeNode::Computed(_))
    }

    fn is_internal(&self) -> bool {
        matches!(self, TreeNode::Internal)
    }
}

/// Compute the root of a compact multi-proof given the nodes and descriptor
/// This is the hot path so any optimizations belong here.
fn calculate_compact_multi_merkle_root<const CHUNK_SIZE: usize>(
    data: &[u8],
    descriptor: &Descriptor,
    stack_depth_hint: usize,
) -> Result<[u8; CHUNK_SIZE]> {
    // single bounds check for future reads into data
    let leaf_count = descriptor.count_ones();
    assert!(data.len() == leaf_count * CHUNK_SIZE);

    let mut stack = Vec::with_capacity(stack_depth_hint);
    let mut node_index = 0;
    let mut hasher = Sha256::new();
    for bit in descriptor.iter() {
        if *bit {
            let start = node_index * CHUNK_SIZE;
            let slice = unsafe { data.get_unchecked(start..start + CHUNK_SIZE) }; // can skip bounds check thanks to above assertion
            stack.push(TreeNode::Leaf(slice));
            node_index += 1;

            // reduce any leaf pairs on the stack until we can progress no further
            while stack.len() >= 3
                && stack[stack.len() - 1].has_value()
                && stack[stack.len() - 2].has_value()
                && stack[stack.len() - 3].is_internal()
            {
                let right = stack.pop().unwrap();
                let left = stack.pop().unwrap();
                stack.pop(); // pop the internal node and replace with the hashed children

                match left {
                    TreeNode::Leaf(node) => hasher.update(node),
                    TreeNode::Computed(node) => hasher.update(node),
                    _ => return Err(Error::UnexpectedInternalNode),
                }
                match right {
                    TreeNode::Leaf(node) => hasher.update(node),
                    TreeNode::Computed(node) => hasher.update(node),
                    _ => return Err(Error::UnexpectedInternalNode),
                }

                stack.push(TreeNode::<CHUNK_SIZE>::Computed(
                    hasher.finalize_reset().as_slice().try_into().unwrap(),
                ));
            }
        } else {
            stack.push(TreeNode::Internal);
        }
    }
    assert_eq!(stack.len(), 1);
    Ok(match stack.pop().unwrap() {
        TreeNode::Leaf(_) => return Err(Error::UnusedLeaves),
        TreeNode::Computed(node) => node,
        _ => return Err(Error::UnexpectedInternalNode),
    })
}

#[cfg(feature = "builder")]
/// Compute ahead of time what the maximum stack depth will be required to verify a proof with the given descriptor
pub(crate) fn calculate_max_stack_depth(descriptor: &Descriptor) -> usize {
    let mut stack = Vec::new();
    let mut max_stack_depth = 0;
    for bit in descriptor.iter() {
        if *bit {
            stack.push(TreeNode::Computed([0; 32]));
            while stack.len() > 2
                && stack[stack.len() - 1].has_value()
                && stack[stack.len() - 2].has_value()
                && stack[stack.len() - 3].is_internal()
            {
                stack.pop();
                stack.pop();
                stack.pop();
                stack.push(TreeNode::Computed([0; 32]));
                max_stack_depth = max_stack_depth.max(stack.len());
            }
        } else {
            stack.push(TreeNode::Internal);
            max_stack_depth = max_stack_depth.max(stack.len());
        }
    }
    assert_eq!(stack.len(), 1);
    max_stack_depth
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_gindex_iterator() {
        use super::*;

        let descriptor = bitvec![u32, Lsb0; 0,0,1,0,0,1,0,1,1,1,1];
        assert_eq!(
            GIndexIterator::new(&descriptor).collect::<Vec<u64>>(),
            vec![4, 20, 42, 43, 11, 3]
        );
    }
}
