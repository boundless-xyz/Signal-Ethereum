// Copyright 2024 RISC Zero, Inc.
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

use crate::multiproof::{calculate_max_stack_depth, Multiproof};
use crate::{Descriptor, Result};
#[cfg(feature = "progress-bar")]
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use itertools::Itertools;
use rayon::prelude::*;
use smallvec::SmallVec;
use ssz_rs::prelude::{GeneralizedIndex, GeneralizedIndexable, Path, Prove};
use ssz_rs::proofs::Prover;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::collections::HashSet;
/// The only way to create a multiproof is via this builder.
///
/// The usage process is as follows:
/// - A number of gindices/paths are be registered with the builder
/// - Calling `build` with a SSZ container (type that implements `Prove`) results in a multiproof containing the data at those gindices/paths.
///     This will error if any of the gindices/paths are invalid for the container.
#[derive(Debug)]
pub struct MultiproofBuilder {
    gindices: BTreeSet<GeneralizedIndex>,
}

impl Default for MultiproofBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiproofBuilder {
    pub fn new() -> Self {
        Self {
            gindices: BTreeSet::new(),
        }
    }

    /// Register a path in the container for data to be included in the proof
    /// Paths and gindices are equivalent, but paths are more human-readable
    /// This will be used to retrieve the corresponding 32 byte word from the container at build time
    pub fn with_path<T: GeneralizedIndexable>(mut self, path: Path) -> Self {
        self.gindices
            .insert(T::generalized_index(path).expect("Path is not valid for this type"));
        self
    }

    /// Register a single gindex to be included in the proof.
    /// This will be used to retrieve the corresponding 32 byte word from the container at build time
    pub fn with_gindex(mut self, gindex: GeneralizedIndex) -> Self {
        self.gindices.insert(gindex);
        self
    }

    /// Register an iterator of gindices to be included in the proof
    pub fn with_gindices<I>(mut self, gindices: I) -> Self
    where
        I: IntoIterator<Item = GeneralizedIndex>,
    {
        self.gindices.extend(gindices);
        self
    }

    /// Build the multi-proof for a given container
    #[tracing::instrument(skip(self, container))]
    pub fn build<T: Prove + Sync>(self, container: &T) -> Result<Multiproof<'static>> {
        let gindices = self.gindices.into_iter().collect::<Vec<_>>();

        tracing::debug!("Computing proof indices and value mask");
        let (proof_indices, value_mask) = compute_proof_indices_and_value_mask(&gindices);
        tracing::debug!("Computing proof indices and value mask done");

        tracing::debug!("Computing tree");
        let tree = container.compute_tree()?;
        tracing::debug!("Computing tree done");

        let nodes = proof_indices.par_iter();
        #[cfg(feature = "progress-bar")]
        let nodes = nodes.progress_with(new_progress_bar(
            "Computing proof nodes",
            proof_indices.len(),
        ));
        let nodes: Vec<_> = nodes
            .map(|index| {
                let mut prover = Prover::from(*index);
                prover.compute_proof_cached_tree(container, &tree)?;
                let proof = prover.into_proof();
                Ok(proof.leaf)
            })
            .collect::<Result<Vec<_>>>()?;

        tracing::debug!("Computing proof descriptor");
        let descriptor = compute_proof_descriptor(&proof_indices)?;
        tracing::debug!("Computing proof descriptor done");
        let max_stack_depth = calculate_max_stack_depth(&descriptor);

        let data: Vec<u8> = nodes
            .iter()
            .flat_map(|node| node.as_slice())
            .copied()
            .collect();

        Ok(Multiproof {
            data: Cow::Owned(data),
            descriptor,
            value_mask: value_mask.iter().collect(),
            max_stack_depth,
        })
    }
}

fn compute_proof_indices_and_value_mask(
    indices: &[GeneralizedIndex],
) -> (Vec<GeneralizedIndex>, Vec<bool>) {
    let (all_helper_indices, all_path_indices) = indices
        .par_iter()
        .with_min_len(10000)
        .map(|&index| {
            let branch = get_branch_indices(index);
            let path = get_path_indices(index);
            (
                branch.into_iter().collect::<HashSet<_>>(),
                path.into_iter().collect::<HashSet<_>>(),
            )
        })
        .reduce(
            || (HashSet::new(), HashSet::new()),
            |(mut h1, mut p1), (h2, p2)| {
                h1.extend(h2);
                p1.extend(p2);
                (h1, p1)
            },
        );
    let helper_indices = all_helper_indices
        .difference(&all_path_indices)
        .map(|a| (*a, false));

    let idx_and_mask = helper_indices
        .chain(indices.iter().map(|a| (*a, true)))
        .sorted_by(|(a, _), (b, _)| cmp_binary_lexicographically(*a, *b));

    let (sorted_indices, value_mask) = idx_and_mask.unzip();

    (sorted_indices, value_mask)
}

/// Compare two GeneralizedIndex values lexicographically in the binary representation (without padding).
/// Equivalent to: .sorted_by_key(|(index, _)| format!("{:b}", index))
fn cmp_binary_lexicographically(a: GeneralizedIndex, b: GeneralizedIndex) -> std::cmp::Ordering {
    if a == 0 && b == 0 {
        return std::cmp::Ordering::Equal;
    } else if a == 0 {
        return std::cmp::Ordering::Less;
    } else if b == 0 {
        return std::cmp::Ordering::Greater;
    }

    let a_len = GeneralizedIndex::BITS - a.leading_zeros();
    let b_len = GeneralizedIndex::BITS - b.leading_zeros();

    let a_shifted = a << (GeneralizedIndex::BITS - a_len);
    let b_shifted = b << (GeneralizedIndex::BITS - b_len);

    match a_shifted.cmp(&b_shifted) {
        std::cmp::Ordering::Equal => a_len.cmp(&b_len),
        other => other,
    }
}

fn compute_proof_descriptor(proof_indices: &[GeneralizedIndex]) -> Result<Descriptor> {
    let mut descriptor = Descriptor::new();
    for index in proof_indices {
        descriptor.extend(std::iter::repeat_n(false, index.trailing_zeros() as usize));
        descriptor.push(true);
    }
    Ok(descriptor)
}

fn get_branch_indices(tree_index: GeneralizedIndex) -> SmallVec<[GeneralizedIndex; 64]> {
    let mut focus = sibling(tree_index);
    let mut result = SmallVec::<[GeneralizedIndex; 64]>::new();
    result.push(focus);
    while focus > 1 {
        focus = sibling(parent(focus));
        result.push(focus);
    }
    result.truncate(result.len() - 1);
    result
}

fn get_path_indices(tree_index: GeneralizedIndex) -> SmallVec<[GeneralizedIndex; 64]> {
    let mut focus = tree_index;
    let mut result = SmallVec::<[GeneralizedIndex; 64]>::new();
    result.push(focus);
    while focus > 1 {
        focus = parent(focus);
        result.push(focus);
    }
    result.truncate(result.len() - 1);
    result
}

const fn sibling(index: GeneralizedIndex) -> GeneralizedIndex {
    index ^ 1
}

const fn parent(index: GeneralizedIndex) -> GeneralizedIndex {
    index / 2
}

#[cfg(feature = "progress-bar")]
fn new_progress_bar(msg: &'static str, len: usize) -> ProgressBar {
    let pb_style = ProgressStyle::with_template(
        "{msg} {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] ({pos}/{len}, ETA {eta})",
    )
    .unwrap();
    let pb = ProgressBar::new(len as u64);
    pb.set_message(msg);
    pb.set_style(pb_style);
    pb
}
