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

        let descriptor = compute_proof_descriptor(&gindices)?;
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

fn compute_proof_indices(indices: &[GeneralizedIndex]) -> Vec<GeneralizedIndex> {
    let mut indices_set: HashSet<GeneralizedIndex> = HashSet::new();
    for &index in indices {
        let helper_indices = get_helper_indices(&[index]);
        for helper_index in helper_indices {
            indices_set.insert(helper_index);
        }
    }
    for &index in indices {
        let path_indices = get_path_indices(index);
        for path_index in path_indices {
            indices_set.remove(&path_index);
        }
        indices_set.insert(index);
    }
    let mut sorted_indices: Vec<GeneralizedIndex> = indices_set.into_iter().collect();
    sorted_indices.sort_by_key(|index| format!("{:b}", *index));
    sorted_indices
}

fn compute_proof_indices_and_value_mask(
    indices: &[GeneralizedIndex],
) -> (Vec<GeneralizedIndex>, Vec<bool>) {
    let mut all_helper_indices = HashSet::new();
    let mut all_path_indices = HashSet::new();

    for index in indices {
        all_helper_indices.extend(get_branch_indices(*index).iter());
        all_path_indices.extend(get_path_indices(*index).iter());
    }

    let helper_indices = all_helper_indices
        .difference(&all_path_indices)
        .map(|a| (a, false));

    let ind = helper_indices
        .chain(indices.iter().map(|a| (a, true)))
        .sorted_by_key(|(index, _)| format!("{:b}", index));

    let (sorted_indices, value_mask) = ind.unzip();

    (sorted_indices, value_mask)
}

fn compute_proof_descriptor(indices: &[GeneralizedIndex]) -> Result<Descriptor> {
    let indices = compute_proof_indices(indices);
    let mut descriptor = Descriptor::new();
    for index in indices {
        descriptor.extend(std::iter::repeat_n(false, index.trailing_zeros() as usize));
        descriptor.push(true);
    }
    Ok(descriptor)
}

fn get_branch_indices(tree_index: GeneralizedIndex) -> Vec<GeneralizedIndex> {
    let mut focus = sibling(tree_index);
    let mut result = vec![focus];
    while focus > 1 {
        focus = sibling(parent(focus));
        result.push(focus);
    }
    result.truncate(result.len() - 1);
    result
}

fn get_path_indices(tree_index: GeneralizedIndex) -> Vec<GeneralizedIndex> {
    let mut focus = tree_index;
    let mut result = vec![focus];
    while focus > 1 {
        focus = parent(focus);
        result.push(focus);
    }
    result.truncate(result.len() - 1);
    result
}

fn get_helper_indices(indices: &[GeneralizedIndex]) -> Vec<GeneralizedIndex> {
    let mut all_helper_indices = HashSet::new();
    let mut all_path_indices = HashSet::new();

    for index in indices {
        all_helper_indices.extend(get_branch_indices(*index).iter());
        all_path_indices.extend(get_path_indices(*index).iter());
    }

    let mut all_branch_indices = all_helper_indices
        .difference(&all_path_indices)
        .cloned()
        .collect::<Vec<_>>();
    all_branch_indices.sort_by(|a: &GeneralizedIndex, b: &GeneralizedIndex| b.cmp(a));
    all_branch_indices
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
