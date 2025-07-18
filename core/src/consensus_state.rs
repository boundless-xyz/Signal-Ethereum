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

use crate::{Checkpoint, Link, ensure};
use alloy_sol_types::{SolType, SolValue};
use safe_arith::{ArithError, SafeArith};
use thiserror::Error;

/// A simplified consensus state for Casper FF.
///
/// This struct tracks the core components required to verify a single-step
/// finality transition, specifically the finalized and currently justified checkpoints.
/// It deliberately omits `previous_justified_checkpoint` to prevent the handling
/// of complex 2-finality cases, aligning with the formal model's assumptions.
#[derive(Debug, Clone, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ConsensusState {
    current_justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
}

/// Represents errors that can occur during consensus state transitions.
#[derive(Debug, Error, PartialEq)]
pub enum ConsensusError {
    #[error("Invalid state")]
    InvalidState,
    #[error("Invalid state transition")]
    InvalidTransition,
    #[error("2-finality not supported")]
    TwoFinality,
    #[error("Arithmetic error: {0:?}")]
    ArithError(ArithError),
}

impl From<ArithError> for ConsensusError {
    fn from(err: ArithError) -> Self {
        ConsensusError::ArithError(err)
    }
}

/// Private module for ABI encoding and decoding, mapping Rust types to Solidity types.
mod abi {
    use crate::{ConsensusError, ensure};

    // Defines the Solidity struct layouts for Checkpoint and State.
    alloy_sol_types::sol! {
        struct Checkpoint {
            uint64 epoch;
            bytes32 root;
        }

        struct State {
            Checkpoint current_justified;
            Checkpoint finalized;
        }
    }

    // ABI conversions for Checkpoint.
    impl From<&crate::Checkpoint> for Checkpoint {
        fn from(value: &crate::Checkpoint) -> Self {
            Self {
                epoch: value.0.epoch.as_u64(),
                root: value.0.root,
            }
        }
    }

    impl From<Checkpoint> for crate::Checkpoint {
        fn from(checkpoint: Checkpoint) -> Self {
            Self(beacon_types::Checkpoint {
                epoch: crate::Epoch::new(checkpoint.epoch),
                root: checkpoint.root,
            })
        }
    }

    // ABI conversions for ConsensusState.
    impl From<&crate::ConsensusState> for State {
        fn from(value: &crate::ConsensusState) -> Self {
            Self {
                current_justified: (&value.current_justified_checkpoint).into(),
                finalized: (&value.finalized_checkpoint).into(),
            }
        }
    }

    impl TryFrom<State> for crate::ConsensusState {
        type Error = ConsensusError;

        fn try_from(state: State) -> Result<Self, Self::Error> {
            let state = Self {
                current_justified_checkpoint: state.current_justified.into(),
                finalized_checkpoint: state.finalized.into(),
            };
            ensure!(state.is_valid(), ConsensusError::InvalidState);
            Ok(state)
        }
    }
}

impl ConsensusState {
    /// Constructs a new `ConsensusState`.
    ///
    /// It panics if the provided checkpoints form an invalid state (i.e., if
    /// `finalized_checkpoint.epoch >= current_justified_checkpoint.epoch`).
    #[inline]
    #[must_use]
    pub fn new(current_justified_checkpoint: Checkpoint, finalized_checkpoint: Checkpoint) -> Self {
        let state = Self {
            current_justified_checkpoint,
            finalized_checkpoint,
        };
        assert!(state.is_valid());
        state
    }

    /// Returns the finalized checkpoint of the consensus state.
    #[inline]
    pub fn finalized_checkpoint(&self) -> Checkpoint {
        self.finalized_checkpoint
    }

    /// Returns the current justified checkpoint of the consensus state.
    #[inline]
    pub fn current_justified_checkpoint(&self) -> Checkpoint {
        self.current_justified_checkpoint
    }

    /// Checks if the consensus state is valid.
    ///
    /// A state is considered valid if the epoch of the finalized checkpoint is strictly
    /// less than the epoch of the current justified checkpoint or if it is all zero.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.finalized_checkpoint.epoch() < self.current_justified_checkpoint.epoch()
            || self == &ConsensusState::default()
    }

    /// Applies a single supermajority link to the current consensus state to produce a new state.
    ///
    /// This function implements the core state transition logic of Casper FFG
    /// for a single step in a chain of justifications. It correctly handles both
    /// justification-only and finalization cases for a 1-epoch link.
    ///
    /// Invariant:
    /// - The resulting consensus state is always valid, i.e.,
    ///   `finalized_checkpoint.epoch() < current_justified_checkpoint.epoch()`.
    pub fn state_transition(&self, link: &Link) -> Result<ConsensusState, ConsensusError> {
        assert!(self.is_valid());

        let &Link { source, target } = link;

        // Case 1: Finalization (1-finality)
        // The link's source is the current justified checkpoint, and its target is the next epoch.
        // This finalizes the source and justifies the target.
        if self.current_justified_checkpoint == source
            && target.epoch() == source.epoch().safe_add(1)?
        {
            return Ok(ConsensusState {
                finalized_checkpoint: source,
                current_justified_checkpoint: target,
            });
        }

        // Case 2: Justification Only
        // The link's source is the current justified checkpoint, but it skips one or more epochs.
        // This justifies the new target but does not advance finality.
        if self.current_justified_checkpoint == source
            && target.epoch() > self.current_justified_checkpoint.epoch().safe_add(1)?
        {
            return Ok(ConsensusState {
                finalized_checkpoint: self.finalized_checkpoint, // no change
                current_justified_checkpoint: target,
            });
        }

        // If none of the above rules match, the transition is invalid.
        Err(ConsensusError::InvalidTransition)
    }

    /// Computes the supermajority link that must have existed to transition from `self` to `other`.
    ///
    /// This method acts as the inverse of `state_transition` and is useful for reconstructing
    /// the chain of justifications between two states.
    ///
    /// # Errors
    ///
    /// Returns an error if the transition from `self` to `other` is not a valid,
    /// supported FFG state progression. This includes unsupported 2-finality cases.
    pub fn transition_link(&self, other: &Self) -> Result<Option<Link>, ConsensusError> {
        assert!(self.is_valid());
        // The target state must also be valid and not older than the current state.
        ensure!(other.is_valid(), ConsensusError::InvalidTransition);
        ensure!(self.less_or_equal(other), ConsensusError::InvalidTransition);

        // If the current justified checkpoint has not changed, no new justification has occurred.
        // In this case, the finalized checkpoint must also be the same.
        if self.current_justified_checkpoint == other.current_justified_checkpoint {
            ensure!(
                self.finalized_checkpoint == other.finalized_checkpoint,
                ConsensusError::InvalidTransition
            );

            return Ok(None);
        }

        let target = other.current_justified_checkpoint;

        // Case 1: Finality was advanced
        if self.finalized_checkpoint != other.finalized_checkpoint {
            // 1-finality: the new finalized must be our previous `current_justified_checkpoint`
            if other.finalized_checkpoint == self.current_justified_checkpoint
                && target.epoch() - other.finalized_checkpoint.epoch() == 1
            {
                return Ok(Some(Link {
                    source: other.finalized_checkpoint,
                    target,
                }));
            }
            // A jump of 2 epochs would imply 2-finality, which is unsupported.
            if target.epoch() - other.finalized_checkpoint.epoch() == 2 {
                return Err(ConsensusError::TwoFinality);
            }

            return Err(ConsensusError::InvalidTransition);
        }

        // Case 2: Justification only (skipped epoch).
        // The source must be our previous `current_justified_checkpoint`.
        ensure!(
            target.epoch() - self.current_justified_checkpoint.epoch() > 1,
            ConsensusError::InvalidTransition
        );

        Ok(Some(Link {
            source: self.current_justified_checkpoint,
            target,
        }))
    }

    fn less_or_equal(&self, other: &Self) -> bool {
        self.finalized_checkpoint
            .less_or_equal(&other.finalized_checkpoint)
            && self
                .current_justified_checkpoint
                .less_or_equal(&other.current_justified_checkpoint)
    }

    /// Returns the size of the ABI-encoded state in bytes.
    #[inline]
    pub const fn abi_encoded_size() -> usize {
        // `unwrap` is safe as the size is fixed and known at compile time.
        abi::State::ENCODED_SIZE.unwrap()
    }

    /// Encodes the `ConsensusState` into its ABI byte representation.
    #[inline]
    pub fn abi_encode(&self) -> Vec<u8> {
        assert!(self.is_valid());
        abi::State::from(self).abi_encode()
    }

    /// Decodes a `ConsensusState` from its ABI byte representation.
    #[inline]
    pub fn abi_decode(data: &[u8]) -> Result<Self, alloy_sol_types::Error> {
        let state = <abi::State as SolType>::abi_decode(data)?;
        state
            .try_into()
            .map_err(|err: ConsensusError| alloy_sol_types::Error::custom(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Checkpoint, Epoch};

    #[test]
    fn test_mainnet_state_transitions() {
        let json_data = include_str!("./fixtures/mainnet-transitions.json");
        let test_cases: Vec<(ConsensusState, ConsensusState)> =
            serde_json::from_str(json_data).unwrap();

        for (i, (pre_state, post_state)) in test_cases.iter().enumerate() {
            // use `transition_link` to determine the `Link`
            match pre_state.transition_link(post_state) {
                // This is the expected path for a valid transition.
                Ok(Some(link)) => {
                    let result = pre_state.state_transition(&link);

                    assert_eq!(
                        result.as_ref().ok(),
                        Some(post_state),
                        "JSON Test Case {i} Failed: state_transition result mismatch.\n\
                         Pre-state:  {pre_state:?}\n\
                         Derived Link: {link:?}\n\
                         Expected:   {post_state:?}\n\
                         Got:        {result:?}"
                    );
                }
                // This case handles no state change.
                Ok(None) => {
                    assert_eq!(
                        pre_state, post_state,
                        "JSON Test Case {i} Failed: transition_link was None, but states differ."
                    );
                }
                // This case handles not supported 2-finality.
                Err(ConsensusError::TwoFinality) => {
                    assert!(
                        pre_state.finalized_checkpoint != post_state.finalized_checkpoint
                            && post_state.current_justified_checkpoint.epoch()
                                - post_state.finalized_checkpoint.epoch()
                                == 2
                    );
                }
                // This case handles invalid transitions between the pairs in your JSON.
                Err(e) => {
                    panic!(
                        "JSON Test Case {i} Failed: Could not determine a valid link.\n\
                         Pre-state:  {pre_state:?}\n\
                         Post-state: {post_state:?}\n\
                         Error:      {e:?}"
                    );
                }
            }
        }
    }

    const fn cp(epoch: u64) -> Checkpoint {
        Checkpoint::new(Epoch::new(epoch), alloy_primitives::B256::ZERO)
    }

    const TEST_CASES: &[(ConsensusState, Link, Result<ConsensusState, ConsensusError>)] = &[
        // Case 1, [Combining GHOST and Casper (Buterin et al., 2020)] Fig. 8
        (
            ConsensusState {
                current_justified_checkpoint: cp(2),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(1),
                target: cp(3),
            },
            Err(ConsensusError::InvalidTransition), // 2-finality
        ),
        // Case 2, [Combining GHOST and Casper (Buterin et al., 2020)] Fig. 8
        (
            ConsensusState {
                current_justified_checkpoint: cp(2),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(2),
                target: cp(3),
            },
            Ok(ConsensusState {
                current_justified_checkpoint: cp(3),
                finalized_checkpoint: cp(2),
            }),
        ),
        // Case 3, [Combining GHOST and Casper (Buterin et al., 2020)] Fig. 8
        (
            ConsensusState {
                current_justified_checkpoint: cp(3),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(2),
                target: cp(4),
            },
            Err(ConsensusError::InvalidTransition), // 2-finality
        ),
        // Case 4, [Combining GHOST and Casper (Buterin et al., 2020)] Fig. 8
        (
            ConsensusState {
                current_justified_checkpoint: cp(3),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(3),
                target: cp(4),
            },
            Ok(ConsensusState {
                current_justified_checkpoint: cp(4),
                finalized_checkpoint: cp(3),
            }),
        ),
        ////// FAILURE CASES //////
        // Invalid link: target epoch is not greater than source
        (
            ConsensusState {
                current_justified_checkpoint: cp(1),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(1),
                target: cp(1),
            },
            Err(ConsensusError::InvalidTransition),
        ),
        // Source checkpoint is not justified
        (
            ConsensusState {
                current_justified_checkpoint: cp(1),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(2),
                target: cp(3),
            },
            Err(ConsensusError::InvalidTransition),
        ),
        // Source checkpoint not verifiably justified (source is not p_j or c_j)
        (
            ConsensusState {
                current_justified_checkpoint: cp(2),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(1),
                target: cp(3),
            },
            Err(ConsensusError::InvalidTransition),
        ),
        // Source checkpoint too old (older than previous_justified_checkpoint)
        (
            ConsensusState {
                current_justified_checkpoint: cp(2),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(0),
                target: cp(4),
            },
            Err(ConsensusError::InvalidTransition),
        ),
        // Link does not match a finality rule
        (
            ConsensusState {
                current_justified_checkpoint: cp(2),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(1),
                target: cp(4), // Should be cp(3) for 2-epoch finality
            },
            Err(ConsensusError::InvalidTransition),
        ),
        // Duplicate justification
        (
            ConsensusState {
                current_justified_checkpoint: cp(2),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(1),
                target: cp(2), // Target is not after current_justified
            },
            Err(ConsensusError::InvalidTransition),
        ),
        // Target < current_justified_checkpoint
        (
            ConsensusState {
                current_justified_checkpoint: cp(3),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(1),
                target: cp(2),
            },
            Err(ConsensusError::InvalidTransition),
        ),
    ];

    #[test]
    fn test_state_transition() {
        for (i, (pre_state, link, expected)) in TEST_CASES.iter().enumerate() {
            let result = pre_state.state_transition(link);
            assert_eq!(
                result, *expected,
                "Test case {i}: Mismatch in state_transition result.\n\
                Pre-state: {pre_state:?}\n\
                Link: {link:?}"
            );

            // if the transition was successful, check that `transition_link` can be reconstructed.
            if let Ok(post_state) = result {
                assert!(
                    post_state.is_valid(),
                    "Test case {i}: Post-state is not consistent."
                );
                assert_eq!(
                    pre_state.transition_link(&post_state),
                    Ok(Some(link.clone())),
                    "Test case {i}: Failed to reconstruct the transition link."
                );
            }
        }
    }
}
