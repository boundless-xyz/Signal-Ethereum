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

/// Represents the consensus state of the Beacon Chain.
///
/// It tracks the finalized, current justified, and previous justified checkpoints,
/// which are fundamental to the Casper FFG consensus mechanism.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ConsensusState {
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
}

/// Represents errors that can occur during consensus state transitions.
#[derive(Debug, Error, PartialEq)]
pub enum ConsensusError {
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
    // Defines the Solidity struct layouts for Checkpoint and State.
    alloy_sol_types::sol! {
        struct Checkpoint {
            uint64 epoch;
            bytes32 root;
        }

        struct State {
            Checkpoint previous_justified;
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
                previous_justified: (&value.previous_justified_checkpoint).into(),
                current_justified: (&value.current_justified_checkpoint).into(),
                finalized: (&value.finalized_checkpoint).into(),
            }
        }
    }

    impl From<State> for crate::ConsensusState {
        fn from(state: State) -> Self {
            Self {
                previous_justified_checkpoint: state.previous_justified.into(),
                current_justified_checkpoint: state.current_justified.into(),
                finalized_checkpoint: state.finalized.into(),
            }
        }
    }
}

impl ConsensusState {
    /// Applies a supermajority link to the current consensus state to produce a new state.
    ///
    /// This function implements the state transition logic of the Casper FFG finality gadget.
    /// It returns an error if the provided link is invalid for the current state.
    ///
    /// Invariant:
    /// - The consensus state remains internally consistent:
    ///     - finalized_checkpoint <= previous_justified_checkpoint
    ///     - previous_justified_checkpoint <= current_justified_checkpoint
    ///
    /// Pre-condition:
    /// - The input consensus state must be internally consistent.
    pub fn state_transition(&self, link: &Link) -> Result<ConsensusState, ConsensusError> {
        assert!(
            self.is_consistent(),
            "Pre-condition failed: consensus state must be consistent"
        );

        let &Link { source, target } = link;

        // 1-finality:
        // - current_justified, target are adjacent epoch boundaries
        // - current_justified is trivially justified
        // - target is the direct successor of source
        if self.current_justified_checkpoint == source
            && target.epoch() == source.epoch().safe_add(1)?
        {
            return Ok(ConsensusState {
                finalized_checkpoint: source,
                current_justified_checkpoint: target,
                previous_justified_checkpoint: self.current_justified_checkpoint,
            });
        }

        // justification only:
        // - source is justified
        // - target is a subsequent checkpoint of current_justified, but not the successor
        // For a skipped epoch previous_justified get set to current_justified, thus the source
        // must be current_justified.
        if self.current_justified_checkpoint == source
            && target.epoch() > self.current_justified_checkpoint.epoch().safe_add(1)?
        {
            return Ok(ConsensusState {
                finalized_checkpoint: self.finalized_checkpoint, // no change
                current_justified_checkpoint: target,
                previous_justified_checkpoint: self.current_justified_checkpoint,
            });
        }

        // If none of the above rules match, the transition is invalid.
        Err(ConsensusError::InvalidTransition)
    }

    /// Returns the justification link that led to the transition from `self` to `other`, if any.
    ///
    /// This method returns an error, if the state progression was not valid or not supported.
    pub fn transition_link(&self, other: &Self) -> Result<Option<Link>, ConsensusError> {
        assert!(
            self.is_consistent(),
            "Pre-condition failed: consensus state must be consistent"
        );
        // if other is not consistent, the transition is definitely not valid
        ensure!(other.is_consistent(), ConsensusError::InvalidTransition);
        // other must be newer or equal
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

        if self.finalized_checkpoint != other.finalized_checkpoint {
            if other.finalized_checkpoint == self.current_justified_checkpoint
                && target.epoch() - other.finalized_checkpoint.epoch() == 1
            {
                return Ok(Some(Link {
                    source: other.finalized_checkpoint,
                    target,
                }));
            }
            if target.epoch() - other.finalized_checkpoint.epoch() == 2 {
                return Err(ConsensusError::TwoFinality);
            }

            return Err(ConsensusError::InvalidTransition);
        }

        // If no finalization occurred, it implies a skipped epoch. The source for the new
        // justification must be the previous `current_justified_checkpoint`.
        ensure!(
            target.epoch() - self.current_justified_checkpoint.epoch() > 1,
            ConsensusError::InvalidTransition
        );

        Ok(Some(Link {
            source: self.current_justified_checkpoint,
            target,
        }))
    }

    /// Returns whether the current consensus state is consistent.
    #[inline]
    pub fn is_consistent(&self) -> bool {
        self.finalized_checkpoint.epoch() < self.current_justified_checkpoint.epoch()
            && self
                .finalized_checkpoint
                .less_or_equal(&self.previous_justified_checkpoint)
            && self
                .previous_justified_checkpoint
                .less_or_equal(&self.current_justified_checkpoint)
    }

    fn less_or_equal(&self, other: &Self) -> bool {
        self.finalized_checkpoint
            .less_or_equal(&other.finalized_checkpoint)
            && self
                .previous_justified_checkpoint
                .less_or_equal(&other.previous_justified_checkpoint)
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
        abi::State::from(self).abi_encode()
    }

    /// Decodes a `ConsensusState` from its ABI byte representation.
    #[inline]
    pub fn abi_decode(data: &[u8]) -> Result<Self, alloy_sol_types::Error> {
        let state = <abi::State as SolType>::abi_decode(data, true)?;

        Ok(state.into())
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
                        pre_state.current_justified_checkpoint,
                        post_state.current_justified_checkpoint,
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
                previous_justified_checkpoint: cp(1),
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
                previous_justified_checkpoint: cp(2),
                current_justified_checkpoint: cp(2),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(2),
                target: cp(3),
            },
            Ok(ConsensusState {
                previous_justified_checkpoint: cp(2),
                current_justified_checkpoint: cp(3),
                finalized_checkpoint: cp(2),
            }),
        ),
        // Case 3, [Combining GHOST and Casper (Buterin et al., 2020)] Fig. 8
        (
            ConsensusState {
                previous_justified_checkpoint: cp(2),
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
                previous_justified_checkpoint: cp(3),
                current_justified_checkpoint: cp(3),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(3),
                target: cp(4),
            },
            Ok(ConsensusState {
                previous_justified_checkpoint: cp(3),
                current_justified_checkpoint: cp(4),
                finalized_checkpoint: cp(3),
            }),
        ),
        ////// FAILURE CASES //////
        // Invalid link: target epoch is not greater than source
        (
            ConsensusState {
                previous_justified_checkpoint: cp(1),
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
                previous_justified_checkpoint: cp(1),
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
                previous_justified_checkpoint: cp(2),
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
                previous_justified_checkpoint: cp(1),
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
                previous_justified_checkpoint: cp(1),
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
                previous_justified_checkpoint: cp(1),
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
                previous_justified_checkpoint: cp(1),
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
                    post_state.is_consistent(),
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
