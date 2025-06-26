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

use crate::{Checkpoint, Link};
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
    ///     - finalized_checkpoint < current_justified_checkpoint
    ///     - current_justified_checkpoint >= previous_justified_checkpoint
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

        // 2-finality:
        // - previous_justified, current_justified, target are adjacent epoch boundaries
        // - previous_justified, current_justified are trivially justified
        // - target is the second successor of source
        if self.previous_justified_checkpoint == source
            && self.current_justified_checkpoint.epoch() == source.epoch().safe_add(1)?
            && target.epoch() == source.epoch().safe_add(2)?
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
    /// This method panics, if the state progression was not valid.
    pub fn transition_link(&self, other: &Self) -> Option<Link> {
        assert!(self.is_consistent() && other.is_consistent());
        // other must be newer or equal
        assert!(
            self.finalized_checkpoint.epoch() < other.finalized_checkpoint.epoch()
                || self.finalized_checkpoint == other.finalized_checkpoint
        );
        assert!(
            self.previous_justified_checkpoint.epoch()
                < other.previous_justified_checkpoint.epoch()
                || self.previous_justified_checkpoint == other.previous_justified_checkpoint
        );
        assert!(
            self.current_justified_checkpoint.epoch() < other.current_justified_checkpoint.epoch()
                || self.current_justified_checkpoint == other.current_justified_checkpoint
        );

        // If the current justified checkpoint has not changed, no new justification has occurred.
        // In this case, the finalized checkpoint must also be the same.
        if self.current_justified_checkpoint == other.current_justified_checkpoint {
            assert_eq!(self.finalized_checkpoint, other.finalized_checkpoint);

            return None;
        }

        let target = other.current_justified_checkpoint;

        // If a finalization occurred, the source of the finalization must have been one of the
        // previously justified checkpoints in `self`.
        if self.finalized_checkpoint != other.finalized_checkpoint {
            assert!(
                other.finalized_checkpoint == self.current_justified_checkpoint
                    || other.finalized_checkpoint == self.previous_justified_checkpoint
            );

            return Some(Link {
                source: other.finalized_checkpoint,
                target,
            });
        }

        // If no finalization occurred, it implies a skipped epoch. The source for the new
        // justification must be the previous `current_justified_checkpoint`.
        assert!(
            other.current_justified_checkpoint.epoch() - self.current_justified_checkpoint.epoch()
                > 1
        );

        Some(Link {
            source: self.current_justified_checkpoint,
            target,
        })
    }

    /// Ensures a consensus state is internally consistent.
    #[inline]
    pub fn is_consistent(&self) -> bool {
        self.finalized_checkpoint.epoch() <= self.previous_justified_checkpoint.epoch()
            && self.current_justified_checkpoint.epoch()
                >= self.previous_justified_checkpoint.epoch()
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

    const fn cp(epoch: u64) -> Checkpoint {
        Checkpoint::new(Epoch::new(epoch), alloy_primitives::B256::ZERO)
    }

    /// Test cases for the state transition function.
    /// Format: (pre-state, link, expected post-state)
    const TEST_CASES: &[(ConsensusState, Link, Result<ConsensusState, ConsensusError>)] = &[
        // The four cases from [Combining GHOST and Casper (Buterin et al., 2020)] Fig. 8
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
            Ok(ConsensusState {
                previous_justified_checkpoint: cp(2),
                current_justified_checkpoint: cp(3),
                finalized_checkpoint: cp(1),
            }),
        ),
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
            Ok(ConsensusState {
                previous_justified_checkpoint: cp(3),
                current_justified_checkpoint: cp(4),
                finalized_checkpoint: cp(2),
            }),
        ),
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
        // Justify only due to skipping over unjustified checkpoint
        //  F=0, P=1, C=1  + link(1->3)  => F=0, P=1, C=3
        (
            ConsensusState {
                previous_justified_checkpoint: cp(1),
                current_justified_checkpoint: cp(1),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(1),
                target: cp(3),
            },
            Ok(ConsensusState {
                previous_justified_checkpoint: cp(1),
                current_justified_checkpoint: cp(3),
                finalized_checkpoint: cp(0),
            }),
        ),
        (
            ConsensusState {
                previous_justified_checkpoint: cp(1),
                current_justified_checkpoint: cp(3),
                finalized_checkpoint: cp(0),
            },
            Link {
                source: cp(3),
                target: cp(5),
            },
            Ok(ConsensusState {
                previous_justified_checkpoint: cp(3),
                current_justified_checkpoint: cp(5),
                finalized_checkpoint: cp(0),
            }),
        ),
        // Mainnet inactivity leak: supermajority first recovered - justification but no finalization
        (
            ConsensusState {
                previous_justified_checkpoint: cp(200749),
                current_justified_checkpoint: cp(200749),
                finalized_checkpoint: cp(200748),
            },
            Link {
                source: cp(200749),
                target: cp(200759),
            },
            Ok(ConsensusState {
                previous_justified_checkpoint: cp(200749),
                current_justified_checkpoint: cp(200759),
                finalized_checkpoint: cp(200748),
            }),
        ),
        // Mainnet inactivity leak: supermajority - justification and finalization
        (
            ConsensusState {
                previous_justified_checkpoint: cp(200749),
                current_justified_checkpoint: cp(200759),
                finalized_checkpoint: cp(200748),
            },
            Link {
                source: cp(200759),
                target: cp(200760),
            },
            Ok(ConsensusState {
                previous_justified_checkpoint: cp(200759),
                current_justified_checkpoint: cp(200760),
                finalized_checkpoint: cp(200759),
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
                    Some(link.clone()),
                    "Test case {i}: Failed to reconstruct the transition link."
                );
            }
        }
    }
}
