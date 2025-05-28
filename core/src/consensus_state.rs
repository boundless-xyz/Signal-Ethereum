use crate::{Checkpoint, Link};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Default)]
pub struct ConsensusState {
    pub finalized_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub previous_justified_checkpoint: Checkpoint,
}

#[derive(Debug, Error, PartialEq)]
pub enum StateTransitionError {
    #[error("The passed link is invalid")]
    LinkNotValid,
    #[error("Link target is lower than the current justified checkpoint")]
    LinkTargetTooLow,
    #[error("Invalid state transition")]
    CannotEvolveState,
}

impl ConsensusState {
    /// Ensure a consensus state is internally consistent.
    pub fn is_consistent(&self) -> bool {
        self.finalized_checkpoint.epoch < self.current_justified_checkpoint.epoch
            && self.current_justified_checkpoint.epoch >= self.previous_justified_checkpoint.epoch
    }

    /// Apply a supermajority link to the current consensus state to obtain a new consensus state.
    ///
    /// Pre-conditions:
    /// - The consensus state must be internally consistent.
    ///     - the finalized checkpoint must be less than the current justified checkpoint.
    ///     - the current justified checkpoint must be greater than or equal to the previous justified checkpoint.
    ///
    pub fn state_transition(&self, link: &Link) -> Result<ConsensusState, StateTransitionError> {
        if link.target.epoch <= link.source.epoch {
            return Err(StateTransitionError::LinkNotValid);
        }

        if link.target.epoch < self.current_justified_checkpoint.epoch {
            return Err(StateTransitionError::LinkTargetTooLow);
        }

        match link {
            // Case 1: 1-finality. Finalizes and justifies the source and target checkpoints respectively
            // where they are adjacent checkpoints.
            // This applies when the source checkpoint is the current justified checkpoint or the previous justified checkpoint
            Link { source, target }
                if target.epoch == source.epoch + 1
                    && (*source == self.current_justified_checkpoint
                        || *source == self.previous_justified_checkpoint) =>
            {
                Ok(ConsensusState {
                    finalized_checkpoint: link.source,
                    current_justified_checkpoint: link.target,
                    previous_justified_checkpoint: link.source,
                })
            }
            // Case 2: Justification only. This occurs when the source is an already finalized checkpoint
            Link { source, .. } if *source == self.finalized_checkpoint => {
                Ok(ConsensusState {
                    finalized_checkpoint: self.finalized_checkpoint, // no change
                    current_justified_checkpoint: link.target,
                    previous_justified_checkpoint: self.current_justified_checkpoint,
                })
            }
            // Case 3: 2-finality. Finalizes the source checkpoint and justifies the target checkpoint
            // with a link that skips over an intermediate justified checkpoint
            Link { source, target }
                if target.epoch == source.epoch + 2
                    && *source == self.previous_justified_checkpoint
                    && self.current_justified_checkpoint.epoch == source.epoch + 1 =>
            {
                Ok(ConsensusState {
                    finalized_checkpoint: link.source,
                    current_justified_checkpoint: link.target,
                    previous_justified_checkpoint: self.current_justified_checkpoint,
                })
            }
            // Case 4: Justify a future checkpoint without finalizing
            // This occurs when the source is justified but the link skips over one or more unjustified epochs when justifying the target
            // The result is that the target becomes justified but the source does not finalize.
            Link { source, target }
                if target.epoch > source.epoch + 1
                    && (*source == self.current_justified_checkpoint
                        || *source == self.previous_justified_checkpoint) =>
            {
                Ok(ConsensusState {
                    finalized_checkpoint: self.finalized_checkpoint, // no change
                    current_justified_checkpoint: link.target,
                    previous_justified_checkpoint: self.current_justified_checkpoint,
                })
            }
            _ => Err(StateTransitionError::CannotEvolveState),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Checkpoint, Epoch};
    use alloy_primitives::B256;

    const fn cp(epoch: Epoch) -> Checkpoint {
        Checkpoint {
            epoch,
            root: B256::ZERO,
        }
    }

    /// Test cases for the state transition function.
    /// (pre-state, link, expected post-state)
    const TEST_CASES: &[(
        ConsensusState,
        Link,
        Result<ConsensusState, StateTransitionError>,
    )] = &[
        // Simple 1-finality case
        //  F   C   C'           F   C
        // [0]-[1]-[2]  ->  [0]-[1]-[2]
        //      └───┘
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(1),
                previous_justified_checkpoint: cp(1),
            },
            Link {
                source: cp(1),
                target: cp(2),
            },
            Ok(ConsensusState {
                finalized_checkpoint: cp(1),
                current_justified_checkpoint: cp(2),
                previous_justified_checkpoint: cp(1),
            }),
        ),
        // Other 1-finality case
        //  F   P   C   C'               F   C
        // [0]-[1]-[2]-[3]  ->  [0]-[1]-[2]-[3]
        //          └───┘
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(2),
                previous_justified_checkpoint: cp(1),
            },
            Link {
                source: cp(2),
                target: cp(3),
            },
            Ok(ConsensusState {
                finalized_checkpoint: cp(2),
                current_justified_checkpoint: cp(3),
                previous_justified_checkpoint: cp(2),
            }),
        ),
        // Justify only due to finalized source
        //  F   C   C'       F   P   C
        // [0]-[1]-[2]  ->  [0]-[1]-[2]
        //  └───────┘
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(1),
                previous_justified_checkpoint: cp(1),
            },
            Link {
                source: cp(0),
                target: cp(2),
            },
            Ok(ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(2),
                previous_justified_checkpoint: cp(1),
            }),
        ),
        // 2-finality case (other variant)
        //  F   P   C   C'       F       P   C
        // [0]-[1]-[2]-[3]  ->  [0]-[1]-[2]-[3]
        //  └───────────┘
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(2),
                previous_justified_checkpoint: cp(1),
            },
            Link {
                source: cp(0),
                target: cp(3),
            },
            Ok(ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(3),
                previous_justified_checkpoint: cp(2),
            }),
        ),
        // 2-finality case
        //  F   P   C   C'           F   P   C
        // [0]-[1]-[2]-[3]  ->  [0]-[1]-[2]-[3]
        //      └───────┘
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(2),
                previous_justified_checkpoint: cp(1),
            },
            Link {
                source: cp(1),
                target: cp(3),
            },
            Ok(ConsensusState {
                finalized_checkpoint: cp(1),
                current_justified_checkpoint: cp(3),
                previous_justified_checkpoint: cp(2),
            }),
        ),
        // Justify only due to skipping over unjustified checkpoint
        //  F   C       C'       F   P       C
        // [0]-[1]-[2]-[3]  ->  [0]-[1]-[2]-[3]
        //      └───────┘
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(1),
                previous_justified_checkpoint: cp(1),
            },
            Link {
                source: cp(1),
                target: cp(3),
            },
            Ok(ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(3),
                previous_justified_checkpoint: cp(1),
            }),
        ),
        //
        // FAILURE CASES

        // Invalid link
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(1),
                previous_justified_checkpoint: cp(1),
            },
            Link {
                source: cp(2),
                target: cp(2),
            },
            Err(StateTransitionError::LinkNotValid),
        ),
        // Source checkpoint is not justified
        //
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(1),
                previous_justified_checkpoint: cp(1),
            },
            Link {
                source: cp(2),
                target: cp(3),
            },
            Err(StateTransitionError::CannotEvolveState),
        ),
        // Target < current_justified_checkpoint (which is always >= previous_justified_checkpoint)
        // This is the "inner vote" case
        //
        (
            ConsensusState {
                finalized_checkpoint: cp(0),
                current_justified_checkpoint: cp(2),
                previous_justified_checkpoint: cp(2),
            },
            Link {
                source: cp(0),
                target: cp(1),
            },
            Err(StateTransitionError::LinkTargetTooLow),
        ),
    ];

    #[test]
    fn test_state_transition() {
        for (i, (state, link, expected)) in TEST_CASES.iter().enumerate() {
            let result = state.state_transition(link);
            assert_eq!(result, *expected, "Failed for case: {:?}", i);
        }
    }
}
