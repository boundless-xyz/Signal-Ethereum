use crate::{Checkpoint, Link};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ConsensusState {
    pub finalized_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub previous_justified_checkpoint: Checkpoint,
}

#[derive(Debug, Error, PartialEq)]
pub enum StateTransitionError {
    #[error("Invalid state transition")]
    CannotEvolveState,
}

impl ConsensusState {
    /// Apply a supermajority link to the current consensus state to obtain a new consensus state.
    pub fn state_transition(&self, link: &Link) -> Result<ConsensusState, StateTransitionError> {
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
                    previous_justified_checkpoint: link.target,
                })
            }
            // Case 2: Justification only. This occurs when the source is an already finalized checkpoint
            Link { source, target }
                if *source == self.finalized_checkpoint
                    && target.epoch == self.current_justified_checkpoint.epoch + 1 =>
            {
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
                    && *source == self.previous_justified_checkpoint =>
            {
                Ok(ConsensusState {
                    finalized_checkpoint: link.source,
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
                previous_justified_checkpoint: cp(2),
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
                previous_justified_checkpoint: cp(3),
            }),
        ),
        // Justify only case
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
    ];

    #[test]
    fn test_state_transition() {
        for (i, (state, link, expected)) in TEST_CASES.iter().enumerate() {
            let result = state.state_transition(link);
            assert_eq!(result, *expected, "Failed for case: {:?}", i);
        }
    }
}
