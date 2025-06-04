use std::cmp::max;

// TODO: Move to context once stabilized
const MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: u64 = 2_u64.pow(7); // in Gwei
const CHURN_LIMIT_QUOTIENT: u64 = 2_u64.pow(16);

/// Return the value that the attesting balance (in Gwei) must meet or exceed
/// for a link to be considered a super-majority link as a function
/// of the total active balance and the lookahead.
///
/// The lookahead is the number of epochs since the last trusted state.
/// total_active_balance is the total active balance at the target epoch in Gwei.
///
/// See docs/safety-and-liveness.md for a detailed explanation of the dynamic threshold
///
pub fn threshold(lookahead: u64, total_active_balance: u64) -> u64 {
    // max churn the beacon chain will allow in an epoch
    let max_epoch_churn = max(
        MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA,
        total_active_balance.saturating_div(CHURN_LIMIT_QUOTIENT),
    );

    // TODO(willem): Also account for slashing, rewards, and inactivity leak

    total_active_balance.saturating_mul(2).saturating_div(3)
        + max_epoch_churn.saturating_mul(2).saturating_mul(lookahead)
}
