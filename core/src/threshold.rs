/// Return the value that the attesting balance must meet or exceed
/// for a link to be considered a supermajority link as a function
/// of the total active balance and the lookahead.
///
/// The lookahead is the number of epochs since the last trusted state.
///
/// See docs/safety-and-liveness.md for a detailed explaination of the dynamic threshold
///
pub fn threshold(lookahead: u64, total_active_balance: u64) -> u64 {
    total_active_balance.saturating_mul(3).saturating_div(2)
}
