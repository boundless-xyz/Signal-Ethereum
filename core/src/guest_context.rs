use crate::Ctx;
#[derive(serde::Serialize, serde::Deserialize)]
pub struct GuestContext;
impl Ctx for GuestContext {
    type Error = ();
    fn slots_per_epoch(&self) -> u64 {
        32u64 as u64
    }
    fn effective_balance_increment(&self) -> u64 {
        1000000000u64 as u64
    }
    fn max_validators_per_committee(&self) -> usize {
        2048u64 as usize
    }
    fn max_committees_per_slot(&self) -> usize {
        64u64 as usize
    }
    fn epochs_per_historical_vector(&self) -> u64 {
        65536u64 as u64
    }
    fn min_seed_lookahead(&self) -> u64 {
        1u64 as u64
    }
    fn shuffle_round_count(&self) -> u64 {
        90u64 as u64
    }
    fn target_committee_size(&self) -> u64 {
        128u64 as u64
    }
    fn max_deposits(&self) -> usize {
        16u64 as usize
    }
}
impl GuestContext {
    fn slot_gindex(&self) -> usize {
        66u64 as usize
    }
    fn genesis_validators_root_gindex(&self) -> usize {
        65u64 as usize
    }
    fn fork_current_version_gindex(&self) -> usize {
        269u64 as usize
    }
    fn validators_gindex(&self) -> usize {
        75u64 as usize
    }
}
