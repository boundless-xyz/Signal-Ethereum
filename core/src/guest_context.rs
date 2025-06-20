use crate::Ctx;
#[derive(serde::Serialize, serde::Deserialize)]
pub struct GuestContext;
impl Ctx for GuestContext {
    type Error = ();
    fn slots_per_epoch(&self) -> u64 {
        32u64
    }
    fn effective_balance_increment(&self) -> u64 {
        1000000000u64
    }
    fn max_validators_per_committee(&self) -> usize {
        2048u64 as usize
    }
    fn max_committees_per_slot(&self) -> usize {
        64u64 as usize
    }
    fn epochs_per_historical_vector(&self) -> u64 {
        65536u64
    }
    fn min_seed_lookahead(&self) -> u64 {
        1u64
    }
    fn shuffle_round_count(&self) -> u64 {
        90u64
    }
    fn target_committee_size(&self) -> u64 {
        128u64
    }
    fn max_deposits(&self) -> usize {
        16u64 as usize
    }
}
impl GuestContext {
    pub fn slot_gindex(&self) -> u64 {
        66u64
    }
    pub fn genesis_validators_root_gindex(&self) -> u64 {
        65u64
    }
    pub fn fork_current_version_gindex(&self) -> u64 {
        269u64
    }
    pub fn validators_gindex(&self) -> u64 {
        75u64
    }
    pub fn randao_mixes_0_gindex(&self) -> u64 {
        5046272u64
    }
}
