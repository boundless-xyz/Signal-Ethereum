use ethereum_consensus::{
    Fork as Version,
    altair::{self},
    bellatrix::{self},
    capella::{self},
    deneb::{
        self, Checkpoint, Fork, JUSTIFICATION_BITS_LENGTH, ParticipationFlags, PendingAttestation,
    },
    phase0::{self, BeaconBlockHeader, Validator},
    primitives::{Bytes32, Gwei, Root, Slot},
    ssz::prelude::*,
};
// TODO(ec2): Remove all of this when electra is properly implemented in upstream ethereum-consensus

pub mod mainnet {
    use ethereum_consensus::{
        electra::mainnet::{
            BYTES_PER_LOGS_BLOOM, EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR,
            ETH1_DATA_VOTES_BOUND, HISTORICAL_ROOTS_LIMIT, MAX_EXTRA_DATA_BYTES,
            MAX_VALIDATORS_PER_COMMITTEE, PENDING_CONSOLIDATIONS_LIMIT, PENDING_DEPOSITS_LIMIT,
            PENDING_PARTIAL_WITHDRAWALS_LIMIT, SLOTS_PER_HISTORICAL_ROOT, SYNC_COMMITTEE_SIZE,
            VALIDATOR_REGISTRY_LIMIT,
        },
        phase0::mainnet::PENDING_ATTESTATIONS_BOUND,
    };
    pub type BeaconState = super::BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >;
    pub type ElectraBeaconState = super::electra::BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >;
}

mod electra {
    use ethereum_consensus::electra::{
        DepositReceipt, PendingConsolidation, PendingPartialWithdrawal,
    };
    use ethereum_consensus::serde::{as_str, seq_of_str};
    use ethereum_consensus::{
        altair::SyncCommittee,
        capella::HistoricalSummary,
        electra::ExecutionPayloadHeader,
        phase0::{
            BeaconBlockHeader, Checkpoint, Eth1Data, Fork, JUSTIFICATION_BITS_LENGTH, Validator,
        },
        primitives::{
            Bytes32, Epoch, Gwei, ParticipationFlags, Root, Slot, ValidatorIndex, WithdrawalIndex,
        },
    };
    use ssz_rs::prelude::*;
    #[derive(
        Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
    )]
    pub struct BeaconState<
        const SLOTS_PER_HISTORICAL_ROOT: usize,
        const HISTORICAL_ROOTS_LIMIT: usize,
        const ETH1_DATA_VOTES_BOUND: usize,
        const VALIDATOR_REGISTRY_LIMIT: usize,
        const EPOCHS_PER_HISTORICAL_VECTOR: usize,
        const EPOCHS_PER_SLASHINGS_VECTOR: usize,
        const MAX_VALIDATORS_PER_COMMITTEE: usize,
        const SYNC_COMMITTEE_SIZE: usize,
        const BYTES_PER_LOGS_BLOOM: usize,
        const MAX_EXTRA_DATA_BYTES: usize,
        const PENDING_DEPOSITS_LIMIT: usize,
        const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize,
        const PENDING_CONSOLIDATIONS_LIMIT: usize,
    > {
        #[serde(with = "as_str")]
        pub genesis_time: u64,
        pub genesis_validators_root: Root,
        #[serde(with = "as_str")]
        pub slot: Slot,
        pub fork: Fork,
        pub latest_block_header: BeaconBlockHeader,
        pub block_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
        pub state_roots: Vector<Root, SLOTS_PER_HISTORICAL_ROOT>,
        pub historical_roots: List<Root, HISTORICAL_ROOTS_LIMIT>,
        pub eth1_data: Eth1Data,
        pub eth1_data_votes: List<Eth1Data, ETH1_DATA_VOTES_BOUND>,
        #[serde(with = "as_str")]
        pub eth1_deposit_index: u64,
        pub validators: List<Validator, VALIDATOR_REGISTRY_LIMIT>,
        #[serde(with = "seq_of_str")]
        pub balances: List<Gwei, VALIDATOR_REGISTRY_LIMIT>,
        pub randao_mixes: Vector<Bytes32, EPOCHS_PER_HISTORICAL_VECTOR>,
        #[serde(with = "seq_of_str")]
        pub slashings: Vector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>,
        #[serde(with = "seq_of_str")]
        pub previous_epoch_participation: List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>,
        #[serde(with = "seq_of_str")]
        pub current_epoch_participation: List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>,
        pub justification_bits: Bitvector<JUSTIFICATION_BITS_LENGTH>,
        pub previous_justified_checkpoint: Checkpoint,
        pub current_justified_checkpoint: Checkpoint,
        pub finalized_checkpoint: Checkpoint,
        #[serde(with = "seq_of_str")]
        pub inactivity_scores: List<u64, VALIDATOR_REGISTRY_LIMIT>,
        pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
        pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
        pub latest_execution_payload_header:
            ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
        #[serde(with = "as_str")]
        pub next_withdrawal_index: WithdrawalIndex,
        #[serde(with = "as_str")]
        pub next_withdrawal_validator_index: ValidatorIndex,
        pub historical_summaries: List<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>,
        #[serde(with = "as_str")]
        pub deposit_requests_start_index: u64,
        #[serde(with = "as_str")]
        pub deposit_balance_to_consume: Gwei,
        #[serde(with = "as_str")]
        pub exit_balance_to_consume: Gwei,
        #[serde(with = "as_str")]
        pub earliest_exit_epoch: Epoch,
        #[serde(with = "as_str")]
        pub consolidation_balance_to_consume: Gwei,
        #[serde(with = "as_str")]
        pub earliest_consolidation_epoch: Epoch,
        pub pending_deposits: List<DepositReceipt, PENDING_DEPOSITS_LIMIT>,
        pub pending_partial_withdrawals:
            List<PendingPartialWithdrawal, PENDING_PARTIAL_WITHDRAWALS_LIMIT>,
        pub pending_consolidations: List<PendingConsolidation, PENDING_CONSOLIDATIONS_LIMIT>,
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    GeneralizedIndexable,
    Prove,
    Serializable,
    HashTreeRoot,
    serde::Serialize,
)]
#[ssz(transparent)]
#[serde(untagged)]
pub enum BeaconState<
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const ETH1_DATA_VOTES_BOUND: usize,
    const VALIDATOR_REGISTRY_LIMIT: usize,
    const EPOCHS_PER_HISTORICAL_VECTOR: usize,
    const EPOCHS_PER_SLASHINGS_VECTOR: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const PENDING_ATTESTATIONS_BOUND: usize,
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
    const PENDING_DEPOSITS_LIMIT: usize,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize,
    const PENDING_CONSOLIDATIONS_LIMIT: usize,
> {
    Phase0(
        phase0::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            PENDING_ATTESTATIONS_BOUND,
        >,
    ),
    Altair(
        altair::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
        >,
    ),
    Bellatrix(
        bellatrix::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
    Capella(
        capella::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
    Deneb(
        deneb::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >,
    ),
    Electra(
        electra::BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_BOUND,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            MAX_VALIDATORS_PER_COMMITTEE,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            PENDING_DEPOSITS_LIMIT,
            PENDING_PARTIAL_WITHDRAWALS_LIMIT,
            PENDING_CONSOLIDATIONS_LIMIT,
        >,
    ),
}

impl<
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const ETH1_DATA_VOTES_BOUND: usize,
    const VALIDATOR_REGISTRY_LIMIT: usize,
    const EPOCHS_PER_HISTORICAL_VECTOR: usize,
    const EPOCHS_PER_SLASHINGS_VECTOR: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const PENDING_ATTESTATIONS_BOUND: usize,
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
    const PENDING_DEPOSITS_LIMIT: usize,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize,
    const PENDING_CONSOLIDATIONS_LIMIT: usize,
>
    BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >
{
    pub fn version(&self) -> Version {
        match self {
            Self::Phase0(_) => Version::Phase0,
            Self::Altair(_) => Version::Altair,
            Self::Bellatrix(_) => Version::Bellatrix,
            Self::Capella(_) => Version::Capella,
            Self::Deneb(_) => Version::Deneb,
            Self::Electra(_) => Version::Electra,
        }
    }

    pub fn genesis_validators_root(&self) -> Root {
        match self {
            Self::Phase0(inner) => inner.genesis_validators_root,
            Self::Altair(inner) => inner.genesis_validators_root,
            Self::Bellatrix(inner) => inner.genesis_validators_root,
            Self::Capella(inner) => inner.genesis_validators_root,
            Self::Deneb(inner) => inner.genesis_validators_root,
            Self::Electra(inner) => inner.genesis_validators_root,
        }
    }
    pub fn genesis_validators_root_mut(&mut self) -> &mut Root {
        match self {
            Self::Phase0(inner) => &mut inner.genesis_validators_root,
            Self::Altair(inner) => &mut inner.genesis_validators_root,
            Self::Bellatrix(inner) => &mut inner.genesis_validators_root,
            Self::Capella(inner) => &mut inner.genesis_validators_root,
            Self::Deneb(inner) => &mut inner.genesis_validators_root,
            Self::Electra(inner) => &mut inner.genesis_validators_root,
        }
    }
    pub fn slot(&self) -> Slot {
        match self {
            Self::Phase0(inner) => inner.slot,
            Self::Altair(inner) => inner.slot,
            Self::Bellatrix(inner) => inner.slot,
            Self::Capella(inner) => inner.slot,
            Self::Deneb(inner) => inner.slot,
            Self::Electra(inner) => inner.slot,
        }
    }

    pub fn fork(&self) -> &Fork {
        match self {
            Self::Phase0(inner) => &inner.fork,
            Self::Altair(inner) => &inner.fork,
            Self::Bellatrix(inner) => &inner.fork,
            Self::Capella(inner) => &inner.fork,
            Self::Deneb(inner) => &inner.fork,
            Self::Electra(inner) => &inner.fork,
        }
    }

    pub fn latest_block_header(&self) -> &BeaconBlockHeader {
        match self {
            Self::Phase0(inner) => &inner.latest_block_header,
            Self::Altair(inner) => &inner.latest_block_header,
            Self::Bellatrix(inner) => &inner.latest_block_header,
            Self::Capella(inner) => &inner.latest_block_header,
            Self::Deneb(inner) => &inner.latest_block_header,
            Self::Electra(inner) => &inner.latest_block_header,
        }
    }

    pub fn block_roots(&self) -> &Vector<Root, SLOTS_PER_HISTORICAL_ROOT> {
        match self {
            Self::Phase0(inner) => &inner.block_roots,
            Self::Altair(inner) => &inner.block_roots,
            Self::Bellatrix(inner) => &inner.block_roots,
            Self::Capella(inner) => &inner.block_roots,
            Self::Deneb(inner) => &inner.block_roots,
            Self::Electra(inner) => &inner.block_roots,
        }
    }

    pub fn state_roots(&self) -> &Vector<Root, SLOTS_PER_HISTORICAL_ROOT> {
        match self {
            Self::Phase0(inner) => &inner.state_roots,
            Self::Altair(inner) => &inner.state_roots,
            Self::Bellatrix(inner) => &inner.state_roots,
            Self::Capella(inner) => &inner.state_roots,
            Self::Deneb(inner) => &inner.state_roots,
            Self::Electra(inner) => &inner.state_roots,
        }
    }

    pub fn historical_roots(&self) -> &List<Root, HISTORICAL_ROOTS_LIMIT> {
        match self {
            Self::Phase0(inner) => &inner.historical_roots,
            Self::Altair(inner) => &inner.historical_roots,
            Self::Bellatrix(inner) => &inner.historical_roots,
            Self::Capella(inner) => &inner.historical_roots,
            Self::Deneb(inner) => &inner.historical_roots,
            Self::Electra(inner) => &inner.historical_roots,
        }
    }
    pub fn historical_roots_mut(&mut self) -> &mut List<Root, HISTORICAL_ROOTS_LIMIT> {
        match self {
            Self::Phase0(inner) => &mut inner.historical_roots,
            Self::Altair(inner) => &mut inner.historical_roots,
            Self::Bellatrix(inner) => &mut inner.historical_roots,
            Self::Capella(inner) => &mut inner.historical_roots,
            Self::Deneb(inner) => &mut inner.historical_roots,
            Self::Electra(inner) => &mut inner.historical_roots,
        }
    }
    pub fn validators(&self) -> &List<Validator, VALIDATOR_REGISTRY_LIMIT> {
        match self {
            Self::Phase0(inner) => &inner.validators,
            Self::Altair(inner) => &inner.validators,
            Self::Bellatrix(inner) => &inner.validators,
            Self::Capella(inner) => &inner.validators,
            Self::Deneb(inner) => &inner.validators,
            Self::Electra(inner) => &inner.validators,
        }
    }
    pub fn balances(&self) -> &List<Gwei, VALIDATOR_REGISTRY_LIMIT> {
        match self {
            Self::Phase0(inner) => &inner.balances,
            Self::Altair(inner) => &inner.balances,
            Self::Bellatrix(inner) => &inner.balances,
            Self::Capella(inner) => &inner.balances,
            Self::Deneb(inner) => &inner.balances,
            Self::Electra(inner) => &inner.balances,
        }
    }
    pub fn randao_mixes(&self) -> &Vector<Bytes32, EPOCHS_PER_HISTORICAL_VECTOR> {
        match self {
            Self::Phase0(inner) => &inner.randao_mixes,
            Self::Altair(inner) => &inner.randao_mixes,
            Self::Bellatrix(inner) => &inner.randao_mixes,
            Self::Capella(inner) => &inner.randao_mixes,
            Self::Deneb(inner) => &inner.randao_mixes,
            Self::Electra(inner) => &inner.randao_mixes,
        }
    }
    pub fn previous_epoch_attestations(
        &self,
    ) -> Option<&List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>>
    {
        match self {
            Self::Phase0(inner) => Some(&inner.previous_epoch_attestations),
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(_) => None,
            Self::Electra(_) => None,
        }
    }
    pub fn current_epoch_attestations(
        &self,
    ) -> Option<&List<PendingAttestation<MAX_VALIDATORS_PER_COMMITTEE>, PENDING_ATTESTATIONS_BOUND>>
    {
        match self {
            Self::Phase0(inner) => Some(&inner.current_epoch_attestations),
            Self::Altair(_) => None,
            Self::Bellatrix(_) => None,
            Self::Capella(_) => None,
            Self::Deneb(_) => None,
            Self::Electra(_) => None,
        }
    }
    pub fn justification_bits(&self) -> &Bitvector<JUSTIFICATION_BITS_LENGTH> {
        match self {
            Self::Phase0(inner) => &inner.justification_bits,
            Self::Altair(inner) => &inner.justification_bits,
            Self::Bellatrix(inner) => &inner.justification_bits,
            Self::Capella(inner) => &inner.justification_bits,
            Self::Deneb(inner) => &inner.justification_bits,
            Self::Electra(inner) => &inner.justification_bits,
        }
    }
    pub fn previous_justified_checkpoint(&self) -> &Checkpoint {
        match self {
            Self::Phase0(inner) => &inner.previous_justified_checkpoint,
            Self::Altair(inner) => &inner.previous_justified_checkpoint,
            Self::Bellatrix(inner) => &inner.previous_justified_checkpoint,
            Self::Capella(inner) => &inner.previous_justified_checkpoint,
            Self::Deneb(inner) => &inner.previous_justified_checkpoint,
            Self::Electra(inner) => &inner.previous_justified_checkpoint,
        }
    }
    pub fn current_justified_checkpoint(&self) -> &Checkpoint {
        match self {
            Self::Phase0(inner) => &inner.current_justified_checkpoint,
            Self::Altair(inner) => &inner.current_justified_checkpoint,
            Self::Bellatrix(inner) => &inner.current_justified_checkpoint,
            Self::Capella(inner) => &inner.current_justified_checkpoint,
            Self::Deneb(inner) => &inner.current_justified_checkpoint,
            Self::Electra(inner) => &inner.current_justified_checkpoint,
        }
    }
    pub fn finalized_checkpoint(&self) -> &Checkpoint {
        match self {
            Self::Phase0(inner) => &inner.finalized_checkpoint,
            Self::Altair(inner) => &inner.finalized_checkpoint,
            Self::Bellatrix(inner) => &inner.finalized_checkpoint,
            Self::Capella(inner) => &inner.finalized_checkpoint,
            Self::Deneb(inner) => &inner.finalized_checkpoint,
            Self::Electra(inner) => &inner.finalized_checkpoint,
        }
    }
    pub fn previous_epoch_participation(
        &self,
    ) -> Option<&List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.previous_epoch_participation),
            Self::Bellatrix(inner) => Some(&inner.previous_epoch_participation),
            Self::Capella(inner) => Some(&inner.previous_epoch_participation),
            Self::Deneb(inner) => Some(&inner.previous_epoch_participation),
            Self::Electra(inner) => Some(&inner.previous_epoch_participation),
        }
    }
    pub fn current_epoch_participation(
        &self,
    ) -> Option<&List<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(inner) => Some(&inner.current_epoch_participation),
            Self::Bellatrix(inner) => Some(&inner.current_epoch_participation),
            Self::Capella(inner) => Some(&inner.current_epoch_participation),
            Self::Deneb(inner) => Some(&inner.current_epoch_participation),
            Self::Electra(inner) => Some(&inner.current_epoch_participation),
        }
    }
}

impl<
    'de,
    const SLOTS_PER_HISTORICAL_ROOT: usize,
    const HISTORICAL_ROOTS_LIMIT: usize,
    const ETH1_DATA_VOTES_BOUND: usize,
    const VALIDATOR_REGISTRY_LIMIT: usize,
    const EPOCHS_PER_HISTORICAL_VECTOR: usize,
    const EPOCHS_PER_SLASHINGS_VECTOR: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const PENDING_ATTESTATIONS_BOUND: usize,
    const SYNC_COMMITTEE_SIZE: usize,
    const BYTES_PER_LOGS_BLOOM: usize,
    const MAX_EXTRA_DATA_BYTES: usize,
    const PENDING_DEPOSITS_LIMIT: usize,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize,
    const PENDING_CONSOLIDATIONS_LIMIT: usize,
> serde::Deserialize<'de>
    for BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_BOUND,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_VALIDATORS_PER_COMMITTEE,
        PENDING_ATTESTATIONS_BOUND,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Electra(inner));
        }
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Deneb(inner));
        }
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Capella(inner));
        }
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Bellatrix(inner));
        }
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Altair(inner));
        }
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Phase0(inner));
        }
        Err(serde::de::Error::custom(
            "no variant could be deserialized from input",
        ))
    }
}
