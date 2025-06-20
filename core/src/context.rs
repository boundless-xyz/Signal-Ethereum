use alloc::fmt::Debug;
use beacon_types::EthSpec;

pub use super::guest_context::GuestContext;

#[cfg(feature = "host")]
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
#[repr(transparent)]
pub struct HostContext<E: EthSpec>(E);

#[cfg(feature = "host")]
impl<E: EthSpec> HostContext<E> {
    fn new(inner: E) -> Self {
        Self(inner)
    }
}
#[cfg(feature = "host")]
impl<E: EthSpec> EthSpec for HostContext<E> {
    type GenesisEpoch = E::GenesisEpoch;

    type JustificationBitsLength = E::JustificationBitsLength;

    type SubnetBitfieldLength = E::SubnetBitfieldLength;

    type MaxValidatorsPerCommittee = E::MaxValidatorsPerCommittee;

    type MaxValidatorsPerSlot = E::MaxValidatorsPerSlot;

    type MaxCommitteesPerSlot = E::MaxCommitteesPerSlot;

    type SlotsPerEpoch = E::SlotsPerEpoch;

    type EpochsPerEth1VotingPeriod = E::EpochsPerEth1VotingPeriod;

    type SlotsPerHistoricalRoot = E::SlotsPerHistoricalRoot;

    type EpochsPerHistoricalVector = E::EpochsPerHistoricalVector;

    type EpochsPerSlashingsVector = E::EpochsPerSlashingsVector;

    type HistoricalRootsLimit = E::HistoricalRootsLimit;

    type ValidatorRegistryLimit = E::ValidatorRegistryLimit;

    type MaxProposerSlashings = E::MaxProposerSlashings;

    type MaxAttesterSlashings = E::MaxAttesterSlashings;

    type MaxAttestations = E::MaxAttestations;

    type MaxDeposits = E::MaxDeposits;

    type MaxVoluntaryExits = E::MaxVoluntaryExits;

    type SyncCommitteeSize = E::SyncCommitteeSize;

    type SyncCommitteeSubnetCount = E::SyncCommitteeSubnetCount;

    type MaxBytesPerTransaction = E::MaxBytesPerTransaction;

    type MaxTransactionsPerPayload = E::MaxTransactionsPerPayload;

    type BytesPerLogsBloom = E::BytesPerLogsBloom;

    type GasLimitDenominator = E::GasLimitDenominator;

    type MinGasLimit = E::MinGasLimit;

    type MaxExtraDataBytes = E::MaxExtraDataBytes;

    type MaxBlsToExecutionChanges = E::MaxBlsToExecutionChanges;

    type MaxWithdrawalsPerPayload = E::MaxWithdrawalsPerPayload;

    type MaxBlobCommitmentsPerBlock = E::MaxBlobCommitmentsPerBlock;

    type FieldElementsPerBlob = E::FieldElementsPerBlob;

    type BytesPerFieldElement = E::BytesPerFieldElement;

    type KzgCommitmentInclusionProofDepth = E::KzgCommitmentInclusionProofDepth;

    type FieldElementsPerCell = E::FieldElementsPerCell;

    type FieldElementsPerExtBlob = E::FieldElementsPerExtBlob;

    type KzgCommitmentsInclusionProofDepth = E::KzgCommitmentsInclusionProofDepth;

    type MaxPendingAttestations = E::MaxPendingAttestations;

    type SlotsPerEth1VotingPeriod = E::SlotsPerEth1VotingPeriod;

    type SyncSubcommitteeSize = E::SyncSubcommitteeSize;

    type BytesPerBlob = E::BytesPerBlob;

    type BytesPerCell = E::BytesPerCell;

    type PendingDepositsLimit = E::PendingDepositsLimit;

    type PendingPartialWithdrawalsLimit = E::PendingPartialWithdrawalsLimit;

    type PendingConsolidationsLimit = E::PendingConsolidationsLimit;

    type MaxConsolidationRequestsPerPayload = E::MaxConsolidationRequestsPerPayload;

    type MaxDepositRequestsPerPayload = E::MaxDepositRequestsPerPayload;

    type MaxAttesterSlashingsElectra = E::MaxAttesterSlashingsElectra;

    type MaxAttestationsElectra = E::MaxAttestationsElectra;

    type MaxWithdrawalRequestsPerPayload = E::MaxWithdrawalRequestsPerPayload;

    type MaxPendingDepositsPerEpoch = E::MaxPendingDepositsPerEpoch;

    fn default_spec() -> beacon_types::ChainSpec {
        E::default_spec()
    }

    fn spec_name() -> beacon_types::EthSpecId {
        E::spec_name()
    }
}

// #[cfg(feature = "host")]
// impl Ctx for HostContext<E> {
//     type Error = ();

//     fn slots_per_epoch(&self) -> u64 {
//         self.0.slots_per_epoch
//     }

//     fn effective_balance_increment(&self) -> u64 {
//         self.0.effective_balance_increment
//     }

//     fn max_validators_per_committee(&self) -> usize {
//         self.0.max_validators_per_committee
//     }

//     fn max_committees_per_slot(&self) -> usize {
//         self.0.max_committees_per_slot
//     }

//     fn epochs_per_historical_vector(&self) -> u64 {
//         self.0.epochs_per_historical_vector
//     }

//     fn min_seed_lookahead(&self) -> u64 {
//         self.0.min_seed_lookahead
//     }

//     fn shuffle_round_count(&self) -> u64 {
//         self.0.shuffle_round_count
//     }

//     fn target_committee_size(&self) -> u64 {
//         self.0.target_committee_size
//     }

//     fn max_deposits(&self) -> usize {
//         self.0.max_deposits
//     }
// }
