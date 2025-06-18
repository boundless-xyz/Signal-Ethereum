use alloy_primitives::{B256, FixedBytes};
use tree_hash_derive::TreeHash;

use crate::{
    BEACON_DEPOSIT_DOMAIN, BlsError, PublicKey, Root, Signature, StateReader, VerifyError,
    compute_signing_root, fork_data_root, verify_signature,
};

#[derive(TreeHash)]
pub struct DepositMessage {
    pub pubkey: FixedBytes<48>,
    pub withdrawal_credentials: B256,
    pub amount: u64,
}

pub struct DepositData {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: B256,
    pub amount: u64,
    pub signature: Signature,
}

impl DepositData {
    /// Create a `DepositMessage` corresponding to this `DepositData`, for signature verification.
    ///
    /// Spec v0.12.1
    pub fn as_deposit_message(&self) -> DepositMessage {
        DepositMessage {
            pubkey: self.pubkey.compress().into(),
            withdrawal_credentials: self.withdrawal_credentials,
            amount: self.amount,
        }
    }

    /// Verify `Deposit.pubkey` signed `Deposit.signature`.
    ///
    /// Spec v0.12.1
    pub fn is_valid_deposit_signature<S: StateReader>(
        &self,
        state_reader: &S,
    ) -> Result<(), BlsError> {
        let (public_key, signature, msg) =
            self.deposit_pubkey_signature_message(state_reader).unwrap();

        verify_signature(&public_key, msg.as_slice(), &signature)
    }

    pub fn deposit_pubkey_signature_message<S: StateReader>(
        &self,
        state_reader: &S,
    ) -> Result<(PublicKey, Signature, B256), VerifyError> {
        let pubkey = self.pubkey.clone();
        let signature = self.signature.clone();
        let domain = get_deposit_domain(state_reader)?;
        let message = compute_signing_root(&self.as_deposit_message(), domain);
        Ok((pubkey, signature, message))
    }
}

fn get_deposit_domain<S: StateReader>(state_reader: &S) -> Result<[u8; 32], VerifyError> {
    let domain_type = BEACON_DEPOSIT_DOMAIN;
    // Deposits are valid across forks, thus the deposit domain is computed
    // with the genesis fork version.
    let fork_data_root = fork_data_root(state_reader, Root::ZERO, 0)?;

    let mut domain = [0_u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_data_root.as_slice()[..28]);
    Ok(domain)
}
