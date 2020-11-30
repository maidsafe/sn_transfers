// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{wallet::Wallet, Outcome, TernaryResult};
use log::debug;
use sn_data_types::{
    DebitAgreementProof, Error, KnownGroupAdded, Money, PublicKey, ReplicaEvent, Result,
    SignedTransfer, Transfer, TransferRegistered,
};
use std::collections::HashSet;
use threshold_crypto::{PublicKeySet, PublicKeyShare};

/// The Replica is the part of an AT2 system
/// that forms validating groups, and signs
/// individual transfers between wallets.
/// Replicas validate requests to debit an wallet, and
/// apply operations that has a valid "debit agreement proof"
/// from the group, i.e. signatures from a quorum of its peers.
/// Replicas don't initiate transfers or drive the algo - only Actors do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletReplica {
    /// The public key of the Wallet.
    id: PublicKey,
    /// The public key share of this Replica.
    replica_id: PublicKeyShare,
    /// The index of this Replica key share, in the group set.
    key_index: usize,
    /// The PK set of our peer Replicas.
    peer_replicas: PublicKeySet,
    /// PK sets of other known groups of Replicas.
    other_groups: HashSet<PublicKeySet>,
    /// All wallets that this Replica validates transfers for.
    wallet: Wallet,
    /// Ensures that invidual wallet's debit
    /// initiations (ValidateTransfer cmd) are sequential.
    pending_debit: u64,
}

impl WalletReplica {
    /// A new Replica instance from a history of events.
    pub fn from_history(
        id: PublicKey,
        replica_id: PublicKeyShare,
        key_index: usize,
        peer_replicas: PublicKeySet,
        events: Vec<ReplicaEvent>,
    ) -> Result<Self> {
        let mut instance = Self::from_snapshot(
            id,
            replica_id,
            key_index,
            peer_replicas,
            Default::default(),
            Wallet::new(id),
            Default::default(),
        );
        for e in events {
            instance.apply(e)?;
        }
        Ok(instance)
    }

    /// A new Replica instance from current state.
    pub fn from_snapshot(
        id: PublicKey,
        replica_id: PublicKeyShare,
        key_index: usize,
        peer_replicas: PublicKeySet,
        other_groups: HashSet<PublicKeySet>,
        wallet: Wallet,
        pending_debit: u64,
    ) -> Self {
        Self {
            id,
            replica_id,
            key_index,
            peer_replicas,
            other_groups,
            wallet,
            pending_debit,
        }
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Queries ----------------------------------
    /// -----------------------------------------------------------------

    /// Query for new credits since specified index.
    /// NB: This is not guaranteed to give you all unknown to you,
    /// since there is no absolute order on the credits!
    /// Includes the credit at specified index (which may,
    /// or may not, be the same as the one that the Actor has at the same index).
    pub fn credits_since(&self, index: usize) -> Vec<Transfer> {
        self.wallet.credits_since(index)
    }

    /// Query for new debits transfers since specified index.
    /// Includes the debit at specified index.
    pub fn debits_since(&self, index: usize) -> Vec<Transfer> {
        self.wallet.debits_since(index)
    }

    ///
    pub fn balance(&self) -> Money {
        self.wallet.balance()
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Cmds -------------------------------------
    /// -----------------------------------------------------------------

    /// This is the one and only infusion of money to the system. Ever.
    /// It is carried out by the first node in the network.
    pub fn genesis<F: FnOnce() -> Result<bool>>(
        &self,
        debit_proof: &DebitAgreementProof,
        past_key: F,
    ) -> Outcome<()> {
        // Genesis must be the first credit.
        if !self.credits_since(0).is_empty() {
            return Err(Error::InvalidOperation);
        }
        self.receive_propagated(debit_proof, past_key)
    }

    /// Adds a PK set for a a new group that we learn of.
    pub fn add_known_group(&self, group: PublicKeySet) -> Outcome<KnownGroupAdded> {
        if self.other_groups.contains(&group) {
            return Err(Error::DataExists);
        }
        Outcome::success(KnownGroupAdded { group })
    }

    /// For now, with test money there is no from wallet.., money is created from thin air.
    pub fn test_validate_transfer(&self, signed_transfer: &SignedTransfer) -> Outcome<()> {
        if signed_transfer.from() == signed_transfer.to() {
            Err(Error::from("Sending from and to the same wallet"))
        } else {
            Outcome::success(())
        }
    }

    /// Step 1. Main business logic validation of a debit.
    pub fn validate(&self, signed_transfer: &SignedTransfer) -> Outcome<()> {
        debug!("Validating transfer");
        let transfer = &signed_transfer.transfer;
        // Always verify signature first! (as to not leak any information).
        if self.verify_actor_signature(&signed_transfer).is_err() {
            return Err(Error::InvalidSignature);
        }
        if transfer.id.actor == transfer.to {
            return Err(Error::from("Sender and recipient are the same."));
        }
        if transfer.amount() == Money::zero() {
            return Outcome::rejected(Error::Unexpected(
                "Cannot send zero value transactions".to_string(),
            ));
        }
        if self.wallet.id() != signed_transfer.from() {
            return Err(Error::InvalidOperation);
        }
        if transfer.id.counter != (self.pending_debit + 1) {
            return Err(Error::from(format!(
                "out of order msg, previous count: {:?}",
                transfer.id.counter
            )));
        }
        if transfer.amount > self.balance() {
            return Err(Error::InsufficientBalance);
        }

        Outcome::success(())
        // match self.sign_validated_transfer(&signed_transfer) {
        //     Err(_) => Err(Error::InvalidSignature),
        //     Ok(replica_signature) => Outcome::success(TransferValidated {
        //         signed_transfer,
        //         replica_signature,
        //         replicas: self.peer_replicas.clone(),
        //     }),
        // }
    }

    /// Step 2. Validation of agreement, and order at debit source.
    pub fn register<F: FnOnce() -> Result<bool>>(
        &self,
        debit_proof: &DebitAgreementProof,
        past_key: F,
    ) -> Outcome<TransferRegistered> {
        debug!("Checking registered transfer");

        // Always verify signature first! (as to not leak any information).
        if self.verify_registered_proof(debit_proof, past_key).is_err() {
            return Err(Error::InvalidSignature);
        }

        let transfer = &debit_proof.signed_transfer.transfer;
        match self.wallet.is_sequential(transfer) {
            Ok(is_sequential) => {
                if is_sequential {
                    Outcome::success(TransferRegistered {
                        debit_proof: debit_proof.clone(),
                    })
                } else {
                    Err(Error::from("Non-sequential operation"))
                }
            }
            Err(_) => Err(Error::InvalidOperation), // from this place this code won't happen, but history validates the transfer is actually debits from it's owner.
        }
    }

    /// Step 3. Validation of DebitAgreementProof, and credit idempotency at credit destination.
    /// (Since this leads to a credit, there is no requirement on order.)
    pub fn receive_propagated<F: FnOnce() -> Result<bool>>(
        &self,
        debit_proof: &DebitAgreementProof,
        past_key: F,
    ) -> Outcome<()> {
        // Always verify signature first! (as to not leak any information).
        self.verify_propagated_proof(debit_proof, past_key)?;
        if self.wallet.contains(&debit_proof.id()) {
            Outcome::no_change()
        } else {
            Outcome::success(())
        }
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Mutation ---------------------------------
    /// -----------------------------------------------------------------

    /// Mutation of state.
    /// There is no validation of an event, it (the cmd) is assumed to have
    /// been properly validated before the fact is established (event raised),
    /// and thus anything that breaks here, is a bug in the validation..
    pub fn apply(&mut self, event: ReplicaEvent) -> Result<()> {
        match event {
            ReplicaEvent::KnownGroupAdded(e) => {
                let _ = self.other_groups.insert(e.group);
                Ok(())
            }
            ReplicaEvent::TransferValidated(e) => {
                let transfer = e.signed_transfer.transfer;
                self.pending_debit = transfer.id.counter;
                Ok(())
            }
            ReplicaEvent::TransferRegistered(e) => {
                let transfer = e.debit_proof.signed_transfer.transfer;
                self.wallet.append(transfer)
            }
            ReplicaEvent::TransferPropagated(e) => {
                let transfer = e.debit_proof.signed_transfer.transfer;
                self.wallet.append(transfer)
            }
        }
    }

    /// Test-helper API to simulate Client CREDIT Transfers.
    #[cfg(feature = "simulated-payouts")]
    pub fn credit_without_proof(&mut self, transfer: Transfer) -> Result<()> {
        self.wallet.simulated_credit(transfer)
    }

    /// Test-helper API to simulate Client DEBIT Transfers.
    #[cfg(feature = "simulated-payouts")]
    pub fn debit_without_proof(&mut self, transfer: Transfer) -> Result<()> {
        self.wallet.simulated_debit(transfer)
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Private methods --------------------------
    /// -----------------------------------------------------------------

    ///
    fn verify_actor_signature(&self, signed_transfer: &SignedTransfer) -> Result<()> {
        match bincode::serialize(&signed_transfer.transfer) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                let actor_sig = signed_transfer
                    .from()
                    .verify(&signed_transfer.actor_signature, data);
                if actor_sig.is_ok() {
                    Ok(())
                } else {
                    Err(Error::InvalidSignature)
                }
            }
        }
    }

    /// Verify that this is a valid _registered_
    /// DebitAgreementProof, i.e. signed by our peers.
    fn verify_registered_proof<F: FnOnce() -> Result<bool>>(
        &self,
        proof: &DebitAgreementProof,
        past_key: F,
    ) -> Result<()> {
        // Check that the proof corresponds to a public key set of our peers.
        match bincode::serialize(&proof.signed_transfer) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                // Check if proof is signed by our peers.
                let public_key = sn_data_types::PublicKey::Bls(self.peer_replicas.public_key());
                let result = public_key.verify(&proof.debiting_replicas_sig, &data);
                if result.is_ok() {
                    return result;
                }
                // Check if proof is signed with an older key
                if past_key()? {
                    return result;
                }

                // If it's not signed with our peers' public key, we won't consider it valid.
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Verify that this is a valid _propagated_
    /// DebitAgreementProof, i.e. signed by a group that we know of.
    fn verify_propagated_proof<F: FnOnce() -> Result<bool>>(
        &self,
        proof: &DebitAgreementProof,
        past_key: F,
    ) -> Result<()> {
        // Check that the proof corresponds to a public key set of some Replicas.
        match bincode::serialize(&proof.signed_transfer) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                // Check if it is from our group.
                let our_key = sn_data_types::PublicKey::Bls(self.peer_replicas.public_key());
                if our_key.verify(&proof.debiting_replicas_sig, &data).is_ok() {
                    return Ok(());
                }

                // Check if it was previously a part of our group
                if past_key()? {
                    return Ok(());
                }

                // TODO: Check retrospectively(using SectionProofChain) for known groups also
                // Check all known groups of Replicas.
                for set in &self.other_groups {
                    let debiting_replicas = sn_data_types::PublicKey::Bls(set.public_key());
                    let result = debiting_replicas.verify(&proof.debiting_replicas_sig, &data);
                    if result.is_ok() {
                        return Ok(());
                    }
                }
                // If we don't know the public key this was signed with, we won't consider it valid.
                Err(Error::InvalidSignature)
            }
        }
    }
}
