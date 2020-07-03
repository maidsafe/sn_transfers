// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::account::Account;
use log::debug;
use safe_nd::{
    AccountId, DebitAgreementProof, Error, KnownGroupAdded, Money, PublicKey, ReplicaEvent, Result,
    SignatureShare, SignedTransfer, Transfer, TransferPropagated, TransferRegistered,
    TransferValidated,
};
use std::collections::{HashMap, HashSet};
use threshold_crypto::{PublicKeySet, PublicKeyShare, SecretKeyShare};

/// The Replica is the part of an AT2 system
/// that forms validating groups, and signs
/// individual transfers between accounts.
/// Replicas validate requests to debit an account, and
/// apply operations that has a valid "debit agreement proof"
/// from the group, i.e. signatures from a quorum of its peers.
/// Replicas don't initiate transfers or drive the algo - only Actors do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replica {
    /// The public key share of this Replica.
    id: PublicKeyShare,
    /// Secret key share.
    secret_key: SecretKeyShare,
    /// The index of this Replica key share, in the group set.
    key_index: usize,
    /// The PK set of our peer Replicas.
    peer_replicas: PublicKeySet,
    /// PK sets of other known groups of Replicas.
    other_groups: HashSet<PublicKeySet>,
    /// All accounts that this Replica validates transfers for.
    accounts: HashMap<AccountId, Account>,
    /// Ensures that invidual account's debit
    /// initiations (ValidateTransfer cmd) are sequential.
    pending_debits: HashMap<AccountId, u64>,
}

impl Replica {
    /// A new Replica instance from a history of events.
    pub fn from_history(
        secret_key: SecretKeyShare,
        key_index: usize,
        peer_replicas: PublicKeySet,
        events: Vec<ReplicaEvent>,
    ) -> Replica {
        let mut instance = Replica::from_snapshot(
            secret_key,
            key_index,
            peer_replicas,
            Default::default(),
            Default::default(),
            Default::default(),
        );
        for e in events {
            instance.apply(e);
        }
        instance
    }

    /// A new Replica instance from current state.
    pub fn from_snapshot(
        secret_key: SecretKeyShare,
        key_index: usize,
        peer_replicas: PublicKeySet,
        other_groups: HashSet<PublicKeySet>,
        accounts: HashMap<AccountId, Account>,
        pending_debits: HashMap<AccountId, u64>,
    ) -> Replica {
        let id = secret_key.public_key_share();
        Replica {
            secret_key,
            id,
            key_index,
            peer_replicas,
            other_groups,
            accounts,
            pending_debits,
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
    pub fn credits_since(&self, account_id: &AccountId, index: usize) -> Option<Vec<Transfer>> {
        match self.accounts.get(&account_id).cloned() {
            None => None,
            Some(history) => Some(history.credits_since(index)),
        }
    }

    /// Query for new debits transfers since specified index.
    /// Includes the debit at specified index.
    pub fn debits_since(&self, account_id: &AccountId, index: usize) -> Option<Vec<Transfer>> {
        match self.accounts.get(&account_id).cloned() {
            None => None,
            Some(history) => Some(history.debits_since(index)),
        }
    }

    ///
    pub fn balance(&self, account_id: &AccountId) -> Option<Money> {
        let result = self.accounts.get(account_id);
        match result {
            None => None,
            Some(history) => Some(history.balance()),
        }
    }

    /// Get the replica's PK set
    pub fn replicas_pk_set(&self) -> Result<PublicKeySet> {
        Ok(self.peer_replicas.clone())
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Cmds -------------------------------------
    /// -----------------------------------------------------------------

    // /// This is the one and only infusion of money to the system. Ever.
    // /// It is carried out by the first node in the network.
    // /// WIP
    // pub fn genesis(&self, proof: DebitAgreementProof) -> Result<TransferPropagated> {
    //     // genesis must be the first
    //     if self.accounts.len() > 0 {
    //         return Err(Error::InvalidOperation);
    //     }
    //     Ok(TransferPropagated { debit_proof, replica_sig })
    // }

    /// Adds a PK set for a a new group that we learn of.
    pub fn add_known_group(&self, group: PublicKeySet) -> Result<KnownGroupAdded> {
        if self.other_groups.contains(&group) {
            return Err(Error::DataExists);
        }
        Ok(KnownGroupAdded { group })
    }

    /// For now, with test money there is no from account.., money is created from thin air.
    pub fn test_validate_transfer(
        &self,
        signed_transfer: SignedTransfer,
    ) -> Result<TransferValidated> {
        if signed_transfer.from() == signed_transfer.to() {
            Err(Error::from("Sending from and to the same account"))
        } else {
            match self.sign_validated_transfer(&signed_transfer) {
                Err(_) => Err(Error::InvalidSignature),
                Ok(replica_signature) => Ok(TransferValidated {
                    signed_transfer,
                    replica_signature,
                    replicas: self.peer_replicas.clone(),
                }),
            }
        }
    }

    /// Step 1. Main business logic validation of a debit.
    pub fn validate(&self, signed_transfer: SignedTransfer) -> Result<TransferValidated> {
        debug!("Checking TransferValidated");
        let transfer = &signed_transfer.transfer;
        // Always verify signature first! (as to not leak any information).
        if !self.verify_actor_signature(&signed_transfer).is_ok() {
            return Err(Error::InvalidSignature);
        }
        if transfer.id.actor == transfer.to {
            return Err(Error::from("Sender and recipient are the same."));
        }
        if !self.accounts.contains_key(&signed_transfer.from()) {
            return Err(Error::NoSuchSender); // "{} sender does not exist (trying to transfer {} to {})."
        }
        match self.pending_debits.get(&signed_transfer.from()) {
            None => {
                if transfer.id.counter != 0 {
                    return Err(Error::from("out of order msg, actor's counter should be 0"));
                }
            }
            Some(value) => {
                if transfer.id.counter != (value + 1) {
                    return Err(Error::from(format!(
                        "out of order msg, previous count: {:?}",
                        value
                    )));
                }
            }
        }
        match self.balance(&signed_transfer.from()) {
            Some(balance) => {
                if transfer.amount > balance {
                    return Err(Error::InsufficientBalance); // "{} does not have enough money to transfer {} to {}. (balance: {})"
                }
            }
            None => return Err(Error::NoSuchSender), //"From account doesn't exist"
        }

        match self.sign_validated_transfer(&signed_transfer) {
            Err(_) => Err(Error::InvalidSignature),
            Ok(replica_signature) => Ok(TransferValidated {
                signed_transfer,
                replica_signature,
                replicas: self.peer_replicas.clone(),
            }),
        }
    }

    /// Step 2. Validation of agreement, and order at debit source.
    pub fn register<F: FnOnce() -> bool>(
        &self,
        debit_proof: &DebitAgreementProof,
        f: F,
    ) -> Result<TransferRegistered> {
        debug!("Checking registered transfer");

        // Always verify signature first! (as to not leak any information).
        if !self.verify_registered_proof(debit_proof, f).is_ok() {
            return Err(Error::InvalidSignature);
        }

        let transfer = &debit_proof.signed_transfer.transfer;
        let sender = self.accounts.get(&debit_proof.from());
        match sender {
            None => Err(Error::NoSuchSender),
            Some(history) => match history.is_sequential(transfer) {
                Ok(is_sequential) => {
                    if is_sequential {
                        Ok(TransferRegistered {
                            debit_proof: debit_proof.clone(),
                        })
                    } else {
                        Err(Error::from("Non-sequential operation"))
                    }
                }
                Err(_) => Err(Error::InvalidOperation), // from this place this code won't happen, but history validates the transfer is actually debits from it's owner.
            },
        }
    }

    /// Step 3. Validation of DebitAgreementProof, and credit idempotency at credit destination.
    /// (Since this leads to a credit, there is no requirement on order.)
    pub fn receive_propagated<F: FnOnce() -> Option<PublicKey>>(
        &self,
        debit_proof: &DebitAgreementProof,
        f: F,
    ) -> Result<TransferPropagated> {
        // Always verify signature first! (as to not leak any information).
        let debiting_replicas = self.verify_propagated_proof(debit_proof, f)?;
        let already_exists = match self.accounts.get(&debit_proof.to()) {
            None => false,
            Some(history) => history.contains(&debit_proof.id()),
        };
        if already_exists {
            Err(Error::TransferIdExists)
        } else {
            match self.sign_proof(&debit_proof) {
                Err(_) => Err(Error::InvalidSignature),
                Ok(crediting_replica_sig) => Ok(TransferPropagated {
                    debit_proof: debit_proof.clone(),
                    debiting_replicas,
                    crediting_replica_sig,
                }),
            }
        }
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Mutation ---------------------------------
    /// -----------------------------------------------------------------

    /// Mutation of state.
    /// There is no validation of an event, it (the cmd) is assumed to have
    /// been properly validated before the fact is established (event raised),
    /// and thus anything that breaks here, is a bug in the validation..
    pub fn apply(&mut self, event: ReplicaEvent) {
        match event {
            ReplicaEvent::KnownGroupAdded(e) => {
                let _ = self.other_groups.insert(e.group);
            }
            ReplicaEvent::TransferValidated(e) => {
                let transfer = e.signed_transfer.transfer;
                let _ = self
                    .pending_debits
                    .insert(transfer.id.actor, transfer.id.counter);
            }
            ReplicaEvent::TransferRegistered(e) => {
                let transfer = e.debit_proof.signed_transfer.transfer;
                self.accounts
                    .get_mut(&transfer.id.actor)
                    .unwrap() // this is OK, since eventsourcing implies events are _facts_, you have a bug if it fails here..
                    .append(transfer);
            }
            ReplicaEvent::TransferPropagated(e) => {
                let transfer = e.debit_proof.signed_transfer.transfer;
                match self.accounts.get_mut(&transfer.to) {
                    Some(account) => account.append(transfer),
                    None => {
                        // Creates if not exists.
                        let mut account = Account::new(transfer.to);
                        account.append(transfer.clone());
                        let _ = self.accounts.insert(transfer.to, account);
                    }
                };
            }
        };
        // consider event log, to properly be able to reconstruct state from restart
    }

    /// Test-helper API to simulate Client CREDIT Transfers.
    #[cfg(feature = "simulated-payouts")]
    pub fn credit_without_proof(&mut self, transfer: Transfer) {
        match self.accounts.get_mut(&transfer.to) {
            Some(account) => account.simulated_credit(transfer),
            None => {
                // Creates if it doesn't exist.
                let mut account = Account::new(transfer.to);
                account.simulated_credit(transfer.clone());
                let _ = self.accounts.insert(transfer.to, account);
            }
        };
    }

    /// Test-helper API to simulate Client DEBIT Transfers.
    #[cfg(feature = "simulated-payouts")]
    pub fn debit_without_proof(&mut self, transfer: Transfer) {
        match self.accounts.get_mut(&transfer.id.actor) {
            Some(account) => account.simulated_debit(transfer),
            None => panic!(
                "Cannot debit from a non-existing account. this transfer caused the problem: {:?}",
                transfer
            ),
        };
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Private methods --------------------------
    /// -----------------------------------------------------------------

    ///
    fn sign_validated_transfer(&self, transfer: &SignedTransfer) -> Result<SignatureShare> {
        match bincode::serialize(transfer) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => Ok(SignatureShare {
                index: self.key_index,
                share: self.secret_key.sign(data),
            }),
        }
    }

    /// Replicas of the credited account, sign the debit proof
    /// for the Actor to aggregate and verify locally.
    /// An alternative to this is to have the Actor know (and trust) all other Replica groups.
    fn sign_proof(&self, proof: &DebitAgreementProof) -> Result<SignatureShare> {
        match bincode::serialize(proof) {
            Err(_) => Err(Error::NetworkOther("Could not serialise proof".into())),
            Ok(data) => Ok(SignatureShare {
                index: self.key_index,
                share: self.secret_key.sign(data),
            }),
        }
    }

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
    fn verify_registered_proof<F: FnOnce() -> bool>(
        &self,
        proof: &DebitAgreementProof,
        f: F,
    ) -> Result<()> {
        // Check that the proof corresponds to a public key set of our peers.
        match bincode::serialize(&proof.signed_transfer) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                // Check if proof is signed by our peers.
                let public_key = safe_nd::PublicKey::Bls(self.peer_replicas.public_key());
                let result = public_key.verify(&proof.debiting_replicas_sig, &data);
                if result.is_ok() {
                    return result;
                }
                // Check if proof is signed with an older key
                if f() {
                    return result;
                }

                // If it's not signed with our peers' public key, we won't consider it valid.
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Verify that this is a valid _propagated_
    /// DebitAgreementProof, i.e. signed by a group that we know of.
    fn verify_propagated_proof<F: FnOnce() -> Option<PublicKey>>(
        &self,
        proof: &DebitAgreementProof,
        f: F,
    ) -> Result<PublicKey> {
        // Check that the proof corresponds to a public key set of some Replicas.
        match bincode::serialize(&proof.signed_transfer) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                // Check if it is from our group.
                let our_key = safe_nd::PublicKey::Bls(self.peer_replicas.public_key());
                if our_key.verify(&proof.debiting_replicas_sig, &data).is_ok() {
                    return Ok(our_key);
                }

                // Check if it was previously a part of our group
                if let Some(our_past_key) = f() {
                    return Ok(our_past_key);
                }

                // TODO: Check retrospectively(using SectionProofChain) for known groups also
                // Check all known groups of Replicas.
                for set in &self.other_groups {
                    let debiting_replicas = safe_nd::PublicKey::Bls(set.public_key());
                    let result = debiting_replicas.verify(&proof.debiting_replicas_sig, &data);
                    if result.is_ok() {
                        return Ok(debiting_replicas);
                    }
                }
                // If we don't know the public key this was signed with, we won't consider it valid.
                Err(Error::InvalidSignature)
            }
        }
    }
}
