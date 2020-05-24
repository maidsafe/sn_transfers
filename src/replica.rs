// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    account::Account, AccountId, DebitAgreementProof, KnownGroupAdded, PeersChanged, ReplicaEvent,
    SignatureShare, Transfer, TransferPropagated, TransferRegistered, TransferValidated,
    ValidateTransfer,
};
use crdts::{CmRDT, VClock};
use safe_nd::{Error, Money, Result};
use std::collections::{HashMap, HashSet};
use threshold_crypto::{PublicKeySet, PublicKeyShare, SecretKeyShare};

/// The Replica is the part of an AT2 system
/// that forms validating groups, and signs individual
/// Actors' transfers.
/// They validate credits requests for transfer, and
/// apply operations that has a valid proof of agreement from the group.
/// Replicas don't initiate transfers or drive the algo - only Actors do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replica {
    /// The public key share of this Replica.
    id: PublicKeyShare,
    /// The index of this Replica key share, in the group set.
    index: usize,
    /// Secret key share.
    secret_key: SecretKeyShare,
    /// The PK set of our peer Replicas.
    peers: PublicKeySet,
    /// PK sets of other known groups of Replicas.
    other_groups: HashSet<PublicKeySet>,
    /// Set of all transfers impacting a given identity.
    accounts: HashMap<AccountId, Account>,
    /// Ensures that invidual actors' transfer
    /// initiations (ValidateTransfer cmd) are sequential.
    pending_transfers: VClock<AccountId>,
}

impl Replica {
    /// A new Replica instance.
    pub fn new(
        secret_key: SecretKeyShare,
        index: usize,
        peers: PublicKeySet,
        other_groups: HashSet<PublicKeySet>,
    ) -> Self {
        let id = secret_key.public_key_share();
        Replica {
            secret_key,
            id,
            index,
            peers,
            other_groups,
            accounts: Default::default(),
            pending_transfers: VClock::new(),
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

    /// On peer composition change we get a new PublicKeySet.
    pub fn set_peers(&self, peers: PublicKeySet) -> Result<PeersChanged> {
        if peers == self.peers {
            return Err(Error::DataExists);
        }
        Ok(PeersChanged { peers })
    }

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
        transfer_cmd: ValidateTransfer,
    ) -> Result<TransferValidated> {
        let id = transfer_cmd.transfer.id;
        if id.actor == transfer_cmd.transfer.to {
            Err(Error::InvalidOperation)
        } else {
            match self.sign_cmd(&transfer_cmd) {
                Err(_) => Err(Error::InvalidSignature),
                Ok(replica_signature) => Ok(TransferValidated {
                    transfer_cmd,
                    replica_signature,
                    replicas: self.peers.clone(),
                }),
            }
        }
    }

    /// Step 1. Main business logic validation of a debit.
    pub fn validate(&self, cmd: ValidateTransfer) -> Result<TransferValidated> {
        let transfer = &cmd.transfer;
        // Always verify signature first! (as to not leak any information).
        if !self.verify_cmd_signature(&cmd).is_ok() {
            return Err(Error::InvalidSignature);
        }
        if transfer.id.actor == transfer.to {
            return Err(Error::InvalidOperation); // "Sender and recipient are the same"
        }
        if !self.accounts.contains_key(&transfer.id.actor) {
            return Err(Error::NoSuchSender); // "{} sender does not exist (trying to transfer {} to {})."
        }
        if transfer.id != self.pending_transfers.inc(transfer.id.actor) {
            return Err(Error::InvalidOperation); // "either already proposed or out of order msg"
        }
        match self.balance(&transfer.id.actor) {
            Some(balance) => {
                if transfer.amount > balance {
                    return Err(Error::InsufficientBalance); // "{} does not have enough money to transfer {} to {}. (balance: {})"
                }
            }
            None => return Err(Error::NoSuchSender), //"From account doesn't exist"
        }

        match self.sign_cmd(&cmd) {
            Err(_) => Err(Error::InvalidSignature),
            Ok(replica_signature) => Ok(TransferValidated {
                transfer_cmd: cmd,
                replica_signature,
                replicas: self.peers.clone(),
            }),
        }
    }

    /// Step 2. Validation of agreement, and order at debit source.
    pub fn register(&self, debit_proof: DebitAgreementProof) -> Result<TransferRegistered> {
        // Always verify signature first! (as to not leak any information).
        if !self.verify_registered_proof(&debit_proof).is_ok() {
            return Err(Error::InvalidSignature);
        }
        let transfer = &debit_proof.transfer_cmd.transfer;
        let sender = self.accounts.get(&transfer.id.actor);
        match sender {
            None => Err(Error::NoSuchSender),
            Some(history) => match history.is_sequential(transfer) {
                Ok(is_sequential) => {
                    if is_sequential {
                        Ok(TransferRegistered { debit_proof })
                    } else {
                        Err(Error::InvalidOperation) // "Non-sequential operation"
                    }
                }
                Err(_) => Err(Error::InvalidOperation), // from this place this code won't happen, but history validates the transfer is actually debits from it's owner.
            },
        }
    }

    /// Step 3. Validation of DebitAgreementProof, and credit idempotency at credit destination.
    /// (Since this leads to a credit, there is no requirement on order.)
    pub fn receive_propagated(
        &self,
        debit_proof: DebitAgreementProof,
    ) -> Result<TransferPropagated> {
        // Always verify signature first! (as to not leak any information).
        if !self.verify_propagated_proof(&debit_proof).is_ok() {
            return Err(Error::InvalidSignature);
        }
        let transfer = &debit_proof.transfer_cmd.transfer;
        let already_exists = match self.accounts.get(&transfer.to) {
            None => false,
            Some(history) => history.contains(&transfer.id),
        };
        if already_exists {
            Err(Error::TransferIdExists)
        } else {
            match self.sign_proof(&debit_proof) {
                Err(_) => Err(Error::InvalidSignature),
                Ok(replica_sig) => Ok(TransferPropagated {
                    debit_proof,
                    replica_sig,
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
            ReplicaEvent::PeersChanged(e) => self.peers = e.peers,
            ReplicaEvent::KnownGroupAdded(e) => {
                let _ = self.other_groups.insert(e.group);
            }
            ReplicaEvent::TransferValidated(e) => {
                let transfer = e.transfer_cmd.transfer;
                self.pending_transfers.apply(transfer.id);
            }
            ReplicaEvent::TransferRegistered(e) => {
                let transfer = e.debit_proof.transfer_cmd.transfer;
                self.accounts
                    .get_mut(&transfer.id.actor)
                    .unwrap() // this is OK, since eventsourcing implies events are _facts_, you have a bug if it fails here..
                    .append(transfer);
            }
            ReplicaEvent::TransferPropagated(e) => {
                let transfer = e.debit_proof.transfer_cmd.transfer;
                match self.accounts.get_mut(&transfer.to) {
                    Some(account) => account.append(transfer),
                    None => {
                        // Creates if not exists.
                        let _ = self.accounts.insert(transfer.to, Account::new(transfer));
                    }
                }
            }
        };
        // consider event log, to properly be able to reconstruct state from restart
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Private methods --------------------------
    /// -----------------------------------------------------------------

    ///
    fn sign_cmd(&self, cmd: &ValidateTransfer) -> Result<SignatureShare> {
        match bincode::serialize(cmd) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => Ok(SignatureShare {
                index: self.index,
                share: self.secret_key.sign(data),
            }),
        }
    }

    /// Replicas of the credited Actor, sign the debit proof
    /// for the Actor to aggregate and verify locally.
    /// An alternative to this is to have the Actor know (and trust) all other Replica groups.
    fn sign_proof(&self, proof: &DebitAgreementProof) -> Result<SignatureShare> {
        match bincode::serialize(proof) {
            Err(_) => Err(Error::NetworkOther("Could not serialise proof".into())),
            Ok(data) => Ok(SignatureShare {
                index: self.index,
                share: self.secret_key.sign(data),
            }),
        }
    }

    ///
    fn verify_cmd_signature(&self, cmd: &ValidateTransfer) -> Result<()> {
        match bincode::serialize(&cmd.transfer) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                let actor_sig = cmd.transfer.id.actor.verify(&cmd.actor_signature, data);
                if actor_sig.is_ok() {
                    Ok(())
                } else {
                    Err(Error::InvalidSignature)
                }
            }
        }
    }

    /// Verify that this is a valid _registered_
    /// ProofOfAgreement, i.e. signed by our peers.
    fn verify_registered_proof(&self, proof: &DebitAgreementProof) -> Result<()> {
        // Check that the proof corresponds to a public key set of our peer Replicas.
        match bincode::serialize(&proof.transfer_cmd) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                // Check if proof is signed by our peers.
                let public_key = safe_nd::PublicKey::Bls(self.peers.public_key());
                let result = public_key.verify(&proof.sender_replicas_sig, &data);
                if result.is_ok() {
                    return result;
                }
                // If it's not signed with our peers' public key, we won't consider it valid.
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Verify that this is a valid _propagated_
    // ProofOfAgreement, i.e. signed by a group that we know of.
    fn verify_propagated_proof(&self, proof: &DebitAgreementProof) -> Result<()> {
        // Check that the proof corresponds to a public key set of some Replicas.
        match bincode::serialize(&proof.transfer_cmd) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                // Check all known groups of peers.
                for set in &self.other_groups {
                    let public_key = safe_nd::PublicKey::Bls(set.public_key());
                    let result = public_key.verify(&proof.sender_replicas_sig, &data);
                    if result.is_ok() {
                        return result;
                    }
                }
                // If we don't know the public key this was signed with, we won't consider it valid.
                Err(Error::InvalidSignature)
            }
        }
    }
}
