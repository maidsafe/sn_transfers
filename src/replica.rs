// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    history::History, Identity, KnownGroupAdded, PeersChanged, ReplicaEvent, TransferPropagated,
};
use crdts::{CmRDT, VClock};
use std::collections::{HashMap, HashSet};

use safe_nd::{
    Error, Money, ProofOfAgreement, Result, Signature, Transfer, TransferRegistered,
    TransferValidated, ValidateTransfer,
};
use threshold_crypto::{PublicKeySet, PublicKeyShare, SecretKeyShare, SignatureShare};

/// The Replica is the part of an AT2 system
/// that forms validating groups, and signs individual
/// Actors' transfers.
/// They validate incoming requests for transfer, and
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
    histories: HashMap<Identity, History>,
    /// Ensures that invidual actors' transfer
    /// initiations (ValidateTransfer cmd) are sequential.
    pending_transfers: VClock<Identity>,
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
            histories: Default::default(),
            pending_transfers: VClock::new(),
        }
    }

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

    /// This is the one and only infusion of money to the system. Ever.
    /// It is carried out by the first node in the network.
    /// WIP
    pub fn genesis(&self, proof: ProofOfAgreement) -> Result<TransferPropagated> {
        // Always verify signature first! (as to not leak any information).
        if !self.verify_proof(&proof).is_ok() {
            return Err(Error::InvalidSignature);
        }
        // genesis must be the first
        if self.histories.len() > 0 {
            return Err(Error::InvalidOperation);
        }
        Ok(TransferPropagated { proof })
    }

    /// Query for new incoming transfers since specified index.
    /// NB: This is not guaranteed to give you all unknown to you,
    /// since there is no absolute order on the incoming!
    pub fn incoming_since(&self, identity: &Identity, index: usize) -> Option<Vec<Transfer>> {
        match self.histories.get(&identity).cloned() {
            None => None,
            Some(history) => Some(history.incoming_since(index)),
        }
    }

    /// Query for new outgoing transfers since specified index.
    pub fn outgoing_since(&self, identity: &Identity, index: usize) -> Option<Vec<Transfer>> {
        match self.histories.get(&identity).cloned() {
            None => None,
            Some(history) => Some(history.outgoing_since(index)),
        }
    }

    ///
    pub fn balance(&self, identity: &Identity) -> Option<Money> {
        let result = self.histories.get(identity);
        match result {
            None => None,
            Some(history) => Some(history.balance()),
        }
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
            match self.sign(&transfer_cmd) {
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
        if !self.histories.contains_key(&transfer.id.actor) {
            // println!(
            //     "{} sender does not exist (trying to transfer {} to {}).",
            return Err(Error::NoSuchSender);
        }
        if transfer.id != self.pending_transfers.inc(transfer.id.actor) {
            return Err(Error::InvalidOperation); // "either already proposed or out of order msg"
        }
        match self.balance(&transfer.id.actor) {
            Some(balance) => {
                if transfer.amount > balance {
                    // println!("{} does not have enough money to transfer {} to {}. (balance: {})"
                    return Err(Error::InsufficientBalance);
                }
            }
            None => return Err(Error::NoSuchSender), //"From account doesn't exist"
        }

        match self.sign(&cmd) {
            Err(_) => Err(Error::InvalidSignature),
            Ok(replica_signature) => Ok(TransferValidated {
                transfer_cmd: cmd,
                replica_signature,
                replicas: self.peers.clone(),
            }),
        }
    }

    /// Step 2. Validation of agreement, and order at debit source.
    pub fn register(&self, proof: ProofOfAgreement) -> Result<TransferRegistered> {
        // Always verify signature first! (as to not leak any information).
        if !self.verify_proof(&proof).is_ok() {
            return Err(Error::InvalidSignature);
        }
        let transfer = &proof.transfer_cmd.transfer;
        let sender = self.histories.get(&transfer.id.actor);
        match sender {
            None => Err(Error::NoSuchSender),
            Some(history) => match history.is_sequential(transfer) {
                Ok(is_sequential) => {
                    if is_sequential {
                        Ok(TransferRegistered { proof })
                    } else {
                        Err(Error::InvalidOperation) // "Non-sequential operation"
                    }
                }
                Err(_) => Err(Error::InvalidOperation), // from this place this code won't happen, but history validates the transfer is actually outgoing from it's owner.
            },
        }
    }

    /// Step 3. Validation of agreement, and idempotency at credit destination.
    /// (Since this leads to a credit, there is no requirement on order.)
    pub fn propagate(&self, proof: ProofOfAgreement) -> Result<TransferPropagated> {
        // Always verify signature first! (as to not leak any information).
        if !self.verify_proof(&proof).is_ok() {
            return Err(Error::InvalidSignature);
        }
        let transfer = &proof.transfer_cmd.transfer;
        let already_exists = match self.histories.get(&transfer.to) {
            None => false,
            Some(history) => history.contains(&transfer.id),
        };
        if already_exists {
            Err(Error::TransferIdExists)
        } else {
            Ok(TransferPropagated { proof })
        }
    }

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
                let transfer = e.proof.transfer_cmd.transfer;
                self.histories
                    .get_mut(&transfer.id.actor)
                    .unwrap() // this is OK, since eventsourcing implies events are _facts_, you have a bug if it fails here..
                    .append(transfer);
            }
            ReplicaEvent::TransferPropagated(e) => {
                let transfer = e.proof.transfer_cmd.transfer;
                match self.histories.get_mut(&transfer.to) {
                    Some(history) => history.append(transfer),
                    None => {
                        // Creates if not exists.
                        let _ = self.histories.insert(transfer.to, History::new(transfer));
                    }
                }
            }
        };
        // consider event log, to properly be able to reconstruct state from restart
    }

    ///
    fn sign(&self, cmd: &ValidateTransfer) -> Result<safe_nd::SignatureShare> {
        match bincode::serialize(cmd) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => Ok(safe_nd::SignatureShare {
                index: self.index,
                signature: self.secret_key.sign(data),
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

    /// Verify that this is a valid ProofOfAgreement,
    /// i.e. signed by our peers or a group that we know of.
    fn verify_proof(&self, proof: &ProofOfAgreement) -> Result<()> {
        // Check that the proof corresponds to a public key set of some Replicas.
        match bincode::serialize(&proof.transfer_cmd) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                // First check if proof is signed by our peers.
                let public_key = safe_nd::PublicKey::Bls(self.peers.public_key());
                let result = public_key.verify(&proof.section_sig, &data);
                if result.is_ok() {
                    return result;
                }
                // Then check all other known groups of peers.
                for set in &self.other_groups {
                    let public_key = safe_nd::PublicKey::Bls(set.public_key());
                    let result = public_key.verify(&proof.section_sig, &data);
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
