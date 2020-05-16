// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{history::History, ActorEvent, Identity, TransferInitiated};
use crdts::Dot;
use std::collections::HashSet;

use safe_nd::{
    ClientFullId, Error, Money, ProofOfAgreement, RegisterTransfer, Result, Signature, Transfer,
    TransferIndices, TransferRegistered, TransferValidated, ValidateTransfer,
};

/// The Actor is the part of an AT2 system
/// that initiates transfers, by requesting Replicas
/// to validate them, and then receive the proof of agreement.
/// It also syncs incoming transfers from the Replicas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    id: Identity,
    client_id: ClientFullId,
    // /// The PK Set of the section
    // pk_set: threshold_crypto::PublicKeySet, // temporary exclude
    /// Set of all transfers impacting a given identity
    history: History,
    /// Ensures that the actor's transfer
    /// initiations (ValidateTransfer cmd) are sequential.
    pending_transfers_checkpoint: Option<u64>,
    received_validations: HashSet<TransferValidated>,
}

impl Actor {
    /// Pass in a function to retrieve any incoming transfers.
    /// Without it, there is no Actor, since there is no balance.
    /// It is the responsibility of the upper layer to perform necessary
    /// validations on the received Transfer.
    pub fn get(client_id: ClientFullId, sync: fn(Identity) -> Option<Transfer>) -> Option<Actor> {
        let id = *client_id.public_id().public_key();
        match sync(id) {
            None => None,
            Some(transfer) => Some(Actor {
                id: transfer.to,
                client_id,
                // pk_set, // temporary exclude
                history: History::new(transfer),
                pending_transfers_checkpoint: None,
                received_validations: Default::default(),
            }),
        }
    }

    /// Query
    pub fn local_history(&self, since_indices: TransferIndices) -> (Vec<Transfer>, Vec<Transfer>) {
        self.history.new_since(since_indices)
    }

    /// Query
    pub fn local_balance(&self) -> Money {
        self.history.balance()
    }

    /// Build a valid cmd for validation of a transfer.
    pub fn validate_transfer(&self, amount: Money, to: Identity) -> Result<TransferInitiated> {
        if to == self.id {
            return Err(Error::InvalidOperation); // "Sender and recipient are the same"
        }

        let id = Dot::new(self.id, self.history.next_version());

        match self.pending_transfers_checkpoint {
            None => {
                if id.counter > 0 {
                    return Err(Error::InvalidOperation); // "out of order msg"
                }
            }
            Some(counter) => {
                if id.counter != counter + 1 {
                    return Err(Error::InvalidOperation); // "either already proposed or out of order msg"
                }
            }
        }
        if amount > self.local_balance() {
            // println!("{} does not have enough money to transfer {} to {}. (balance: {})"
            return Err(Error::InsufficientBalance);
        }
        let transfer = Transfer { id, to, amount };
        match self.sign(&transfer) {
            Ok(signature) => {
                let cmd = ValidateTransfer {
                    transfer,
                    client_signature: signature,
                };
                Ok(TransferInitiated { cmd })
            }
            Err(e) => Err(e),
        }
    }

    /// Build a valid cmd for registration of an agreed transfer.
    pub fn register_transfer(&self, proof: ProofOfAgreement) -> Result<RegisterTransfer> {
        // Always verify signature first! (as to not leak any information).
        if !self.verify_proof(&proof) {
            return Err(Error::InvalidSignature);
        }
        match self.history.is_sequential(&proof.transfer_cmd.transfer) {
            Ok(is_seq) => {
                if is_seq {
                    Ok(RegisterTransfer { proof })
                } else {
                    Err(Error::InvalidOperation) // "Non-sequential operation"
                }
            }
            Err(_) => Err(Error::InvalidOperation), // from this place this code won't happen, but history validates the transfer is actually outgoing from it's owner.
        }
    }

    /// Mutation of state.
    pub fn apply(&mut self, event: ActorEvent) {
        match event {
            ActorEvent::TransferInitiated(e) => {
                let transfer = e.cmd.transfer;
                self.pending_transfers_checkpoint = Some(transfer.id.counter);
            }
            ActorEvent::TransferValidated(e) => {
                let _ = self.received_validations.insert(e);
            }
            ActorEvent::TransferRegistered(e) => {
                let transfer = e.proof.transfer_cmd.transfer;
                self.history.append(transfer);
                self.received_validations.clear();
            }
        };
    }

    fn sign(&self, transfer: &Transfer) -> Result<Signature> {
        match bincode::serialize(transfer) {
            Err(_) => Err(Error::NetworkOther("Could not serialise".into())),
            Ok(data) => Ok(self.client_id.sign(data)),
        }
    }

    fn verify_validation_sig(&self, event: &TransferValidated) -> bool {
        unimplemented!()
    }

    fn verify_proof(&self, proof: &ProofOfAgreement) -> bool {
        unimplemented!()
    }
}
