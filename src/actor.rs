// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    history::History, ActorEvent, Identity, RemoteTransfersSynced, TransferInitiated,
    TransferRegistrationSent, TransferValidationReceived,
};
use crdts::Dot;
use std::collections::HashSet;

use safe_nd::{
    ClientFullId, Error, Money, ProofOfAgreement, RegisterTransfer, Result, Signature, Transfer,
    TransferIndices, TransferValidated, ValidateTransfer,
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

    /// Step 1. Build a valid cmd for validation of a transfer.
    pub fn initiate(&self, amount: Money, to: Identity) -> Result<TransferInitiated> {
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
                let next_pending = counter + 1;
                if next_pending != self.history.next_version() {
                    // ensures one transfer is completed at a time
                    return Err(Error::InvalidOperation); // "current pending transfer has not been completed"
                }
                if next_pending != id.counter {
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

    /// Step 2. Receive validations from Replicas, aggregate the signatures.
    pub fn receive(&self, validation: TransferValidated) -> Result<TransferValidationReceived> {
        // Always verify signature first! (as to not leak any information).
        if !self.verify_validation(&validation) {
            return Err(Error::InvalidSignature);
        }
        match self.pending_transfers_checkpoint {
            None => return Err(Error::InvalidOperation), // "there is no pending transfer, cannot receive validations"
            Some(counter) => {
                if counter != validation.transfer_cmd.transfer.id.counter {
                    return Err(Error::InvalidOperation); // "out of order validation"
                }
            }
        }
        if self.received_validations.contains(&validation) {
            return Err(Error::InvalidOperation); // "Already received validation"
        }

        // TODO: check if quorum validations, and construct the proof

        Ok(TransferValidationReceived {
            validation,
            proof: None,
        })
    }

    /// Step 3. Build a valid cmd for registration of an agreed transfer.
    pub fn register(&self, proof: ProofOfAgreement) -> Result<TransferRegistrationSent> {
        // Always verify signature first! (as to not leak any information).
        if !self.verify_proof(&proof) {
            return Err(Error::InvalidSignature);
        }
        match self.history.is_sequential(&proof.transfer_cmd.transfer) {
            Ok(is_sequential) => {
                if is_sequential {
                    Ok(TransferRegistrationSent {
                        cmd: RegisterTransfer { proof },
                    })
                } else {
                    Err(Error::InvalidOperation) // "Non-sequential operation"
                }
            }
            Err(_) => Err(Error::InvalidOperation), // from this place this code won't happen, but history validates the transfer is actually outgoing from it's owner.
        }
    }

    /// Continuous syncing from Replicas ensure
    /// that we receive incoming transfers.
    /// With multiple devices we can also sync outgoing made on other devices.
    pub fn sync_remote(transfers: (Vec<Transfer>, Vec<Transfer>)) -> Result<RemoteTransfersSynced> {
        let (incoming, outgoing) = transfers;
        // TODO: validate.. validate..
        Ok(RemoteTransfersSynced { incoming, outgoing })
    }

    /// Mutation of state.
    pub fn apply(&mut self, event: ActorEvent) {
        match event {
            ActorEvent::TransferInitiated(e) => {
                let transfer = e.cmd.transfer;
                self.pending_transfers_checkpoint = Some(transfer.id.counter);
            }
            ActorEvent::TransferValidationReceived(e) => {
                let _ = self.received_validations.insert(e.validation);
            }
            ActorEvent::TransferRegistrationSent(e) => {
                let transfer = e.cmd.proof.transfer_cmd.transfer;
                self.history.append(transfer);
                self.received_validations.clear();
            }
            ActorEvent::RemoteTransfersSynced(e) => {
                for transfer in e.incoming {
                    self.history.append(transfer);
                }
                for transfer in e.outgoing {
                    self.history.append(transfer);
                }
            }
        };
        // consider event log, to properly be able to rehydrate state
    }

    fn sign(&self, transfer: &Transfer) -> Result<Signature> {
        match bincode::serialize(transfer) {
            Err(_) => Err(Error::NetworkOther("Could not serialise".into())),
            Ok(data) => Ok(self.client_id.sign(data)),
        }
    }

    fn verify_validation(&self, event: &TransferValidated) -> bool {
        unimplemented!()
    }

    fn verify_proof(&self, proof: &ProofOfAgreement) -> bool {
        unimplemented!()
    }
}
