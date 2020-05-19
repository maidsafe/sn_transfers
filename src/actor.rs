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
    TransferValidated, ValidateTransfer,
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
    current_transfer_version: Option<u64>,
    /// When a transfer is initiated, validations are accumulated here.
    /// After quorum is reached and proof produced, the set is cleared.
    accumulating_validations: HashSet<TransferValidated>,
}

impl Actor {
    /// Pass in a first incoming transfer.
    /// Without it, there is no Actor, since there is no balance.
    /// There is no essential validations here, since without a valid transfer
    /// this Actor can't really convince Replicas to do anything.
    pub fn get(client_id: ClientFullId, transfer: Transfer) -> Option<Actor> {
        let id = *client_id.public_id().public_key();
        if id != transfer.to {
            return None;
        }
        Some(Actor {
            id: transfer.to,
            client_id,
            // pk_set, // temporary exclude
            history: History::new(transfer),
            current_transfer_version: None,
            accumulating_validations: Default::default(),
        })
    }

    /// Query for new incoming transfers since specified index.
    /// NB: This is not guaranteed to give you all unknown to you,
    /// since there is no absolute order on the incoming!
    pub fn incoming_since(&self, index: usize) -> Vec<Transfer> {
        self.history.incoming_since(index)
    }

    /// Query for new outgoing transfers since specified index.
    pub fn outgoing_since(&self, index: usize) -> Vec<Transfer> {
        self.history.outgoing_since(index)
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

        match self.current_transfer_version {
            None => {
                if id.counter != 0 {
                    return Err(Error::InvalidOperation); // "out of order msg"
                }
            }
            Some(current_version) => {
                let next_version = current_version + 1;
                if next_version != self.history.next_version() {
                    // ensures one transfer is completed at a time
                    return Err(Error::InvalidOperation); // "current pending transfer has not been completed"
                }
                if next_version != id.counter {
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
        match self.current_transfer_version {
            None => return Err(Error::InvalidOperation), // "there is no pending transfer, cannot receive validations"
            Some(counter) => {
                if counter != validation.transfer_cmd.transfer.id.counter {
                    return Err(Error::InvalidOperation); // "out of order validation"
                }
            }
        }
        if self.accumulating_validations.contains(&validation) {
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

    /// Step xx. Continuous syncing from Replicas ensure
    /// that we receive incoming transfers. This can be push or pull model, decided by upper layer.
    /// With multiple devices we can also sync outgoing made on other devices.
    pub fn sync_from_replica(
        &self,
        incoming: Vec<ProofOfAgreement>,
        outgoing: Vec<ProofOfAgreement>,
    ) -> Result<RemoteTransfersSynced> {
        let valid_incoming = incoming
            .iter()
            .filter(|t| self.verify_proof(t))
            .filter(|t| self.id == t.transfer_cmd.transfer.to)
            .filter(|t| !self.history.contains(&t.transfer_cmd.transfer.id))
            .map(|t| t.clone())
            .collect::<Vec<ProofOfAgreement>>();

        let mut outgoing = outgoing
            .iter()
            .filter(|t| self.verify_proof(t))
            .filter(|t| self.id == t.transfer_cmd.transfer.id.actor)
            .collect::<Vec<&ProofOfAgreement>>();

        outgoing.sort_by_key(|t| t.transfer_cmd.transfer.id.counter);

        let mut iter = 0;
        let mut valid_outgoing = vec![];
        for out in outgoing {
            let version = out.transfer_cmd.transfer.id.counter;
            let expected_version = iter + self.history.next_version();
            if version != expected_version {
                break; // since it's sorted, if first is not matching, then no point continuing
            }
            valid_outgoing.push(out.clone());
            iter += 1;
        }

        if valid_incoming.len() > 0 || valid_outgoing.len() > 0 {
            Ok(RemoteTransfersSynced {
                incoming: valid_incoming,
                outgoing: valid_outgoing,
            })
        } else {
            Err(Error::InvalidOperation)
        }
    }

    /// Mutation of state.
    /// There is no validation of an event, it is assumed to have
    /// been properly validated before raised, and thus anything that breaks is a bug.
    pub fn apply(&mut self, event: ActorEvent) {
        match event {
            ActorEvent::TransferInitiated(e) => {
                let transfer = e.cmd.transfer;
                self.current_transfer_version = Some(transfer.id.counter);
            }
            ActorEvent::TransferValidationReceived(e) => {
                let _ = self.accumulating_validations.insert(e.validation);
            }
            ActorEvent::TransferRegistrationSent(e) => {
                let transfer = e.cmd.proof.transfer_cmd.transfer;
                self.history.append(transfer);
                self.accumulating_validations.clear();
            }
            ActorEvent::RemoteTransfersSynced(e) => {
                for proof in e.incoming {
                    self.history.append(proof.transfer_cmd.transfer);
                }
                for proof in e.outgoing {
                    self.history.append(proof.transfer_cmd.transfer);
                }
            }
        };
        // consider event log, to properly be able to reconstruct state from restart
    }

    fn sign(&self, transfer: &Transfer) -> Result<Signature> {
        match bincode::serialize(transfer) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
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
