// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    history::History, ActorEvent, Identity, RemoteCreditsSynced, RemoteDebitsSynced,
    TransferInitiated, TransferRegistrationSent, TransferValidationReceived,
};
use crdts::Dot;
use safe_nd::{
    ClientFullId, Error, Money, ProofOfAgreement, RegisterTransfer, Result, Signature, Transfer,
    TransferValidated, ValidateTransfer,
};
use std::collections::{BTreeMap, HashSet};
use threshold_crypto::PublicKeySet;

/// A signature share, with its index in the combined collection.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SecretKeyShare {
    /// Index in the combined collection.
    pub index: usize,
    /// Replica signature over the transfer cmd.
    pub secret_key: threshold_crypto::SecretKeyShare,
}

/// The Actor is the part of an AT2 system
/// that initiates transfers, by requesting Replicas
/// to validate them, and then receive the proof of agreement.
/// It also syncs transfers from the Replicas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    id: Identity,
    client_id: ClientFullId,
    /// Set of all transfers impacting a given identity
    history: History,
    /// Ensures that the actor's transfer
    /// initiations (ValidateTransfer cmd) are sequential.
    current_transfer_version: Option<u64>,
    /// When a transfer is initiated, validations are accumulated here.
    /// After quorum is reached and proof produced, the set is cleared.
    accumulating_validations: BTreeMap<PublicKeySet, HashSet<TransferValidated>>,
    /// The PK Set history of the Replicas
    replica_key_history: HashSet<PublicKeySet>,
}

impl Actor {
    /// Pass in the first credit.
    /// Without it, there is no Actor, since there is no balance.
    /// There is no essential validations here, since without a valid transfer
    /// this Actor can't really convince Replicas to do anything.
    pub fn new(
        client_id: ClientFullId,
        transfer: Transfer,
        replicas: PublicKeySet,
    ) -> Option<Actor> {
        let id = *client_id.public_id().public_key();
        if id != transfer.to {
            return None;
        }
        let mut replica_key_history = HashSet::new();
        let _ = replica_key_history.insert(replicas);
        Some(Actor {
            id: transfer.to,
            client_id,
            replica_key_history,
            history: History::new(transfer),
            current_transfer_version: None,
            accumulating_validations: Default::default(),
        })
    }

    /// Query for new credits since specified index.
    /// NB: This is not guaranteed to give you all unknown to you,
    /// since there is no absolute order on the credits!
    pub fn credits_since(&self, index: usize) -> Vec<Transfer> {
        self.history.credits_since(index)
    }

    /// Query for new debits since specified index.
    pub fn debits_since(&self, index: usize) -> Vec<Transfer> {
        self.history.debits_since(index)
    }

    /// Query
    pub fn local_balance(&self) -> Money {
        self.history.balance()
    }

    /// Step 1. Build a valid cmd for validation of a debit.
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
                    // ensures one debit is completed at a time
                    return Err(Error::InvalidOperation); // "current pending debit has not been completed"
                }
                if next_version != id.counter {
                    return Err(Error::InvalidOperation); // "either already proposed or out of order debit"
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
                    actor_signature: signature,
                };
                Ok(TransferInitiated { cmd })
            }
            Err(e) => Err(e),
        }
    }

    /// Step 2. Receive validations from Replicas, aggregate the signatures.
    pub fn receive(&self, validation: TransferValidated) -> Result<TransferValidationReceived> {
        // Always verify signature first! (as to not leak any information).
        if !self.verify(&validation).is_ok() {
            return Err(Error::InvalidSignature);
        }
        let transfer_cmd = &validation.transfer_cmd;
        // check if validation was initiated by this actor
        if self.id != transfer_cmd.transfer.id.actor {
            return Err(Error::InvalidOperation); // "validation is not intended for this actor"
        }
        // check if expected this validation
        match self.current_transfer_version {
            None => return Err(Error::InvalidOperation), // "there is no pending transfer, cannot receive validations"
            Some(counter) => {
                if counter != transfer_cmd.transfer.id.counter {
                    return Err(Error::InvalidOperation); // "out of order validation"
                }
            }
        }
        // check if already received
        for (_, validations) in &self.accumulating_validations {
            if validations.contains(&validation) {
                return Err(Error::InvalidOperation); // "Already received validation"
            }
        }

        let mut proof = None;
        let accumulating_validations = &self.accumulating_validations;
        let largest_group = accumulating_validations
            .clone()
            .into_iter()
            .max_by_key(|c| c.1.len());
        match largest_group {
            None => (),
            Some((replicas, accumulated)) => {
                // If received validation is made by same set of replicas as this group,
                // and the current count of accumulated is same as the threshold,
                // then we have reached the quorum needed to build the proof. (Quorum = threshold + 1)
                let quorum =
                    accumulated.len() == replicas.threshold() && replicas == validation.replicas;
                if quorum {
                    // collect sig shares
                    let sig_shares: BTreeMap<_, _> = accumulated
                        .into_iter()
                        .map(|v| v.replica_signature)
                        .map(|s| (s.index, s.signature))
                        .collect();

                    if let Ok(data) = bincode::serialize(&transfer_cmd) {
                        // Combine shares to produce the main signature.
                        let sig = replicas
                            .combine_signatures(&sig_shares)
                            .expect("not enough shares");
                        // Validate the main signature. If the shares were valid, this can't fail.
                        if replicas.public_key().verify(&sig, data) {
                            proof = Some(ProofOfAgreement {
                                transfer_cmd: transfer_cmd.clone(),
                                section_sig: safe_nd::Signature::Bls(sig),
                            });
                        } // else, we have some corrupt data
                    };
                }
            }
        }

        Ok(TransferValidationReceived { validation, proof })
    }

    /// Step 3. Build a valid cmd for registration of an agreed transfer.
    pub fn register(&self, proof: ProofOfAgreement) -> Result<TransferRegistrationSent> {
        // Always verify signature first! (as to not leak any information).
        if !self.verify_debits_proof(&proof).is_ok() {
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
            Err(_) => Err(Error::InvalidOperation), // from this place this code won't happen, but history validates the transfer is actually debits from it's owner.
        }
    }

    /// Step xx. Continuous syncing from Replicas ensure
    /// that we receive transfers initiated at other Actor instances (same id or other).
    /// This can be push or pull model, decided by upper layer.
    pub fn sync_credits(&self, proofs: Vec<ProofOfAgreement>) -> Result<RemoteCreditsSynced> {
        let valid_credits = proofs
            .iter()
            .filter(|p| self.id == p.transfer_cmd.transfer.to)
            .filter(|p| !self.history.contains(&p.transfer_cmd.transfer.id))
            .filter(|p| self.verify_credits_proof(p).is_ok())
            .map(|p| p.clone())
            .collect::<Vec<ProofOfAgreement>>();

        if valid_credits.len() > 0 {
            Ok(RemoteCreditsSynced {
                credits: valid_credits,
            })
        } else {
            Err(Error::InvalidOperation)
        }
    }

    /// Step xx. Continuous syncing from Replicas ensure
    /// that we receive transfers initiated at other Actor instances (same id or other).
    /// This can be push or pull model, decided by upper layer.
    /// With multiple devices we can also sync debits made on other devices.
    pub fn sync_debits(
        &self,
        credits: Vec<ProofOfAgreement>,
        debits: Vec<ProofOfAgreement>,
    ) -> Result<RemoteDebitsSynced> {
        let mut debits = debits
            .iter()
            .filter(|p| self.id == p.transfer_cmd.transfer.id.actor)
            .filter(|p| self.verify_debits_proof(p).is_ok())
            .collect::<Vec<&ProofOfAgreement>>();

        debits.sort_by_key(|t| t.transfer_cmd.transfer.id.counter);

        let mut iter = 0;
        let mut valid_debits = vec![];
        for out in debits {
            let version = out.transfer_cmd.transfer.id.counter;
            let expected_version = iter + self.history.next_version();
            if version != expected_version {
                break; // since it's sorted, if first is not matching, then no point continuing
            }
            valid_debits.push(out.clone());
            iter += 1;
        }

        if valid_debits.len() > 0 {
            Ok(RemoteDebitsSynced {
                debits: valid_debits,
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
                if let Some(_) = e.proof {
                    // if we have a proof, then we have a valid set of replicas (potentially new) to update with
                    let _ = self
                        .replica_key_history
                        .insert(e.validation.replicas.clone());
                }
                match self
                    .accumulating_validations
                    .get_mut(&e.validation.replicas)
                {
                    Some(set) => {
                        let _ = set.insert(e.validation.clone());
                    }
                    None => {
                        // Creates if not exists.
                        let mut set = HashSet::new();
                        let _ = set.insert(e.validation.clone());
                        let _ = self
                            .accumulating_validations
                            .insert(e.validation.replicas.clone(), set);
                    }
                }
            }
            ActorEvent::TransferRegistrationSent(e) => {
                let transfer = e.cmd.proof.transfer_cmd.transfer;
                self.history.append(transfer);
                self.accumulating_validations.clear();
            }
            ActorEvent::RemoteCreditsSynced(e) => {
                for proof in e.credits {
                    self.history.append(proof.transfer_cmd.transfer);
                }
            }
            ActorEvent::RemoteDebitsSynced(e) => {
                for proof in e.debits {
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

    /// We verify that we signed the underlying cmd,
    /// and the replica signature against the pk set included in the event.
    /// Note that we use the provided pk set to verify the event.
    /// This might not be the way we want to do it.
    fn verify(&self, event: &TransferValidated) -> Result<()> {
        let cmd = &event.transfer_cmd;
        // Check that we signed this.
        if let error @ Err(_) = self.verify_is_our_transfer(cmd) {
            return error;
        }

        // Check that the replica signature is valid per the provided public key set.
        let replica_signature = &event.replica_signature.signature;
        let share_index = event.replica_signature.index;
        match bincode::serialize(&cmd) {
            Err(_) => Err(Error::NetworkOther(
                "Could not serialise transfer cmd".into(),
            )),
            Ok(data) => {
                let verified = event
                    .replicas
                    .public_key_share(share_index)
                    .verify(replica_signature, data);
                if verified {
                    Ok(())
                } else {
                    Err(Error::InvalidSignature)
                }
            }
        }
    }

    /// Verify that this is a valid ProofOfAgreement over our cmd.
    fn verify_debits_proof(&self, proof: &ProofOfAgreement) -> Result<()> {
        let cmd = &proof.transfer_cmd;
        // Check that we signed this.
        if let error @ Err(_) = self.verify_is_our_transfer(cmd) {
            return error;
        }

        // Check that the proof corresponds to a/the public key set of our Replicas.
        match bincode::serialize(&proof.transfer_cmd) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                for set in &self.replica_key_history {
                    let public_key = safe_nd::PublicKey::Bls(set.public_key());
                    let result = public_key.verify(&proof.section_sig, &data);
                    if result.is_ok() {
                        return result;
                    }
                }
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Verify that this is a valid ProofOfAgreement.
    fn verify_credits_proof(&self, proof: &ProofOfAgreement, replicas: PublicKeySet) -> Result<()> {
        // Check that the proof corresponds to the public key set of some remote Replicas.
        match bincode::serialize(&proof.transfer_cmd) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                let public_key = safe_nd::PublicKey::Bls(replicas.public_key());
                let result = public_key.verify(&proof.section_sig, &data);
                if result.is_ok() {
                    return result;
                }
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Check that we signed this.
    /// Used both by verify_proof() and verify_transfer_validation().
    fn verify_is_our_transfer(&self, cmd: &ValidateTransfer) -> Result<()> {
        match bincode::serialize(&cmd.transfer) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                let actor_sig = self
                    .client_id
                    .public_id()
                    .public_key()
                    .verify(&cmd.actor_signature, data);
                if actor_sig.is_ok() {
                    Ok(())
                } else {
                    Err(Error::InvalidSignature)
                }
            }
        }
    }
}
