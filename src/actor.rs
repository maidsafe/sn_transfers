// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    account::Account, AccountId, ActorEvent, CreditAgreementProof, DebitAgreementProof,
    NewCreditsReceived, NewDebitsReceived, RegisterTransfer, SignatureShare, SignedCredit,
    Transfer, TransferInitiated, TransferRegistrationSent, TransferValidated,
    TransferValidationReceived, ValidateTransfer,
};
use crdts::Dot;
use safe_nd::{ClientFullId, Error, Money, Result, Signature};
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

type TransferIdHash = Vec<u8>;

/// The Actor is the part of an AT2 system
/// that initiates transfers, by requesting Replicas
/// to validate them, and then receive the proof of agreement.
/// It also syncs transfers from the Replicas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    id: AccountId,
    client_id: ClientFullId,
    /// Set of all transfers impacting a given identity
    account: Account,
    /// Ensures that the actor's transfer
    /// initiations (ValidateTransfer cmd) are sequential.
    current_debit_version: Option<u64>,
    /// When a transfer is initiated, validations are accumulated here.
    /// After quorum is reached and proof produced, the set is cleared.
    accumulating_validations: BTreeMap<PublicKeySet, HashSet<TransferValidated>>,
    /// The PK Set of the Replicas
    replicas: PublicKeySet,
    /// In progress syncing of remote credits.
    accumulating_remote_credits: BTreeMap<TransferIdHash, HashSet<SignedCredit>>,
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
        Some(Actor {
            id: transfer.to,
            client_id,
            replicas,
            account: Account::new(transfer),
            current_debit_version: None,
            accumulating_validations: Default::default(),
            accumulating_remote_credits: Default::default(),
        })
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Queries ----------------------------------
    /// -----------------------------------------------------------------

    /// Query for new credits since specified index.
    /// NB: This is not guaranteed to give you all unknown to you,
    /// since there is no absolute order on the credits!
    pub fn credits_since(&self, index: usize) -> Vec<Transfer> {
        self.account.credits_since(index)
    }

    /// Query for new debits since specified index.
    pub fn debits_since(&self, index: usize) -> Vec<Transfer> {
        self.account.debits_since(index)
    }

    /// Query for the balance of the Actor.
    pub fn local_balance(&self) -> Money {
        self.account.balance()
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Cmds -------------------------------------
    /// -----------------------------------------------------------------

    /// Step 1. Build a valid cmd for validation of a debit.
    pub fn initiate(&self, amount: Money, to: AccountId) -> Result<TransferInitiated> {
        if to == self.id {
            return Err(Error::InvalidOperation); // "Sender and recipient are the same"
        }

        let id = Dot::new(self.id, self.account.next_debit());

        match self.current_debit_version {
            None => {
                if id.counter != 0 {
                    return Err(Error::InvalidOperation); // "out of order msg"
                }
            }
            Some(current_debit) => {
                let next_debit = current_debit + 1;
                if next_debit != self.account.next_debit() {
                    // ensures one debit is completed at a time
                    return Err(Error::InvalidOperation); // "current pending debit has not been completed"
                }
                if next_debit != id.counter {
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
            Ok(actor_signature) => {
                let cmd = ValidateTransfer {
                    transfer,
                    actor_signature,
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
        match self.current_debit_version {
            None => return Err(Error::InvalidOperation), // "there is no pending transfer, cannot receive validations"
            Some(version) => {
                if version != transfer_cmd.transfer.id.counter {
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
                        .map(|s| (s.index, s.share))
                        .collect();

                    if let Ok(data) = bincode::serialize(&transfer_cmd) {
                        // Combine shares to produce the main signature.
                        let sig = replicas
                            .combine_signatures(&sig_shares)
                            .expect("not enough shares");
                        // Validate the main signature. If the shares were valid, this can't fail.
                        if replicas.public_key().verify(&sig, data) {
                            proof = Some(DebitAgreementProof {
                                transfer_cmd: transfer_cmd.clone(),
                                sender_replicas_sig: safe_nd::Signature::Bls(sig),
                            });
                        } // else, we have some corrupt data
                    };
                }
            }
        }

        Ok(TransferValidationReceived { validation, proof })
    }

    /// Step 3. Build a valid cmd for registration of an agreed transfer.
    pub fn register(&self, proof: DebitAgreementProof) -> Result<TransferRegistrationSent> {
        // Always verify signature first! (as to not leak any information).
        if !self.verify_debits_proof(&proof).is_ok() {
            return Err(Error::InvalidSignature);
        }
        match self.account.is_sequential(&proof.transfer_cmd.transfer) {
            Ok(is_sequential) => {
                if is_sequential {
                    Ok(TransferRegistrationSent {
                        cmd: RegisterTransfer { proof },
                    })
                } else {
                    Err(Error::InvalidOperation) // "Non-sequential operation"
                }
            }
            Err(_) => Err(Error::InvalidOperation), // from this place this code won't happen, but account validates the transfer is actually debits from it's owner.
        }
    }

    /// Step xx. Continuously receiving debits from Replicas via push or pull model, decided by upper layer.
    /// This ensures that we receive transfers initiated at other Actor instances (same id or other,
    /// i.e. with multiple instances of same Actor we can also sync debits made on other isntances).
    pub fn receive_debits(&self, debits: Vec<DebitAgreementProof>) -> Result<NewDebitsReceived> {
        let mut debits = debits
            .iter()
            .filter(|p| self.id == p.transfer_cmd.transfer.id.actor)
            .filter(|p| self.verify_debits_proof(p).is_ok())
            .collect::<Vec<&DebitAgreementProof>>();

        debits.sort_by_key(|t| t.transfer_cmd.transfer.id.counter);

        let mut iter = 0;
        let mut valid_debits = vec![];
        for out in debits {
            let version = out.transfer_cmd.transfer.id.counter;
            let expected_version = iter + self.account.next_debit();
            if version != expected_version {
                break; // since it's sorted, if first is not matching, then no point continuing
            }
            valid_debits.push(out.clone());
            iter += 1;
        }

        if valid_debits.len() > 0 {
            Ok(NewDebitsReceived {
                debits: valid_debits,
            })
        } else {
            Err(Error::InvalidOperation) // TODO: We need much better error types to inform about what is wrong.
        }
    }

    /// Step xx. Continuously receiving credits from Replicas via push or pull model, decided by upper layer.
    /// The credits are most likely originating at an Actor whose Replicas are not the same as our Replicas.
    /// That means that the signature on the DebitAgreementProof, is that of some Replicas we don't know.
    /// What we do here is to aggregate signatures from our Replicas, over that same DebitAgreementProof, as to
    /// confirm that it is a valid DebitAgreementProof. An alternative to this would be to know the other Replicas
    /// (i.e. know them as valid Replicas in the network) so that we could verify their signature with their public key.
    /// Unfortunately, that would require us to know all groups of Replicas in the entire network.
    /// The solution picked here is more convoluted (at this place at least), as we aggregate signatures from all our Replicas,
    /// but it allows our Actor instance to be aware of only its Replicas, and no other.
    /// Cost / benefit (or better solution of course) to be discussed..
    pub fn receive_credits(&self, proofs: Vec<SignedCredit>) -> Result<NewCreditsReceived> {
        let accumulating_credits = proofs
            .iter()
            .filter(|p| self.id == p.debit_proof.transfer_cmd.transfer.to)
            .filter(|p| {
                !self
                    .account
                    .contains(&p.debit_proof.transfer_cmd.transfer.id)
            })
            .filter(|p| self.verify_credit(p).is_ok())
            .filter(|p| {
                // check not already added
                let transfer_id_hash = vec![];
                match self.accumulating_remote_credits.get(&transfer_id_hash) {
                    None => true,
                    Some(set) => !set.contains(p),
                }
            })
            .map(|p| p.clone())
            .collect::<Vec<SignedCredit>>();

        let mut accumulated_credit_proofs = vec![];
        let threshold = self.replicas.threshold();
        for credit in &accumulating_credits {
            let transfer_id_hash = vec![];
            match self.accumulating_remote_credits.get(&transfer_id_hash) {
                None => continue,
                Some(set) => {
                    let quorum = set.len() == threshold;
                    if quorum {
                        let mut accumulated = set.clone();
                        let _ = accumulated.insert(credit.clone());
                        // collect sig shares
                        let sig_shares: BTreeMap<_, _> = accumulated
                            .into_iter()
                            .map(|v| v.receiver_replica_sig)
                            .map(|s| (s.index, s.share))
                            .collect();

                        if let Ok(data) = bincode::serialize(&credit.debit_proof) {
                            // Combine shares to produce the main signature.
                            let sig = self
                                .replicas
                                .combine_signatures(&sig_shares)
                                .expect("not enough shares");
                            // Validate the main signature. If the shares were valid, this can't fail.
                            if self.replicas.public_key().verify(&sig, data) {
                                accumulated_credit_proofs.push(CreditAgreementProof {
                                    debit_proof: credit.debit_proof.clone(),
                                    receiver_replica_sig: safe_nd::Signature::Bls(sig),
                                });
                            } // else, we have some corrupt data
                        };
                    }
                }
            }
        }

        // NB: We do not remove from accumulating_credits where we have a proof,
        // simply because we inform about the signature share received by keeping it.
        // It does not affect state, since that set is cleared when we have a proof.

        let any_valid_credits =
            accumulating_credits.len() > 0 || accumulated_credit_proofs.len() > 0;

        if any_valid_credits {
            Ok(NewCreditsReceived {
                accumulating_credits,
                accumulated_credit_proofs,
            })
        } else {
            Err(Error::InvalidOperation)
        }
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Mutation ---------------------------------
    /// -----------------------------------------------------------------

    /// Mutation of state.
    /// There is no validation of an event, it is assumed to have
    /// been properly validated before raised, and thus anything that breaks is a bug.
    pub fn apply(&mut self, event: ActorEvent) {
        match event {
            ActorEvent::TransferInitiated(e) => {
                let transfer = e.cmd.transfer;
                self.current_debit_version = Some(transfer.id.counter);
            }
            ActorEvent::TransferValidationReceived(e) => {
                if let Some(_) = e.proof {
                    // if we have a proof, then we have a valid set of replicas (potentially new) to update with
                    self.replicas = e.validation.replicas.clone();
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
                self.account.append(transfer);
                self.accumulating_validations.clear();
            }
            ActorEvent::NewDebitsReceived(e) => {
                for proof in e.debits {
                    self.account.append(proof.transfer_cmd.transfer);
                }
            }
            ActorEvent::NewCreditsReceived(e) => {
                for credit in e.accumulating_credits {
                    let hash = vec![]; // hash(credit.debit_proof.transfer_cmd.transfer.id)
                    match self.accumulating_remote_credits.get_mut(&hash) {
                        Some(set) => {
                            let _ = set.insert(credit.clone());
                        }
                        None => {
                            // Creates if not exists.
                            let mut set = HashSet::new();
                            let _ = set.insert(credit.clone());
                            let _ = self.accumulating_remote_credits.insert(hash, set);
                        }
                    }
                }
                for proof in e.accumulated_credit_proofs {
                    self.account.append(proof.debit_proof.transfer_cmd.transfer); // append credit
                    let hash = vec![]; // hash(credit.debit_proof.transfer_cmd.transfer.id)
                    let _ = self.accumulating_remote_credits.remove(&hash); // clear accumulation of the credit
                }
            }
        };
        // consider event log, to properly be able to reconstruct state from restart
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Private methods --------------------------
    /// -----------------------------------------------------------------

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

        self.verify_share(cmd, &event.replica_signature, &event.replicas)
    }

    // Check that the replica signature is valid per the provided public key set.
    fn verify_share<T: serde::Serialize>(
        &self,
        item: T,
        replica_signature: &SignatureShare,
        replicas: &PublicKeySet,
    ) -> Result<()> {
        let sig_share = &replica_signature.share;
        let share_index = replica_signature.index;
        match bincode::serialize(&item) {
            Err(_) => Err(Error::NetworkOther("Could not serialise item".into())),
            Ok(data) => {
                let verified = replicas
                    .public_key_share(share_index)
                    .verify(sig_share, data);
                if verified {
                    Ok(())
                } else {
                    Err(Error::InvalidSignature)
                }
            }
        }
    }

    /// Verify that this is a valid DebitAgreementProof over our cmd.
    fn verify_debits_proof(&self, proof: &DebitAgreementProof) -> Result<()> {
        let cmd = &proof.transfer_cmd;
        // Check that we signed this.
        if let error @ Err(_) = self.verify_is_our_transfer(cmd) {
            return error;
        }

        // Check that the proof corresponds to a/the public key set of our Replicas.
        match bincode::serialize(&proof.transfer_cmd) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                let public_key = safe_nd::PublicKey::Bls(self.replicas.public_key());
                public_key.verify(&proof.sender_replicas_sig, &data)
            }
        }
    }

    /// Verify that this is a valid SignedCredit.
    fn verify_credit(&self, proof: &SignedCredit) -> Result<()> {
        self.verify_share(
            &proof.debit_proof,
            &proof.receiver_replica_sig,
            &self.replicas,
        )
    }

    /// Check that we signed this.
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
