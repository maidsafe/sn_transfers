// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    account::Account, AccountId, ActorEvent, CreditsReceived, DebitAgreementProof, DebitsReceived,
    ReceivedCredit, RegisterTransfer, ReplicaValidator, SignatureShare, Transfer,
    TransferInitiated, TransferRegistrationSent, TransferValidated, TransferValidationReceived,
    ValidateTransfer,
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

/// The Actor is the part of an AT2 system
/// that initiates transfers, by requesting Replicas
/// to validate them, and then receive the proof of agreement.
/// It also syncs transfers from the Replicas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor<V: ReplicaValidator> {
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
    /// The passed in replica_validator, contains the logic from upper layers
    /// for determining if a remote group of Replicas, represented by a PublicKey, is indeed valid.
    replica_validator: V,
}

impl<V: ReplicaValidator> Actor<V> {
    /// Pass in the first credit.
    /// Without it, there is no Actor, since there is no balance.
    /// There is no essential validations here, since without a valid transfer
    /// this Actor can't really convince Replicas to do anything.
    pub fn new(
        client_id: ClientFullId,
        transfer: Transfer,
        replicas: PublicKeySet,
        replica_validator: V,
    ) -> Option<Actor<V>> {
        let id = *client_id.public_id().public_key();
        if id != transfer.to {
            return None;
        }
        if 0 >= transfer.amount.as_nano() {
            return None;
        }
        Some(Actor {
            id: transfer.to,
            client_id,
            replicas,
            replica_validator,
            account: Account::new(transfer),
            current_debit_version: None,
            accumulating_validations: Default::default(),
        })
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Queries ----------------------------------
    /// -----------------------------------------------------------------

    /// Query for the id of the Actor.
    pub fn id(&self) -> AccountId {
        self.id
    }

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
    pub fn balance(&self) -> Money {
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
        if amount > self.balance() {
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
                    let last_sig = validation.clone().replica_signature;
                    let sig_shares: BTreeMap<_, _> = accumulated
                        .into_iter()
                        .map(|v| v.replica_signature)
                        .map(|s| (s.index, s.share))
                        .chain(vec![(last_sig.index, last_sig.share)])
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
        if !self.verify_debit_proof(&proof).is_ok() {
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

    /// Step xx. Continuously receiving credits from Replicas via push or pull model, decided by upper layer.
    /// The credits are most likely originating at an Actor whose Replicas are not the same as our Replicas.
    /// That means that the signature on the DebitAgreementProof, is that of some Replicas we don't know.
    /// What we do here is to use the passed in replica_validator, that injects the logic from upper layers
    /// for determining if this remote group of Replicas is indeed valid.
    /// It should consider our Replicas valid as well, for the rare cases when sender replicate to the same group.
    pub fn receive_credits(&self, proofs: Vec<ReceivedCredit>) -> Result<CreditsReceived> {
        let valid_credits = proofs
            .iter()
            .filter(|p| self.verify_credit_proof(p).is_ok())
            .filter(|p| self.id == p.debit_proof.transfer_cmd.transfer.to)
            .filter(|p| {
                !self
                    .account
                    .contains(&p.debit_proof.transfer_cmd.transfer.id)
            })
            .map(|p| p.clone())
            .collect::<Vec<ReceivedCredit>>();

        if valid_credits.len() > 0 {
            Ok(CreditsReceived {
                credits: valid_credits,
            })
        } else {
            Err(Error::InvalidOperation)
        }
    }

    /// Step xx. Continuously receiving debits from Replicas via push or pull model, decided by upper layer.
    /// This ensures that we receive transfers initiated at other Actor instances (same id or other,
    /// i.e. with multiple instances of same Actor we can also sync debits made on other isntances).
    pub fn receive_debits(&self, debits: Vec<DebitAgreementProof>) -> Result<DebitsReceived> {
        let mut debits = debits
            .iter()
            .filter(|p| self.id == p.transfer_cmd.transfer.id.actor)
            .filter(|p| self.verify_debit_proof(p).is_ok())
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
            Ok(DebitsReceived {
                debits: valid_debits,
            })
        } else {
            Err(Error::InvalidOperation) // TODO: We need much better error types to inform about what is wrong.
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
            ActorEvent::CreditsReceived(e) => {
                for credit in e.credits {
                    self.account
                        .append(credit.debit_proof.transfer_cmd.transfer); // append credit
                }
            }
            ActorEvent::DebitsReceived(e) => {
                for proof in e.debits {
                    self.account.append(proof.transfer_cmd.transfer);
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
    // (if we only use this in one place we can move the content to that method)
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
    fn verify_debit_proof(&self, proof: &DebitAgreementProof) -> Result<()> {
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

    /// Verify that this is a valid ReceivedCredit.
    fn verify_credit_proof(&self, credit: &ReceivedCredit) -> Result<()> {
        if !self.replica_validator.is_valid(credit.signing_replicas) {
            return Err(Error::InvalidSignature);
        }
        let proof = &credit.debit_proof;
        // Check that the proof corresponds to a/the public key set of our Replicas.
        match bincode::serialize(&proof.transfer_cmd) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                let public_key = safe_nd::PublicKey::Bls(credit.signing_replicas);
                public_key.verify(&proof.sender_replicas_sig, &data)
            }
        }
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

mod test {
    use super::{Actor, ActorEvent, ReplicaValidator, Transfer, TransferInitiated};
    use crdts::Dot;
    use rand::Rng;
    use safe_nd::{ClientFullId, Money, PublicKey};
    use threshold_crypto::{SecretKey, SecretKeySet};

    struct Validator {}

    impl ReplicaValidator for Validator {
        fn is_valid(&self, replica_group: threshold_crypto::PublicKey) -> bool {
            true
        }
    }

    #[test]
    fn creates_actor() {
        // Act
        let _ = get_actor(10);
    }

    #[test]
    fn initial_state_is_applied() {
        // Act
        let initial_amount = 10;
        let actor = get_actor(initial_amount);
        let credits = actor.credits_since(0);
        let debits = actor.debits_since(0);
        assert!(debits.len() == 0);
        assert!(credits.len() == 1);
        assert!(credits[0].amount == Money::from_nano(initial_amount));
        assert!(actor.balance() == Money::from_nano(initial_amount));
    }

    #[test]
    fn initiates_transfers() {
        // Act
        let actor = get_actor(10);
        let debit = get_debit(&actor);
        let mut actor = actor;
        actor.apply(ActorEvent::TransferInitiated(debit))
    }

    fn get_debit(actor: &Actor<Validator>) -> TransferInitiated {
        match actor.initiate(Money::from_nano(10), get_random_pk()) {
            Ok(event) => event,
            Err(_) => panic!(),
        }
    }

    fn get_actor(amount: u64) -> Actor<Validator> {
        let mut rng = rand::thread_rng();
        let client_id = ClientFullId::new_ed25519(&mut rng);
        let client_pubkey = *client_id.public_id().public_key();
        let bls_secret_key = SecretKeySet::random(1, &mut rng);
        let replicas_id = bls_secret_key.public_keys();
        let balance = Money::from_nano(amount);
        let sender = Dot::new(get_random_pk(), 0);
        let transfer = get_transfer(sender, client_pubkey, balance);
        let replica_validator = Validator {};
        match Actor::new(client_id, transfer, replicas_id, replica_validator) {
            None => panic!(),
            Some(actor) => actor,
        }
    }

    fn get_transfer(from: Dot<PublicKey>, to: PublicKey, amount: Money) -> Transfer {
        Transfer {
            id: from,
            to,
            amount,
        }
    }

    fn get_random_dot() -> Dot<PublicKey> {
        Dot::new(get_random_pk(), 0)
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }
}
