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
    /// The index of this Replica key share, in the group set.
    index: usize,
    /// Secret key share.
    secret_key: SecretKeyShare,
    /// The PK set of our peer Replicas.
    peer_replicas: PublicKeySet,
    /// PK sets of other known groups of Replicas.
    other_groups: HashSet<PublicKeySet>,
    /// All accounts that this Replica validates transfers for.
    accounts: HashMap<AccountId, Account>,
    /// Ensures that invidual account's debit
    /// initiations (ValidateTransfer cmd) are sequential.
    pending_debits: VClock<AccountId>,
}

impl Replica {
    /// A new Replica instance.
    pub fn new(
        secret_key: SecretKeyShare,
        index: usize,
        peer_replicas: PublicKeySet,
        other_groups: HashSet<PublicKeySet>,
    ) -> Self {
        let id = secret_key.public_key_share();
        Replica {
            secret_key,
            id,
            index,
            peer_replicas,
            other_groups,
            accounts: Default::default(),
            pending_debits: VClock::new(),
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
        if peers == self.peer_replicas {
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
                    replicas: self.peer_replicas.clone(),
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
        if transfer.id != self.pending_debits.inc(transfer.id.actor) {
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
                replicas: self.peer_replicas.clone(),
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
            ReplicaEvent::PeersChanged(e) => self.peer_replicas = e.peers,
            ReplicaEvent::KnownGroupAdded(e) => {
                let _ = self.other_groups.insert(e.group);
            }
            ReplicaEvent::TransferValidated(e) => {
                let transfer = e.transfer_cmd.transfer;
                self.pending_debits.apply(transfer.id);
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

    /// Replicas of the credited account, sign the debit proof
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
    /// DebitAgreementProof, i.e. signed by our peers.
    fn verify_registered_proof(&self, proof: &DebitAgreementProof) -> Result<()> {
        // Check that the proof corresponds to a public key set of our peers.
        match bincode::serialize(&proof.transfer_cmd) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                // Check if proof is signed by our peers.
                let public_key = safe_nd::PublicKey::Bls(self.peer_replicas.public_key());
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
    // DebitAgreementProof, i.e. signed by a group that we know of.
    fn verify_propagated_proof(&self, proof: &DebitAgreementProof) -> Result<()> {
        // Check that the proof corresponds to a public key set of some Replicas.
        match bincode::serialize(&proof.transfer_cmd) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => {
                // Check all known groups of Replicas.
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

mod test {
    use super::Replica;
    use crate::{
        actor::Actor, ActorEvent, ReceivedCredit, ReplicaEvent, ReplicaValidator, Transfer,
    };
    use crdts::Dot;
    use rand::Rng;
    use safe_nd::{ClientFullId, Money, PublicKey};
    use std::collections::{HashMap, HashSet};
    use threshold_crypto::{PublicKeySet, SecretKey, SecretKeySet};

    struct Validator {}

    impl ReplicaValidator for Validator {
        fn is_valid(&self, replica_group: threshold_crypto::PublicKey) -> bool {
            true
        }
    }

    #[test]
    fn send_between_replica_groups() {
        // --- Arrange ---
        let actor_0_initial = Money::from_nano(100);
        let actor_1_initial = Money::from_nano(10);
        let actor_1_final = actor_0_initial.checked_add(actor_1_initial).unwrap();
        let mut actor_0 = get_actor(actor_0_initial.as_nano());
        let mut actor_1 = get_actor(actor_1_initial.as_nano());
        let mut replica_groups = get_replica_groups();
        let transfer = actor_0.initiate(actor_0.balance(), actor_1.id()).unwrap();
        let cmd = transfer.cmd;
        let mut debit_proof = None;
        let mut sender_replicas_pubkey = None;

        // --- Act ---
        // Validate at Replica Group 0
        for (index, (keyset, group)) in &mut replica_groups {
            if *index != 0 {
                continue;
            }
            sender_replicas_pubkey = Some(keyset.public_key());
            for replica in group {
                let validated = replica.validate(cmd.clone()).unwrap();
                replica.apply(ReplicaEvent::TransferValidated(validated.clone()));
                let validation_received = actor_0.receive(validated).unwrap();
                actor_0.apply(ActorEvent::TransferValidationReceived(
                    validation_received.clone(),
                ));

                if let Some(proof) = validation_received.proof {
                    debit_proof = Some(proof);
                }
            }
        }

        // Register at Replica Group 0
        for (index, (_, group)) in &mut replica_groups {
            if *index != 0 {
                continue;
            }
            for replica in group {
                let registered = replica.register(debit_proof.clone().unwrap()).unwrap();
                replica.apply(ReplicaEvent::TransferRegistered(registered));
            }
        }

        let mut set = HashSet::new();
        // Propagate to Replica Group 1
        for (index, (_, group)) in &mut replica_groups {
            if *index != 1 {
                continue;
            }
            for replica in group {
                let propagated = replica
                    .receive_propagated(debit_proof.clone().unwrap())
                    .unwrap();
                replica.apply(ReplicaEvent::TransferPropagated(propagated.clone()));
                match replica.credits_since(&actor_1.id(), 0) {
                    None => panic!("No credits!"),
                    Some(credits) => {
                        assert!(credits.len() == 1);
                        match replica.balance(&actor_1.id()) {
                            None => panic!("No balance!"),
                            Some(balance) => assert!(credits[0].amount == balance),
                        }
                        let _ = set.insert(ReceivedCredit {
                            debit_proof: propagated.debit_proof,
                            signing_replicas: sender_replicas_pubkey.unwrap(),
                        });
                    }
                }
            }
        }
        let received_credits = set.into_iter().collect();
        let credits_received = actor_1.receive_credits(received_credits).unwrap();
        actor_1.apply(ActorEvent::CreditsReceived(credits_received));

        // --- Assert ---

        assert!(actor_0.balance() == Money::zero());
        assert!(actor_1.balance() == actor_1_final);
    }

    fn get_replica_groups() -> HashMap<usize, (PublicKeySet, Vec<Replica>)> {
        let mut rng = rand::thread_rng();

        // Create 3 replica groups, with 3 replicas in each
        let v: [u64; 3] = [0, 1, 2];
        let mut groups = HashMap::new();
        for i in &v {
            let bls_secret_key = SecretKeySet::random(3, &mut rng);
            let peers = bls_secret_key.public_keys();
            let mut shares = vec![];
            for j in &v {
                let share = bls_secret_key.secret_key_share(j);
                shares.push((share, *j as usize));
            }
            let _ = groups.insert(i, (peers, shares));
        }

        let mut other_groups = HashMap::new();
        let _ = other_groups.insert(0, vec![1, 2]);
        let _ = other_groups.insert(1, vec![0, 2]);
        let _ = other_groups.insert(2, vec![0, 1]);

        let mut replica_groups = HashMap::new();
        for i in &v {
            let other = other_groups[i]
                .clone()
                .into_iter()
                .map(|c| groups[i].clone())
                .map(|c| c.0)
                .collect::<HashSet<PublicKeySet>>();

            let mut replicas = vec![];
            let (key, shares) = groups[i].clone();
            for (share, index) in shares {
                let replica = Replica::new(share, index, key.clone(), other.clone());
                replicas.push(replica);
            }
            let _ = replica_groups.insert(*i as usize, (key, replicas));
        }
        replica_groups
    }

    fn get_actor(amount: u64) -> Actor<Validator> {
        let mut rng = rand::thread_rng();
        let client_id = ClientFullId::new_ed25519(&mut rng);
        let client_pubkey = *client_id.public_id().public_key();
        let bls_secret_key = SecretKeySet::random(1, &mut rng);
        let replicas_id = bls_secret_key.public_keys();
        let balance = Money::from_nano(amount);
        let sender = Dot::new(get_random_pk(), 0);
        let transfer = Transfer {
            id: sender,
            to: client_pubkey,
            amount: balance,
        };
        let replica_validator = Validator {};
        match Actor::new(client_id, transfer, replicas_id, replica_validator) {
            None => panic!(),
            Some(actor) => actor,
        }
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }
}
