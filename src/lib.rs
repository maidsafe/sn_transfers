// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Implementation of Transfers in the SAFE Network.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help`.
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

mod actor;
mod error;
mod genesis;
mod replica;
mod replica_signing;
mod wallet;
mod wallet_replica;

pub use self::{
    actor::Actor as TransferActor,
    error::Error,
    genesis::get_genesis,
    replica_signing::ReplicaSigning,
    wallet::{Wallet, WalletOwner},
    wallet_replica::WalletReplica,
};

use serde::{Deserialize, Serialize};
use sn_data_types::{
    CreditAgreementProof, CreditId, DebitId, Money, PublicKey, SignedCredit, SignedDebit,
    TransferAgreementProof, TransferValidated,
};
use std::collections::HashSet;

type Result<T> = std::result::Result<T, Error>;
type Outcome<T> = Result<Option<T>>;

trait TernaryResult<T> {
    fn success(item: T) -> Self;
    fn no_change() -> Self;
    fn rejected(error: Error) -> Self;
}

impl<T> TernaryResult<T> for Outcome<T> {
    fn success(item: T) -> Self {
        Ok(Some(item))
    }
    fn no_change() -> Self {
        Ok(None)
    }
    fn rejected(error: Error) -> Self {
        Err(error)
    }
}

/// A received credit, contains the CreditAgreementProof from the sender Replicas,
/// as well as the public key of those Replicas, for us to verify that they are valid Replicas.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct ReceivedCredit {
    /// The sender's aggregated Replica signatures of the credit.
    pub credit_proof: CreditAgreementProof,
    /// The public key of the signing Replicas.
    pub crediting_replica_keys: PublicKey,
}

impl ReceivedCredit {
    /// Get the transfer id
    pub fn id(&self) -> &CreditId {
        self.credit_proof.id()
    }

    /// Get the amount of this transfer
    pub fn amount(&self) -> Money {
        self.credit_proof.amount()
    }

    /// Get the recipient of this transfer
    pub fn recipient(&self) -> PublicKey {
        self.credit_proof.recipient()
    }
}

// ------------------------------------------------------------
//                      Actor
// ------------------------------------------------------------

/// An implementation of the ReplicaValidator, should contain the logic from upper layers
/// for determining if a remote group of Replicas, represented by a PublicKey, is indeed valid.
/// This is logic from the membership part of the system, and thus handled by the upper layers
/// membership implementation.
pub trait ReplicaValidator {
    /// Determines if a remote group of Replicas, represented by a PublicKey, is indeed valid.
    fn is_valid(&self, replica_group: PublicKey) -> bool;
}

/// Events raised by the Actor.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub enum ActorEvent {
    /// Raised when a request to create
    /// a transfer validation cmd for Replicas,
    /// has been successful (valid on local state).
    TransferInitiated(TransferInitiated),
    /// Raised when an Actor receives a Replica transfer validation.
    TransferValidationReceived(TransferValidationReceived),
    /// Raised when the Actor has accumulated a
    /// quorum of validations, and produced a RegisterTransfer cmd
    /// for sending to Replicas.
    TransferRegistrationSent(TransferRegistrationSent),
    /// Raised when the Actor has received
    /// unknown credits on querying Replicas.
    TransfersSynched(TransfersSynched),
}

/// Raised when the Actor has received
/// f.ex. credits that its Replicas were holding upon
/// the propagation of them from a remote group of Replicas,
/// or unknown debits that its Replicas were holding
/// upon the registration of them from another
/// instance of the same Actor.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct TransfersSynched {
    id: PublicKey,
    balance: Money,
    debit_version: u64,
    credit_ids: HashSet<CreditId>,
}

/// This event is raised by the Actor after having
/// successfully created a transfer cmd to send to the
/// Replicas for validation.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct TransferInitiated {
    /// The debit signed by the initiating Actor.
    pub signed_debit: SignedDebit,
    /// The credit signed by the initiating Actor.
    pub signed_credit: SignedCredit,
}

impl TransferInitiated {
    /// Get the debit id
    pub fn id(&self) -> DebitId {
        self.signed_debit.id()
    }
}

/// Raised when a Replica responds with
/// a successful validation of a transfer.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct TransferValidationReceived {
    /// The event raised by a Replica.
    validation: TransferValidated,
    /// Added when quorum of validations
    /// have been received from Replicas.
    pub proof: Option<TransferAgreementProof>,
}

/// Raised when the Actor has accumulated a
/// quorum of validations, and produced a RegisterTransfer cmd
/// for sending to Replicas.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct TransferRegistrationSent {
    transfer_proof: TransferAgreementProof,
}

#[allow(unused)]
mod test {
    use crate::{
        actor::Actor, genesis, wallet, wallet_replica::WalletReplica, ActorEvent, Error,
        ReplicaSigning, ReplicaValidator, Result, TransferInitiated, Wallet, WalletOwner,
    };
    //use anyhow::Result;
    use crdts::{
        quickcheck::{quickcheck, TestResult},
        Dot,
    };
    use sn_data_types::{
        Credit, CreditAgreementProof, CreditId, Debit, Keypair, Money, PublicKey, ReplicaEvent,
        SignedTransfer, Transfer, TransferAgreementProof,
    };
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use threshold_crypto::{PublicKeySet, SecretKey, SecretKeySet, SecretKeyShare};

    macro_rules! hashmap {
        ($( $key: expr => $val: expr ),*) => {{
             let mut map = ::std::collections::HashMap::new();
             $( let _ = map.insert($key, $val); )*
             map
        }}
    }

    // ------------------------------------------------------------------------
    // ------------------------ Basic Transfer --------------------------------
    // ------------------------------------------------------------------------

    #[test]
    fn basic_transfer() {
        let _ = transfer_between_actors(100, 10, 2, 3, 0, 1);
    }

    // #[test]
    // fn reproduce_quickcheck_basic_transfer() {
    //     let _ = transfer_between_actors(1, 0, 2, 4, 0, 1);
    // }

    // #[allow(trivial_casts)]
    // #[test]
    // fn quickcheck_basic_transfer() {
    //     quickcheck(transfer_between_actors as fn(u64, u64, u8, u8, u8, u8) -> TestResult);
    // }

    // ------------------------------------------------------------------------
    // ------------------------ Genesis --------------------------------
    // ------------------------------------------------------------------------

    #[test]
    fn can_start_with_genesis() -> Result<()> {
        let group_count = 1;
        let replica_count = 1;
        let (genesis, credit_proof) = get_genesis(replica_count - 1)?;
        //let genesis = setup_random_wallet(0, 0)?;
        println!("Got genesis");
        let keys = setup_replica_group_keys(group_count, replica_count as u8);
        let recipient = &genesis.wallet.id().public_key();
        let mut groups = setup_replica_groups(keys, vec![genesis]);
        println!("Got groups");
        for replica in &mut groups.remove(0).replicas {
            let past_key = Ok(PublicKey::Bls(replica.signing.replicas_pk_set().public_key()));
            let wallet_replica = match replica.wallets.get_mut(recipient) {
                Some(w) => w,
                None => panic!("Failed the test; no such wallet."),
            };
            let _ = wallet_replica
                .genesis(&credit_proof, || past_key)?
                .ok_or(Error::UnexpectedOutcome)?;

            println!("Passed genesis");

            wallet_replica.apply(ReplicaEvent::TransferPropagated(
                sn_data_types::TransferPropagated {
                    credit_proof: credit_proof.clone(),
                    crediting_replica_keys: PublicKey::Bls(
                        replica.signing.replicas_pk_set().public_key(),
                    ),
                    crediting_replica_sig: replica
                        .signing
                        .sign_credit_proof(&credit_proof)?
                        .ok_or(Error::UnexpectedOutcome)?,
                },
            ))?;
            let balance = wallet_replica.balance();
            println!("Balance: {}", balance);
            assert_eq!(credit_proof.amount(), balance);
        }
        Ok(())
    }

    use sn_data_types::SignatureShare;
    fn dummy_sig() -> SignatureShare {
        let dummy_shares = SecretKeyShare::default();
        let dummy_sig = dummy_shares.sign("DUMMY MSG");
        SignatureShare {
            index: 0,
            share: dummy_sig,
        }
    }

    #[test]
    fn genesis_can_only_be_the_first() -> Result<()> {
        let group_count = 1;
        let replica_count = 1;
        let (wallet, credit_proof) = get_genesis(replica_count - 1)?;
        let wallet_configs = hashmap![0 => 10];
        let (mut groups, _) = get_network(group_count, replica_count as u8, wallet, wallet_configs);
        for replica in &mut groups.remove(0).replicas {
            let past_key = Ok(PublicKey::Bls(credit_proof.replica_keys().public_key()));
            let wallet = match replica.wallets.get(&credit_proof.recipient()) {
                Some(w) => w,
                None => panic!("Failed the test; no such wallet."),
            };
            let result = wallet.genesis(&credit_proof, || past_key);
            assert_eq!(result.is_err(), true);
        }
        Ok(())
    }

    // ------------------------------------------------------------------------
    // ------------------------ Basic Transfer Body ---------------------------
    // ------------------------------------------------------------------------

    fn transfer_between_actors(
        sender_balance: u64,
        recipient_balance: u64,
        group_count: u8,
        replica_count: u8,
        sender_index: u8,
        recipient_index: u8,
    ) -> TestResult {
        match basic_transfer_between_actors(
            sender_balance,
            recipient_balance,
            group_count,
            replica_count,
            sender_index,
            recipient_index,
        ) {
            Ok(Some(_)) => TestResult::passed(),
            Ok(None) => TestResult::discard(),
            Err(_) => TestResult::failed(),
        }
    }

    fn basic_transfer_between_actors(
        sender_balance: u64,
        recipient_balance: u64,
        group_count: u8,
        replica_count: u8,
        sender_index: u8,
        recipient_index: u8,
    ) -> Result<Option<()>> {
        // --- Filter ---
        if 0 == sender_balance
            || 0 == group_count
            || 2 >= replica_count
            || sender_index >= group_count
            || recipient_index >= group_count
            || sender_index == recipient_index
        {
            return Ok(None);
        }

        // --- Arrange ---
        let recipient_final = sender_balance + recipient_balance;
        let wallet_configs =
            hashmap![sender_index => sender_balance, recipient_index => recipient_balance];
        let (genesis, credit_proof) = get_genesis(replica_count as usize - 1)?;
        let (_, mut actors) = get_network(group_count, replica_count, genesis, wallet_configs);
        let mut sender = actors.remove(&sender_index).ok_or(Error::MissingSender)?;
        let mut recipient = actors
            .remove(&recipient_index)
            .ok_or(Error::MissingRecipient)?;

        // --- Act ---
        // 1. Init transfer at Sender Actor.
        let transfer = init_transfer(&mut sender, recipient.actor.id())?;
        // 2. Validate at Sender Replicas.
        let debit_proof =
            validate_at_sender_replicas(transfer, &mut sender)?.ok_or(Error::UnexpectedOutcome)?;
        // 3. Register at Sender Replicas.
        register_at_debiting_replicas(&debit_proof, &mut sender.replica_group)?;
        // 4. Propagate to Recipient Replicas.
        let events = propagate_to_crediting_replicas(
            debit_proof.credit_proof(),
            &mut recipient.replica_group,
        );
        // 5. Synch at Recipient Actor.
        synch(&mut recipient)?;

        // --- Assert ---
        // Actor and Replicas have the correct balance.
        assert_balance(sender, Money::zero());
        assert_balance(recipient, Money::from_nano(recipient_final));
        Ok(Some(()))
    }

    fn assert_balance(actor: TestActor, amount: Money) {
        assert!(actor.actor.balance() == amount);
        actor.replica_group.replicas.iter().for_each(|replica| {
            let wallet = match replica.wallets.get(&actor.actor.id()) {
                Some(w) => w,
                None => panic!("Failed the test; no such wallet."),
            };
            assert_eq!(wallet.balance(), amount)
        });
    }

    // ------------------------------------------------------------------------
    // ------------------------ AT2 Steps -------------------------------------
    // ------------------------------------------------------------------------

    // 1. Init debit at Sender Actor.
    fn init_transfer(sender: &mut TestActor, to: PublicKey) -> Result<TransferInitiated> {
        let transfer = sender
            .actor
            .transfer(sender.actor.balance(), to, "asdf".to_string())?
            .ok_or(Error::UnexpectedOutcome)?;

        sender
            .actor
            .apply(ActorEvent::TransferInitiated(transfer.clone()))?;

        Ok(transfer)
    }

    // 2. Validate debit at Sender Replicas.
    fn validate_at_sender_replicas(
        transfer: TransferInitiated,
        sender: &mut TestActor,
    ) -> Result<Option<TransferAgreementProof>> {
        for replica in &mut sender.replica_group.replicas {
            let wallet_replica = match replica.wallets.get_mut(&sender.actor.id()) {
                Some(w) => w,
                None => panic!("Failed the test; no such wallet."),
            };
            let _ = wallet_replica
                .validate(&transfer.signed_debit, &transfer.signed_credit)?
                .ok_or(Error::UnexpectedOutcome)?;

            let signed_transfer = SignedTransfer {
                debit: transfer.signed_debit.clone(),
                credit: transfer.signed_credit.clone(),
            };
            if let Some((replica_debit_sig, replica_credit_sig)) =
                replica.signing.sign_transfer(&signed_transfer)?
            {
                let validation = sn_data_types::TransferValidated {
                    signed_credit: signed_transfer.credit,
                    signed_debit: signed_transfer.debit,
                    replica_debit_sig,
                    replica_credit_sig,
                    replicas: sender.replica_group.id.clone(),
                };
                // then apply to inmem state
                wallet_replica.apply(ReplicaEvent::TransferValidated(validation.clone()))?;

                let validation_received = sender
                    .actor
                    .receive(validation)?
                    .ok_or(Error::UnexpectedOutcome)?;
                sender.actor.apply(ActorEvent::TransferValidationReceived(
                    validation_received.clone(),
                ))?;
                if let Some(proof) = validation_received.proof {
                    let registered = sender
                        .actor
                        .register(proof.clone())?
                        .ok_or(Error::UnexpectedOutcome)?;
                    sender
                        .actor
                        .apply(ActorEvent::TransferRegistrationSent(registered))?;
                    return Ok(Some(proof));
                }
            } else {
                return Err(Error::InvalidSignature);
            }
        }
        Ok(None)
    }

    // 3. Register debit at Sender Replicas.
    fn register_at_debiting_replicas(
        debit_proof: &TransferAgreementProof,
        replica_group: &mut ReplicaGroup,
    ) -> Result<()> {
        for replica in &mut replica_group.replicas {
            let wallet_replica = match replica.wallets.get_mut(&debit_proof.sender()) {
                Some(w) => w,
                None => panic!("Failed the test; no such wallet."),
            };
            let past_key = Ok(PublicKey::Bls(debit_proof.replica_keys().public_key()));
            let registered = wallet_replica
                .register(debit_proof, || past_key)?
                .ok_or(Error::UnexpectedOutcome)?;
            wallet_replica.apply(ReplicaEvent::TransferRegistered(registered))?;
        }
        Ok(())
    }

    // 4. Propagate credit to Recipient Replicas.
    fn propagate_to_crediting_replicas(
        credit_proof: CreditAgreementProof,
        replica_group: &mut ReplicaGroup,
    ) -> Vec<ReplicaEvent> {
        replica_group
            .replicas
            .iter_mut()
            .map(|replica| {
                let wallet_replica = match replica.wallets.get_mut(&credit_proof.recipient()) {
                    Some(w) => w,
                    None => panic!("Failed the test; no such wallet."),
                };
                let past_key = Ok(PublicKey::Bls(credit_proof.replica_keys().public_key()));
                let _ = wallet_replica
                    .receive_propagated(&credit_proof, || past_key)?
                    .ok_or(Error::UnexpectedOutcome)?;

                if let Some(crediting_replica_sig) =
                    replica.signing.sign_credit_proof(&credit_proof)?
                {
                    let propagated = sn_data_types::TransferPropagated {
                        credit_proof: credit_proof.clone(),
                        crediting_replica_keys: PublicKey::Bls(
                            replica.signing.replicas_pk_set().public_key(),
                        ),
                        crediting_replica_sig,
                    };
                    // then apply to inmem state
                    wallet_replica.apply(ReplicaEvent::TransferPropagated(propagated.clone()))?;
                    Ok(ReplicaEvent::TransferPropagated(propagated))
                } else {
                    Err(Error::UnexpectedOutcome)
                }
            })
            .filter_map(|c: Result<ReplicaEvent>| match c {
                Ok(c) => Some(c),
                _ => None,
            })
            .collect()
    }

    // 5. Synch at Recipient Actor.
    fn synch(recipient: &mut TestActor) -> Result<()> {
        let replicas = &recipient.replica_group;
        let wallet = replicas.replicas[0]
            .wallets
            .get(&recipient.actor.id())
            .ok_or(Error::UnexpectedOutcome)?;
        let snapshot = wallet.wallet().ok_or(Error::UnexpectedOutcome)?;
        let transfers = recipient
            .actor
            .synch(
                snapshot.balance,
                snapshot.debit_version,
                snapshot.credit_ids,
            )?
            .ok_or(Error::UnexpectedOutcome)?;
        recipient
            .actor
            .apply(ActorEvent::TransfersSynched(transfers))
    }

    // ------------------------------------------------------------------------
    // ------------------------ Setup Helpers ---------------------------------
    // ------------------------------------------------------------------------

    /// gets an empty wallet and the genesis credit to be applied on it
    fn get_genesis(threshold: usize) -> Result<(TestWallet, CreditAgreementProof)> {
        let balance = u32::MAX as u64 * 1_000_000_000;
        let mut rng = rand::thread_rng();
        //let threshold = 0;
        let bls_secret_key = SecretKeySet::random(threshold, &mut rng);
        let peer_replicas = bls_secret_key.public_keys();
        let id = PublicKey::Bls(peer_replicas.public_key());
        let keypair = sn_data_types::Keypair::new_bls_share(
            0,
            bls_secret_key.secret_key_share(0),
            peer_replicas.clone(),
        );
        let owner = WalletOwner::Multi(peer_replicas.clone());
        let wallet = Wallet::new(owner);
        Ok((
            setup_wallet(0, 0, keypair, wallet)?,
            genesis::get_genesis(
                balance,
                id,
                peer_replicas,
                bls_secret_key.secret_key_share(0),
            )?,
        ))
    }

    fn get_network(
        group_count: u8,
        replica_count: u8,
        genesis: TestWallet,
        wallet_configs: HashMap<u8, u64>,
    ) -> (Vec<ReplicaGroup>, HashMap<u8, TestActor>) {
        let wallets: Vec<_> = wallet_configs
            .iter()
            .filter_map(|(index, balance)| setup_random_wallet(*balance, *index).ok())
            .collect();

        let group_keys = setup_replica_group_keys(group_count, replica_count);
        let mut wallets_clones = wallets.clone();
        let _ = wallets_clones.push(genesis.clone());
        let mut replica_groups = setup_replica_groups(group_keys, wallets_clones);

        let mut actors: HashMap<_, _> = wallets
            .iter()
            .map(|a| (a.replica_group, setup_actor(a.clone(), &mut replica_groups)))
            .filter_map(|(key, val)| {
                if let Ok(actor) = val {
                    Some((key, actor))
                } else {
                    None
                }
            })
            .collect();

        let next_key = match actors.keys().max() {
            Some(i) => i + 1,
            None => 0,
        };
        if let Ok(actor) = setup_actor(genesis, &mut replica_groups) {
            let _ = actors.insert(next_key, actor);
        }
        assert_eq!(
            wallets.len(),
            actors.len(),
            "All actor creations were not successful"
        );

        (replica_groups, actors)
    }

    fn find_group(index: u8, replica_groups: &mut Vec<ReplicaGroup>) -> Option<&mut ReplicaGroup> {
        for replica_group in replica_groups {
            if replica_group.index == index {
                return Some(replica_group);
            }
        }
        None
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }

    fn setup_random_wallet(balance: u64, replica_group: u8) -> Result<TestWallet> {
        let mut rng = rand::thread_rng();
        let keypair = Keypair::new_ed25519(&mut rng);
        let recipient = keypair.public_key();
        let owner = WalletOwner::Single(recipient);
        let mut wallet = Wallet::new(owner);
        setup_wallet(balance, replica_group, keypair, wallet)
    }

    fn setup_wallet(
        balance: u64,
        replica_group: u8,
        keypair: Keypair,
        wallet: Wallet,
    ) -> Result<TestWallet> {
        let mut wallet = wallet;
        if balance > 0 {
            let amount = Money::from_nano(balance);
            let sender = Dot::new(get_random_pk(), 0);
            let debit = Debit { id: sender, amount };
            let credit = Credit {
                id: debit.credit_id()?,
                recipient: wallet.id().public_key(),
                amount,
                msg: "".to_string(),
            };
            let _ = wallet.apply_credit(credit)?;
        }

        Ok(TestWallet {
            wallet,
            keypair: Arc::new(keypair),
            replica_group,
        })
    }

    fn setup_actor(
        wallet: TestWallet,
        replica_groups: &mut Vec<ReplicaGroup>,
    ) -> Result<TestActor> {
        let replica_group = find_group(wallet.replica_group, replica_groups)
            .ok_or(Error::MissingReplicaGroup)?
            .clone();

        let actor = Actor::from_snapshot(
            wallet.wallet,
            wallet.keypair,
            replica_group.id.clone(),
            Validator {},
        );

        Ok(TestActor {
            actor,
            replica_group,
        })
    }

    // Create n replica groups, with k replicas in each
    fn setup_replica_group_keys(
        group_count: u8,
        replica_count: u8,
    ) -> HashMap<u8, ReplicaGroupKeys> {
        let mut rng = rand::thread_rng();
        let mut groups = HashMap::new();
        for i in 0..group_count {
            let threshold = std::cmp::max(1, 2 * replica_count / 3) - 1;
            let bls_secret_key = SecretKeySet::random(threshold as usize, &mut rng);
            let peers = bls_secret_key.public_keys();
            let mut shares = vec![];
            for j in 0..replica_count {
                let share = bls_secret_key.secret_key_share(j as usize);
                shares.push((share, j as usize));
            }
            let _ = groups.insert(
                i,
                ReplicaGroupKeys {
                    index: i,
                    id: peers,
                    keys: shares,
                },
            );
        }
        groups
    }

    fn setup_replica_groups(
        group_keys: HashMap<u8, ReplicaGroupKeys>,
        wallets: Vec<TestWallet>,
    ) -> Vec<ReplicaGroup> {
        let mut replica_groups = vec![];
        for (i, group) in &group_keys {
            let group_wallets = wallets
                .clone()
                .into_iter()
                .filter(|c| c.replica_group == *i)
                .map(|c| (c.wallet.id().public_key(), c.wallet))
                .collect::<HashMap<PublicKey, Wallet>>();

            let mut replicas = vec![];
            for (secret_key, key_index) in &group.keys {
                let peer_replicas = group.id.clone();
                let wallets = group_wallets.clone();
                let mut wallet_replicas = hashmap![];
                for (key, wallet) in wallets.into_iter() {
                    let wallet_id = wallet.id();
                    let pending_proposals = Default::default();
                    let wallet_replica = WalletReplica::from_snapshot(
                        wallet_id.clone(),
                        secret_key.public_key_share(),
                        *key_index,
                        peer_replicas.clone(),
                        wallet.clone(),
                        pending_proposals,
                        None,
                    );
                    let _ = wallet_replicas.insert(wallet_id.public_key(), wallet_replica);
                }
                replicas.push(Replica {
                    id: secret_key.public_key_share(),
                    wallets: wallet_replicas,
                    signing: ReplicaSigning::new(
                        secret_key.clone(),
                        *key_index,
                        peer_replicas.clone(),
                    ),
                });
            }
            replica_groups.push(ReplicaGroup {
                index: *i,
                id: group.id.clone(),
                replicas,
            });
        }
        replica_groups
    }

    // ------------------------------------------------------------------------
    // ------------------------ Structs ---------------------------------------
    // ------------------------------------------------------------------------

    #[derive(Debug, Clone)]
    struct Validator {}

    impl ReplicaValidator for Validator {
        fn is_valid(&self, _replica_group: PublicKey) -> bool {
            true
        }
    }

    #[derive(Debug, Clone)]
    struct TestWallet {
        wallet: Wallet,
        keypair: Arc<Keypair>,
        replica_group: u8,
    }

    #[derive(Debug, Clone)]
    struct TestActor {
        actor: Actor<Validator>,
        replica_group: ReplicaGroup,
    }

    #[derive(Debug, Clone)]
    struct Replica {
        id: threshold_crypto::PublicKeyShare,
        wallets: HashMap<PublicKey, WalletReplica>,
        signing: ReplicaSigning,
    }

    #[derive(Debug, Clone)]
    struct ReplicaGroup {
        index: u8,
        id: PublicKeySet,
        replicas: Vec<Replica>,
    }

    #[derive(Debug, Clone)]
    struct ReplicaGroupKeys {
        index: u8,
        id: PublicKeySet,
        keys: Vec<(SecretKeyShare, usize)>,
    }
}
