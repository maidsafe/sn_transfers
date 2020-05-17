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
mod history;
mod replica;

pub use self::{
    actor::Actor as TransferActor, history::History as TransferHistory,
    replica::Replica as TransferReplica, ReplicaEvent as TransferReplicaEvent,
};

use safe_nd::{
    ProofOfAgreement, PublicKey, RegisterTransfer, Transfer, TransferRegistered, TransferValidated,
    ValidateTransfer,
};
use serde::{Deserialize, Serialize};

///
pub type Identity = PublicKey;

/// Events raised by the Replica.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub enum ReplicaEvent {
    /// The event raised when
    /// ValidateTransfer cmd has been successful.
    TransferValidated(TransferValidated),
    /// The event raised when
    /// RegisterTransfer cmd has been successful.
    TransferRegistered(TransferRegistered),
    /// The event raised when
    /// PropagateTransfer cmd has been successful.
    TransferPropagated(TransferPropagated),
}

/// The Replica event raised when
/// PropagateTransfer cmd has been successful.
/// Not part of the public contract, hence only used in this module.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub struct TransferPropagated {
    /// The transfer proof.
    pub proof: ProofOfAgreement,
}

/// Events raised by the Actor.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
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
    /// unknown transfers on querying Replicas.
    RemoteTransfersSynced(RemoteTransfersSynced),
}

/// This event is raised by the Actor after having
/// successfully created a transfer cmd to send to the
/// Replicas for validation.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub struct TransferInitiated {
    cmd: ValidateTransfer,
}

/// Raised when a Replica responds with
/// a successful validation of a transfer.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub struct TransferValidationReceived {
    /// The event raised by a Replica.
    validation: TransferValidated,
    /// Added when quorum of validations
    /// have been received from Replicas.
    proof: Option<ProofOfAgreement>,
}

/// Raised when the Actor has accumulated a
/// quorum of validations, and produced a RegisterTransfer cmd
/// for sending to Replicas.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub struct TransferRegistrationSent {
    cmd: RegisterTransfer,
}

/// Raised when the Actor has received
/// unknown transfers on querying Replicas.
#[derive(Clone, Hash, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub struct RemoteTransfersSynced {
    /// credits
    incoming: Vec<ProofOfAgreement>,
    /// debits
    outgoing: Vec<ProofOfAgreement>,
}
