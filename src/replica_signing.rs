// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Outcome, TernaryResult};
use sn_data_types::{DebitAgreementProof, Error, SignatureShare, SignedTransfer};
use threshold_crypto::{PublicKeySet, PublicKeyShare, SecretKeyShare};

/// The Replica is the part of an AT2 system
/// that forms validating groups, and signs
/// individual transfers between wallets.
/// Replicas validate requests to debit an wallet, and
/// apply operations that has a valid "debit agreement proof"
/// from the group, i.e. signatures from a quorum of its peers.
/// Replicas don't initiate transfers or drive the algo - only Actors do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaSigning {
    /// The public key share of this Replica.
    id: PublicKeyShare,
    /// Secret key share.
    secret_key: SecretKeyShare,
    /// The index of this Replica key share, in the group set.
    key_index: usize,
    /// The PK set of our peer Replicas.
    peer_replicas: PublicKeySet,
    // /// PK sets of other known groups of Replicas.
    // other_groups: HashSet<PublicKeySet>,
}

impl ReplicaSigning {
    /// A new instance
    pub fn new(
        secret_key: SecretKeyShare,
        key_index: usize,
        peer_replicas: PublicKeySet,
        //other_groups: HashSet<PublicKeySet>,
    ) -> Self {
        let id = secret_key.public_key_share();
        Self {
            secret_key,
            id,
            key_index,
            peer_replicas,
            //other_groups,
        }
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Queries ----------------------------------
    /// -----------------------------------------------------------------

    /// Get the replica's PK set
    pub fn replicas_pk_set(&self) -> PublicKeySet {
        self.peer_replicas.clone()
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Cmds -------------------------------------
    /// -----------------------------------------------------------------

    ///
    pub fn sign_validated_transfer(&self, transfer: &SignedTransfer) -> Outcome<SignatureShare> {
        match bincode::serialize(transfer) {
            Err(_) => Err(Error::NetworkOther("Could not serialise transfer".into())),
            Ok(data) => Outcome::success(SignatureShare {
                index: self.key_index,
                share: self.secret_key.sign(data),
            }),
        }
    }

    /// Replicas of the credited wallet, sign the debit proof
    /// for the Actor to aggregate and verify locally.
    /// An alternative to this is to have the Actor know (and trust) all other Replica groups.
    pub fn sign_proof(&self, debit_proof: &DebitAgreementProof) -> Outcome<SignatureShare> {
        match bincode::serialize(debit_proof) {
            Err(_) => Err(Error::NetworkOther("Could not serialise proof".into())),
            Ok(data) => Outcome::success(SignatureShare {
                index: self.key_index,
                share: self.secret_key.sign(data),
            }),
        }
    }
}
