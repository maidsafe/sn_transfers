// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crdts::Dot;
use safe_nd::{AccountId, DebitAgreementProof, Money, PublicKey, SignedTransfer, Transfer};
use std::collections::BTreeMap;
use threshold_crypto::{SecretKey, SecretKeySet};

/// Produces a genesis balance for a new network.
pub fn get_genesis(balance: u64, id: AccountId) -> DebitAgreementProof {
    let mut rng = rand::thread_rng();
    let index = 0;
    let threshold = 0;
    let bls_secret_key = SecretKeySet::random(threshold, &mut rng);
    let peer_replicas = bls_secret_key.public_keys();
    let secret_key = bls_secret_key.secret_key_share(index);

    let transfer = Transfer {
        amount: Money::from_nano(balance),
        id: Dot::new(get_random_pk(), 0),
        to: id,
    };

    let serialised_transfer = bincode::serialize(&transfer).unwrap();
    let transfer_sig_share = secret_key.sign(serialised_transfer);
    let mut transfer_sig_shares = BTreeMap::new();
    let _ = transfer_sig_shares.insert(0, transfer_sig_share);
    // Combine shares to produce the main signature.
    let actor_signature = safe_nd::Signature::Bls(
        peer_replicas
            .combine_signatures(&transfer_sig_shares)
            .expect("not enough shares"),
    );

    let signed_transfer = SignedTransfer {
        transfer,
        actor_signature,
    };

    let serialised_transfer = bincode::serialize(&signed_transfer).unwrap();
    let transfer_sig_share = secret_key.sign(serialised_transfer);
    let mut transfer_sig_shares = BTreeMap::new();
    let _ = transfer_sig_shares.insert(0, transfer_sig_share);
    // Combine shares to produce the main signature.
    let debiting_replicas_sig = safe_nd::Signature::Bls(
        peer_replicas
            .combine_signatures(&transfer_sig_shares)
            .expect("not enough shares"),
    );

    DebitAgreementProof {
        signed_transfer,
        debiting_replicas_sig,
        replica_key: peer_replicas,
    }
}

fn get_random_pk() -> PublicKey {
    PublicKey::from(SecretKey::random().public_key())
}
