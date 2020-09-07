// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crdts::Dot;
use sn_data_types::{
    AccountId, DebitAgreementProof, Error, Money, PublicKey, Result, SignedTransfer, Transfer,
};
use std::collections::BTreeMap;
use threshold_crypto::{SecretKey, SecretKeySet};

/// Produces a genesis balance for a new network.
pub fn get_genesis(balance: u64, id: AccountId) -> Result<DebitAgreementProof> {
    let index = 0;
    let threshold = 0;
    // Nothing comes before genesis, it is a paradox
    // that it comes from somewhere. In other words, it is
    // signed over from a "ghost", the keys generated are "ghost" keys,
    // they come from nothing and can't be verified.
    // They are unimportant and will be thrown away,
    // thus the source of random is also unimportant.
    let mut rng = rand::thread_rng();
    let bls_secret_key = SecretKeySet::random(threshold, &mut rng);
    let peer_replicas = bls_secret_key.public_keys();
    let secret_key = bls_secret_key.secret_key_share(index);

    let transfer = Transfer {
        amount: Money::from_nano(balance),
        id: Dot::new(get_random_pk(), 0),
        to: id,
    };

    let serialised_transfer =
        bincode::serialize(&transfer).map_err(|e| Error::NetworkOther(e.to_string()))?;
    let transfer_sig_share = secret_key.sign(serialised_transfer);
    let mut transfer_sig_shares = BTreeMap::new();
    let _ = transfer_sig_shares.insert(0, transfer_sig_share);
    // Combine shares to produce the main signature.
    let actor_signature = sn_data_types::Signature::Bls(
        peer_replicas
            .combine_signatures(&transfer_sig_shares)
            .map_err(|e| Error::NetworkOther(e.to_string()))?,
    );

    let signed_transfer = SignedTransfer {
        transfer,
        actor_signature,
    };

    let serialised_transfer =
        bincode::serialize(&signed_transfer).map_err(|e| Error::NetworkOther(e.to_string()))?;
    let transfer_sig_share = secret_key.sign(serialised_transfer);
    let mut transfer_sig_shares = BTreeMap::new();
    let _ = transfer_sig_shares.insert(0, transfer_sig_share);
    // Combine shares to produce the main signature.
    let debiting_replicas_sig = sn_data_types::Signature::Bls(
        peer_replicas
            .combine_signatures(&transfer_sig_shares)
            .map_err(|e| Error::NetworkOther(e.to_string()))?,
    );

    Ok(DebitAgreementProof {
        signed_transfer,
        debiting_replicas_sig,
        replica_key: peer_replicas,
    })
}

fn get_random_pk() -> PublicKey {
    PublicKey::from(SecretKey::random().public_key())
}
