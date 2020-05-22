// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Identity;
use safe_nd::{Error, Money, Result, Transfer, TransferId};
use std::collections::HashSet;

/// History of transfers for an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History {
    id: Identity,
    balance: Money,
    incoming: Vec<Transfer>,
    outgoing: Vec<Transfer>,
    transfer_ids: HashSet<TransferId>,
}

impl History {
    /// Creates a new history, requires an incoming transfer.
    pub fn new(first: Transfer) -> Self {
        let mut transfer_ids = HashSet::new();
        let _ = transfer_ids.insert(first.id);
        Self {
            id: first.to,
            balance: first.amount,
            incoming: vec![first],
            outgoing: Default::default(),
            transfer_ids,
        }
    }

    /// Query for next version.
    pub fn next_version(&self) -> u64 {
        self.outgoing.len() as u64
    }

    /// Query for balance.
    pub fn balance(&self) -> Money {
        self.balance
    }

    /// Query for already stored transfer.
    pub fn contains(&self, id: &TransferId) -> bool {
        self.transfer_ids.contains(id)
    }

    /// Zero based indexing, first (outgoing) transfer will be nr 0
    /// (we could just as well just compare outgoing.len()..)
    pub fn is_sequential(&self, transfer: &Transfer) -> Result<bool> {
        let id = transfer.id;
        if id.actor != self.id {
            Err(Error::InvalidOperation)
        } else {
            match self.outgoing.last() {
                None => Ok(id.counter == 0), // if not outgoing transfers have been made, transfer counter must be 0
                Some(previous) => Ok(previous.id.counter + 1 == id.counter),
            }
        }
    }

    /// Query for new incoming transfers since specified index.
    /// NB: This is not guaranteed to give you all unknown to you,
    /// since there is no absolute order on the incoming!
    pub fn incoming_since(&self, index: usize) -> Vec<Transfer> {
        if self.incoming.len() > index {
            self.incoming.split_at(index).1.to_vec()
        } else {
            vec![]
        }
    }

    /// Query for new outgoing transfers since specified index.
    pub fn outgoing_since(&self, index: usize) -> Vec<Transfer> {
        if self.outgoing.len() > index {
            self.outgoing.split_at(index).1.to_vec()
        } else {
            vec![]
        }
    }

    /// Mutates state.
    pub fn append(&mut self, transfer: Transfer) {
        if self.id == transfer.id.actor {
            match self.balance.checked_sub(transfer.amount) {
                Some(amount) => self.balance = amount,
                None => panic!("overflow when subtracting!"),
            }
            let _ = self.transfer_ids.insert(transfer.id);
            self.outgoing.push(transfer);
        } else if self.id == transfer.to {
            match self.balance.checked_add(transfer.amount) {
                Some(amount) => self.balance = amount,
                None => panic!("overflow when adding!"),
            }
            let _ = self.transfer_ids.insert(transfer.id);
            self.incoming.push(transfer);
        } else {
            panic!("Transfer does not belong to this history")
        }
    }
}

mod test {
    use super::*;
    use crdts::Dot;
    use safe_nd::{PublicKey, XorName};
    use threshold_crypto::SecretKey;

    #[test]
    fn creates_with_ctor_state() {
        // Arrange
        let balance = Money::from_nano(10);
        let first_incoming = Transfer {
            id: Dot::new(get_random_pk(), 0),
            to: get_random_pk(),
            amount: balance,
        };

        // Act
        let history = History::new(first_incoming.clone());
        let incoming = history.incoming_since(0);
        let outgoing = history.outgoing_since(0);
        let first_outgoing = Transfer {
            id: Dot::new(first_incoming.to, 0),
            to: get_random_pk(),
            amount: balance,
        };
        let is_sequential = history.is_sequential(&first_outgoing);

        // Assert
        assert!(history.contains(&first_incoming.id));
        assert!(history.balance() == balance);
        assert!(incoming.len() == 1);
        assert!(incoming[0] == first_incoming);
        assert!(outgoing.len() == 0);
        assert!(history.next_version() == 0);
        assert!(is_sequential.is_ok() && is_sequential.unwrap());
    }

    #[test]
    fn appends_outgoing() {
        // Arrange
        let balance = Money::from_nano(10);
        let first_incoming = Transfer {
            id: Dot::new(get_random_pk(), 0),
            to: get_random_pk(),
            amount: balance,
        };
        let mut history = History::new(first_incoming.clone());
        let first_outgoing = Transfer {
            id: Dot::new(first_incoming.to, 0),
            to: get_random_pk(),
            amount: balance,
        };

        // Act
        history.append(first_outgoing.clone());
        let incoming = history.incoming_since(0);
        let outgoing = history.outgoing_since(0);
        let is_sequential = history.is_sequential(&Transfer {
            id: Dot::new(first_incoming.to, 1),
            to: get_random_pk(),
            amount: balance,
        });

        // Assert
        assert!(history.contains(&first_outgoing.id));
        assert!(history.balance() == Money::zero());
        assert!(outgoing.len() == 1);
        assert!(outgoing[0] == first_outgoing);
        assert!(incoming.len() == 1);
        assert!(incoming[0] == first_incoming);
        assert!(history.next_version() == 1);
        assert!(is_sequential.is_ok() && is_sequential.unwrap());
    }

    #[test]
    fn appends_incoming() {
        // Arrange
        let balance = Money::from_nano(10);
        let first_incoming = Transfer {
            id: Dot::new(get_random_pk(), 0),
            to: get_random_pk(),
            amount: balance,
        };
        let mut history = History::new(first_incoming.clone());
        let second_incoming = Transfer {
            id: Dot::new(get_random_pk(), 0),
            to: first_incoming.to,
            amount: balance,
        };

        // Act
        history.append(second_incoming.clone());
        let incoming = history.incoming_since(0);
        let outgoing = history.outgoing_since(0);
        let is_sequential = history.is_sequential(&Transfer {
            id: Dot::new(first_incoming.to, 0),
            to: get_random_pk(),
            amount: balance,
        });

        // Assert
        assert!(history.contains(&second_incoming.id));
        assert!(history.balance() == balance.checked_add(balance).unwrap());
        assert!(incoming.len() == 2);
        assert!(incoming[1] == second_incoming);
        assert!(outgoing.len() == 0);
        assert!(history.next_version() == 0);
        assert!(is_sequential.is_ok() && is_sequential.unwrap());
    }

    fn get_random_xor() -> XorName {
        XorName::from(get_random_pk())
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }
}
