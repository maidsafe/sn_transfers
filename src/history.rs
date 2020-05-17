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
            balance: Money::zero(),
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
        let include_index = index + 1;
        if self.incoming.len() > include_index {
            self.incoming.split_at(include_index).1.to_vec()
        } else {
            vec![]
        }
    }

    /// Query for new outgoing transfers since specified index.
    pub fn outgoing_since(&self, index: usize) -> Vec<Transfer> {
        let include_index = index + 1;
        if self.outgoing.len() > include_index {
            self.outgoing.split_at(include_index).1.to_vec()
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
