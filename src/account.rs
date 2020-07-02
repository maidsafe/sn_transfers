// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use safe_nd::{AccountId, Error, Money, Result, Transfer, TransferId};
use std::collections::HashSet;
/// The balance and history of transfers for an account id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    id: AccountId,
    balance: Money,
    credits: Vec<Transfer>,
    debits: Vec<Transfer>,
    transfer_ids: HashSet<TransferId>,
}

impl Account {
    /// Creates a new account out of a credit.
    pub fn new(id: AccountId) -> Self {
        Self {
            id,
            balance: Money::zero(),
            credits: vec![],
            debits: Default::default(),
            transfer_ids: Default::default(),
        }
    }

    /// Returns the ID(PublicKey) for the Account
    pub fn id(&self) -> AccountId {
        self.id
    }

    /// Query for next version.
    pub fn next_debit(&self) -> u64 {
        self.debits.len() as u64
    }

    /// Query for balance.
    pub fn balance(&self) -> Money {
        self.balance
    }

    /// Query for already stored transfer.
    pub fn contains(&self, id: &TransferId) -> bool {
        self.transfer_ids.contains(id)
    }

    /// Zero based indexing, first debit will be nr 0
    /// (we could just as well just compare debits.len()..)
    pub fn is_sequential(&self, transfer: &Transfer) -> Result<bool> {
        let id = transfer.id;
        if id.actor != self.id {
            Err(Error::from("Account operation is non-sequential"))
        } else {
            match self.debits.last() {
                None => Ok(id.counter == 0), // if no debits have been made, transfer counter must be 0
                Some(previous) => Ok(previous.id.counter + 1 == id.counter),
            }
        }
    }

    /// Query for new credits since specified index.
    /// NB: This is not guaranteed to give you all unknown to you,
    /// since there is no absolute order on the credits!
    pub fn credits_since(&self, index: usize) -> Vec<Transfer> {
        if self.credits.len() > index {
            self.credits.split_at(index).1.to_vec()
        } else {
            vec![]
        }
    }

    /// Query for new debit since specified index.
    pub fn debits_since(&self, index: usize) -> Vec<Transfer> {
        if self.debits.len() > index {
            self.debits.split_at(index).1.to_vec()
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
            self.debits.push(transfer);
        } else if self.id == transfer.to {
            match self.balance.checked_add(transfer.amount) {
                Some(amount) => self.balance = amount,
                None => panic!("overflow when adding!"),
            }
            let _ = self.transfer_ids.insert(transfer.id);
            self.credits.push(transfer);
        } else {
            panic!(
                "Transfer to append does not belong to this account({:?}): transfer: {:?}",
                self.id, transfer
            )
        }
    }

    /// Test-helper API to simulate Client Transfers.
    #[cfg(feature = "simulated-payouts")]
    pub fn simulated_credit(&mut self, transfer: Transfer) {
        if self.id == transfer.to {
            match self.balance.checked_add(transfer.amount) {
                Some(amount) => self.balance = amount,
                None => panic!("overflow when adding!"),
            }
            let _ = self.transfer_ids.insert(transfer.id);
            self.credits.push(transfer);
        } else {
            panic!(
                "Credit transfer does not belong to this account({:?}): transfer: {:?}",
                self.id, transfer
            )
        }
    }

    /// Test-helper API to simulate section payments.
    #[cfg(feature = "simulated-payouts")]
    pub fn simulated_debit(&mut self, transfer: Transfer) {
        if self.id == transfer.id.actor {
            match self.balance.checked_sub(transfer.amount) {
                Some(amount) => self.balance = amount,
                None => panic!("overflow when subtracting!"),
            }
            let _ = self.transfer_ids.insert(transfer.id);
            self.debits.push(transfer);
        } else {
            panic!(
                "Debit transfer does not belong to this account({:?}): transfer: {:?}",
                self.id, transfer
            )
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crdts::Dot;
    use safe_nd::{PublicKey, XorName};
    use threshold_crypto::SecretKey;

    #[test]
    fn appends_credits() {
        // Arrange
        let balance = Money::from_nano(10);
        let first_credit = Transfer {
            id: Dot::new(get_random_pk(), 0),
            to: get_random_pk(),
            amount: balance,
        };
        let mut account = Account::new(first_credit.to);
        account.append(first_credit.clone());
        let second_credit = Transfer {
            id: Dot::new(get_random_pk(), 0),
            to: first_credit.to,
            amount: balance,
        };

        // Act
        account.append(second_credit.clone());
        let credits = account.credits_since(0);
        let debits = account.debits_since(0);
        let is_sequential = account.is_sequential(&Transfer {
            id: Dot::new(first_credit.to, 0),
            to: get_random_pk(),
            amount: balance,
        });

        // Assert
        assert!(account.contains(&second_credit.id));
        assert!(account.balance() == balance.checked_add(balance).unwrap());
        assert!(credits.len() == 2);
        assert!(credits[1] == second_credit);
        assert!(debits.len() == 0);
        assert!(account.next_debit() == 0);
        assert!(is_sequential.is_ok() && is_sequential.unwrap());
    }

    #[test]
    fn appends_debits() {
        // Arrange
        let balance = Money::from_nano(10);
        let first_credit = Transfer {
            id: Dot::new(get_random_pk(), 0),
            to: get_random_pk(),
            amount: balance,
        };
        let mut account = Account::new(first_credit.to);
        account.append(first_credit.clone());
        let first_debit = Transfer {
            id: Dot::new(first_credit.to, 0),
            to: get_random_pk(),
            amount: balance,
        };

        // Act
        account.append(first_debit.clone());
        let credits = account.credits_since(0);
        let debits = account.debits_since(0);
        let is_sequential = account.is_sequential(&Transfer {
            id: Dot::new(first_credit.to, 1),
            to: get_random_pk(),
            amount: balance,
        });

        // Assert
        assert!(account.contains(&first_debit.id));
        assert!(account.balance() == Money::zero());
        assert!(debits.len() == 1);
        assert!(debits[0] == first_debit);
        assert!(credits.len() == 1);
        assert!(credits[0] == first_credit);
        assert!(account.next_debit() == 1);
        assert!(is_sequential.is_ok() && is_sequential.unwrap());
    }

    fn get_random_xor() -> XorName {
        XorName::from(get_random_pk())
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }
}
