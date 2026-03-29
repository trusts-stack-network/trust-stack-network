use serde::{Deserialize, Serialize};

use crate::crypto::Address;

/// An account in the blockchain state.
///
/// Uses an account-based model (like Ethereum) rather than UTXO (like Bitcoin).
/// Each account has a balance and a nonce to prevent replay attacks.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    /// The account's address
    pub address: Address,
    /// Current balance in smallest units
    pub balance: u64,
    /// Transaction counter (incremented with each outgoing tx)
    pub nonce: u64,
}

impl Account {
    /// Create a new account with zero balance.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            balance: 0,
            nonce: 0,
        }
    }

    /// Create a new account with an initial balance (for genesis state).
    pub fn with_balance(address: Address, balance: u64) -> Self {
        Self {
            address,
            balance,
            nonce: 0,
        }
    }

    /// Check if the account can afford a transaction.
    pub fn can_afford(&self, amount: u64, fee: u64) -> bool {
        self.balance >= amount.saturating_add(fee)
    }

    /// Debit the account (subtract balance, increment nonce).
    ///
    /// Returns an error if insufficient balance.
    pub fn debit(&mut self, amount: u64, fee: u64) -> Result<(), AccountError> {
        let total = amount.saturating_add(fee);
        if self.balance < total {
            return Err(AccountError::InsufficientBalance {
                required: total,
                available: self.balance,
            });
        }
        self.balance -= total;
        self.nonce += 1;
        Ok(())
    }

    /// Credit the account (add balance).
    pub fn credit(&mut self, amount: u64) {
        self.balance = self.balance.saturating_add(amount);
    }

    /// Check if a transaction nonce is valid (must equal current nonce).
    pub fn is_valid_nonce(&self, tx_nonce: u64) -> bool {
        tx_nonce == self.nonce
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u64, available: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address() -> Address {
        Address::from_bytes([1u8; 20])
    }

    #[test]
    fn test_new_account() {
        let addr = test_address();
        let account = Account::new(addr);

        assert_eq!(account.balance, 0);
        assert_eq!(account.nonce, 0);
    }

    #[test]
    fn test_account_with_balance() {
        let addr = test_address();
        let account = Account::with_balance(addr, 1000);

        assert_eq!(account.balance, 1000);
        assert_eq!(account.nonce, 0);
    }

    #[test]
    fn test_can_afford() {
        let addr = test_address();
        let account = Account::with_balance(addr, 100);

        assert!(account.can_afford(50, 1));
        assert!(account.can_afford(99, 1));
        assert!(!account.can_afford(100, 1));
        assert!(account.can_afford(100, 0));
    }

    #[test]
    fn test_debit() {
        let addr = test_address();
        let mut account = Account::with_balance(addr, 100);

        account.debit(50, 1).unwrap();

        assert_eq!(account.balance, 49);
        assert_eq!(account.nonce, 1);
    }

    #[test]
    fn test_debit_insufficient_balance() {
        let addr = test_address();
        let mut account = Account::with_balance(addr, 100);

        let result = account.debit(100, 1);

        assert!(result.is_err());
        assert_eq!(account.balance, 100); // Unchanged
        assert_eq!(account.nonce, 0); // Unchanged
    }

    #[test]
    fn test_credit() {
        let addr = test_address();
        let mut account = Account::new(addr);

        account.credit(100);

        assert_eq!(account.balance, 100);
    }

    #[test]
    fn test_nonce_validation() {
        let addr = test_address();
        let mut account = Account::new(addr);

        assert!(account.is_valid_nonce(0));
        assert!(!account.is_valid_nonce(1));

        account.debit(0, 0).unwrap(); // Increment nonce

        assert!(!account.is_valid_nonce(0));
        assert!(account.is_valid_nonce(1));
    }

    #[test]
    fn test_serialization() {
        let addr = test_address();
        let account = Account::with_balance(addr, 1000);

        let json = serde_json::to_string(&account).unwrap();
        let restored: Account = serde_json::from_str(&json).unwrap();

        assert_eq!(account, restored);
    }
}
