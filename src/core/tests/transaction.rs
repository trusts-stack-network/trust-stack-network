use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Transaction, TransactionType, Address, Signature};

    #[test]
    fn test_validate_transaction_valid() {
        let tx = Transaction {
            id: TxId::default(),
            type_: TransactionType::Transfer,
            sender: Address::default(),
            recipient: Address::default(),
            amount: 100,
            fee: 1,
            data: vec![],
            signature: Signature::default(),
        };

        let state = State::new();

        assert!(validate_transaction(&tx, &state).is_ok());
    }

    #[test]
    fn test_validate_transaction_invalid_type() {
        let tx = Transaction {
            id: TxId::default(),
            type_: TransactionType::Unknown,
            sender: Address::default(),
            recipient: Address::default(),
            amount: 100,
            fee: 1,
            data: vec![],
            signature: Signature::default(),
        };

        let state = State::new();

        assert_eq!(validate_transaction(&tx, &state).unwrap_err(), TransactionValidationError::InvalidType);
    }

    #[test]
    fn test_validate_transaction_insufficient_funds() {
        let tx = Transaction {
            id: TxId::default(),
            type_: TransactionType::Transfer,
            sender: Address::default(),
            recipient: Address::default(),
            amount: 100,
            fee: 1,
            data: vec![],
            signature: Signature::default(),
        };

        let state = State::new();

        assert_eq!(validate_transaction(&tx, &state).unwrap_err(), TransactionValidationError::InsufficientFunds);
    }

    #[test]
    fn test_validate_transaction_double_spend() {
        let tx = Transaction {
            id: TxId::default(),
            type_: TransactionType::Transfer,
            sender: Address::default(),
            recipient: Address::default(),
            amount: 100,
            fee: 1,
            data: vec![],
            signature: Signature::default(),
        };

        let state = State::new();

        assert_eq!(validate_transaction(&tx, &state).unwrap_err(), TransactionValidationError::DoubleSpend);
    }

    #[test]
    fn test_validate_transaction_invalid_signature() {
        let tx = Transaction {
            id: TxId::default(),
            type_: TransactionType::Transfer,
            sender: Address::default(),
            recipient: Address::default(),
            amount: 100,
            fee: 1,
            data: vec![],
            signature: Signature::default(),
        };

        let state = State::new();

        assert_eq!(validate_transaction(&tx, &state).unwrap_err(), TransactionValidationError::InvalidSignature);
    }
}