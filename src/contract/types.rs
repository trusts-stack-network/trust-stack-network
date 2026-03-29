//! Smart contract types for TSN blockchain.

use serde::{Deserialize, Serialize};

/// A deployed smart contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    /// Deterministic address: hash(deployer_pk_hash || nonce || code_hash)
    pub address: [u8; 32],
    /// Hash of the bytecode
    pub code_hash: [u8; 32],
    /// The executable bytecode
    pub bytecode: Vec<u8>,
    /// Creator's public key hash
    pub creator: [u8; 32],
    /// Block height at deployment
    pub created_at_height: u64,
    /// Current storage root (Poseidon2 SMT root)
    pub storage_root: [u8; 32],
    /// Contract balance (in base units)
    pub balance: u64,
}

/// Transaction to deploy a new contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDeployTransaction {
    /// Bytecode to deploy
    pub bytecode: Vec<u8>,
    /// Constructor arguments
    pub constructor_args: Vec<u64>,
    /// Gas limit for deployment
    pub gas_limit: u64,
    /// Fee paid for deployment
    pub fee: u64,
    /// Deployer's public key hash
    pub deployer_pk_hash: [u8; 32],
    /// Deployer nonce (for deterministic address)
    pub nonce: u64,
    /// ML-DSA-65 signature over the transaction
    pub signature: Vec<u8>,
    /// Deployer's public key
    pub public_key: Vec<u8>,
}

/// Transaction to call a deployed contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCallTransaction {
    /// Target contract address
    pub contract_address: [u8; 32],
    /// Function selector (first 4 bytes of function name hash)
    pub function_selector: [u8; 4],
    /// Call arguments
    pub args: Vec<u64>,
    /// Gas limit
    pub gas_limit: u64,
    /// Fee paid
    pub fee: u64,
    /// Value to transfer to contract (optional)
    pub value: u64,
    /// Caller's public key hash
    pub caller_pk_hash: [u8; 32],
    /// Caller nonce
    pub nonce: u64,
    /// ML-DSA-65 signature
    pub signature: Vec<u8>,
    /// Caller's public key
    pub public_key: Vec<u8>,
}

/// Event emitted by a contract during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractEventLog {
    /// Contract that emitted the event
    pub contract_address: [u8; 32],
    /// Block height
    pub height: u64,
    /// Transaction index in the block
    pub tx_index: u32,
    /// Event topic
    pub topic: u64,
    /// Event data
    pub data: Vec<u64>,
}

/// Execution receipt for a contract transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractReceipt {
    /// Transaction hash
    pub tx_hash: [u8; 32],
    /// Whether execution succeeded
    pub success: bool,
    /// Gas used
    pub gas_used: u64,
    /// Return value (if any)
    pub return_value: Option<u64>,
    /// Events emitted
    pub events: Vec<ContractEventLog>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// New contract address (for deploy transactions)
    pub contract_address: Option<[u8; 32]>,
}

impl ContractDeployTransaction {
    /// Compute the hash of this transaction (for signing and indexing).
    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"tsn_contract_deploy_v1");
        hasher.update(&self.deployer_pk_hash);
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.gas_limit.to_le_bytes());
        hasher.update(&self.fee.to_le_bytes());
        // Hash the bytecode
        let mut code_hasher = Sha256::new();
        code_hasher.update(&self.bytecode);
        hasher.update(code_hasher.finalize());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Compute the deterministic contract address.
    pub fn contract_address(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"tsn_contract_addr_v1");
        hasher.update(&self.deployer_pk_hash);
        hasher.update(&self.nonce.to_le_bytes());
        let mut code_hasher = Sha256::new();
        code_hasher.update(&self.bytecode);
        hasher.update(code_hasher.finalize());
        let result = hasher.finalize();
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&result);
        addr
    }

    /// Compute the code hash.
    pub fn code_hash(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&self.bytecode);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

impl ContractCallTransaction {
    /// Compute the hash of this transaction.
    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"tsn_contract_call_v1");
        hasher.update(&self.contract_address);
        hasher.update(&self.function_selector);
        hasher.update(&self.caller_pk_hash);
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.gas_limit.to_le_bytes());
        hasher.update(&self.fee.to_le_bytes());
        hasher.update(&self.value.to_le_bytes());
        for arg in &self.args {
            hasher.update(&arg.to_le_bytes());
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// Compute a function selector from a function name (first 4 bytes of SHA256).
pub fn function_selector(name: &str) -> [u8; 4] {
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(name.as_bytes());
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&hash[..4]);
    sel
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deploy_address_deterministic() {
        let tx = ContractDeployTransaction {
            bytecode: vec![0x01, 0x42],
            constructor_args: vec![],
            gas_limit: 100_000,
            fee: 1000,
            deployer_pk_hash: [1u8; 32],
            nonce: 0,
            signature: vec![],
            public_key: vec![],
        };
        let addr1 = tx.contract_address();
        let addr2 = tx.contract_address();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_function_selector() {
        let sel = function_selector("transfer");
        assert_eq!(sel.len(), 4);
        // Different functions produce different selectors
        assert_ne!(function_selector("transfer"), function_selector("balance_of"));
    }

    #[test]
    fn test_tx_hash() {
        let tx = ContractCallTransaction {
            contract_address: [2u8; 32],
            function_selector: function_selector("transfer"),
            args: vec![100, 42],
            gas_limit: 50_000,
            fee: 500,
            value: 0,
            caller_pk_hash: [1u8; 32],
            nonce: 1,
            signature: vec![],
            public_key: vec![],
        };
        let h = tx.hash();
        assert_ne!(h, [0u8; 32]);
    }
}
