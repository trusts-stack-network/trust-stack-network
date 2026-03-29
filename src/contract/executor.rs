//! Contract executor — deploys and calls contracts using the zkVM.

use std::collections::HashMap;
use blake2::{Blake2s256, Digest};
use crate::vm::{Vm, ExecContext, ExecResult, CONTRACT_MAX_SIZE};
use super::types::*;
use super::storage::{ContractRegistry, ContractStorage, EventStore};

/// The contract execution engine.
pub struct ContractExecutor {
    pub registry: ContractRegistry,
    pub storage: ContractStorage,
    pub events: EventStore,
}

/// Errors from the contract executor.
#[derive(Debug)]
pub enum ContractError {
    BytecodeTooLarge(usize),
    ContractAlreadyExists([u8; 32]),
    ContractNotFound([u8; 32]),
    ExecutionFailed(String),
    StorageError(String),
    InvalidSignature,
    InsufficientFee,
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BytecodeTooLarge(s) => write!(f, "bytecode too large: {} bytes (max {})", s, CONTRACT_MAX_SIZE),
            Self::ContractAlreadyExists(a) => write!(f, "contract already exists: {:?}", &a[..8]),
            Self::ContractNotFound(a) => write!(f, "contract not found: {:?}", &a[..8]),
            Self::ExecutionFailed(e) => write!(f, "execution failed: {}", e),
            Self::StorageError(e) => write!(f, "storage error: {}", e),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::InsufficientFee => write!(f, "insufficient fee"),
        }
    }
}

/// Compute a deterministic storage root from key-value writes.
/// Uses Blake2s256 over sorted (key, value) pairs for a unique commitment.
fn compute_storage_root(storage_writes: &HashMap<u64, u64>) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(b"TSN_StorageRoot");
    let mut sorted: Vec<_> = storage_writes.iter().collect();
    sorted.sort_by_key(|(&k, _)| k);
    for (&key, &value) in &sorted {
        hasher.update(key.to_le_bytes());
        hasher.update(value.to_le_bytes());
    }
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

impl ContractExecutor {
    /// Create a new executor backed by a Sled database.
    pub fn new(db: &sled::Db) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            registry: ContractRegistry::new(db)?,
            storage: ContractStorage::new(db)?,
            events: EventStore::new(db)?,
        })
    }

    /// Deploy a new contract.
    pub fn deploy(
        &self,
        tx: &ContractDeployTransaction,
        block_height: u64,
        block_timestamp: u64,
    ) -> Result<ContractReceipt, ContractError> {
        // Validate bytecode size
        if tx.bytecode.len() > CONTRACT_MAX_SIZE {
            return Err(ContractError::BytecodeTooLarge(tx.bytecode.len()));
        }

        let contract_addr = tx.contract_address();

        // Check if contract already exists
        if self.registry.exists(&contract_addr).map_err(|e| ContractError::StorageError(e.to_string()))? {
            return Err(ContractError::ContractAlreadyExists(contract_addr));
        }

        // Execute constructor (run bytecode with constructor_args on the stack)
        let ctx = ExecContext {
            caller: tx.deployer_pk_hash,
            self_addr: contract_addr,
            block_height,
            block_timestamp,
            tx_fee: tx.fee,
            call_value: 0,
            call_depth: 0,
        };

        let mut vm = Vm::new(tx.gas_limit, ctx, HashMap::new());

        // Build constructor bytecode: push args, then run the actual bytecode
        let mut constructor_bc = Vec::new();
        for &arg in tx.constructor_args.iter().rev() {
            constructor_bc.push(crate::vm::OpCode::Push as u8);
            constructor_bc.extend_from_slice(&arg.to_le_bytes());
        }
        constructor_bc.extend_from_slice(&tx.bytecode);

        let result = vm.execute(&constructor_bc);
        let tx_hash = tx.hash();

        if !result.success {
            return Ok(ContractReceipt {
                tx_hash,
                success: false,
                gas_used: result.gas_used,
                return_value: None,
                events: Vec::new(),
                error: result.error.map(|e| e.to_string()),
                contract_address: None,
            });
        }

        // Apply storage writes
        self.storage.apply_writes(&contract_addr, &result.storage_writes)
            .map_err(|e| ContractError::StorageError(e.to_string()))?;

        // Store contract
        let contract = Contract {
            address: contract_addr,
            code_hash: tx.code_hash(),
            bytecode: tx.bytecode.clone(),
            creator: tx.deployer_pk_hash,
            created_at_height: block_height,
            storage_root: compute_storage_root(&result.storage_writes),
            balance: 0,
        };
        self.registry.put(&contract)
            .map_err(|e| ContractError::StorageError(e.to_string()))?;

        // Store events
        let event_logs: Vec<ContractEventLog> = result.events.iter().map(|ev| {
            ContractEventLog {
                contract_address: contract_addr,
                height: block_height,
                tx_index: 0,
                topic: ev.topic,
                data: ev.data.clone(),
            }
        }).collect();
        for ev in &event_logs {
            let _ = self.events.put(ev);
        }

        Ok(ContractReceipt {
            tx_hash,
            success: true,
            gas_used: result.gas_used,
            return_value: result.return_value,
            events: event_logs,
            error: None,
            contract_address: Some(contract_addr),
        })
    }

    /// Call an existing contract.
    pub fn call(
        &self,
        tx: &ContractCallTransaction,
        block_height: u64,
        block_timestamp: u64,
    ) -> Result<ContractReceipt, ContractError> {
        // Load contract
        let contract = self.registry.get(&tx.contract_address)
            .map_err(|e| ContractError::StorageError(e.to_string()))?
            .ok_or(ContractError::ContractNotFound(tx.contract_address))?;

        // Load storage snapshot
        let storage_snapshot = self.storage.load_snapshot(&tx.contract_address)
            .map_err(|e| ContractError::StorageError(e.to_string()))?;

        let ctx = ExecContext {
            caller: tx.caller_pk_hash,
            self_addr: tx.contract_address,
            block_height,
            block_timestamp,
            tx_fee: tx.fee,
            call_value: tx.value,
            call_depth: 0,
        };

        let mut vm = Vm::new(tx.gas_limit, ctx, storage_snapshot);

        // Build call bytecode: push function_selector + args, then run contract code
        let mut call_bc = Vec::new();
        // Push args in reverse order (so first arg is on top)
        for &arg in tx.args.iter().rev() {
            call_bc.push(crate::vm::OpCode::Push as u8);
            call_bc.extend_from_slice(&arg.to_le_bytes());
        }
        // Push function selector as u32
        let sel = u32::from_le_bytes(tx.function_selector);
        call_bc.push(crate::vm::OpCode::Push as u8);
        call_bc.extend_from_slice(&(sel as u64).to_le_bytes());
        // Append contract bytecode
        call_bc.extend_from_slice(&contract.bytecode);

        let result = vm.execute(&call_bc);
        let tx_hash = tx.hash();

        if !result.success {
            return Ok(ContractReceipt {
                tx_hash,
                success: false,
                gas_used: result.gas_used,
                return_value: None,
                events: Vec::new(),
                error: result.error.map(|e| e.to_string()),
                contract_address: None,
            });
        }

        // Apply storage writes
        self.storage.apply_writes(&tx.contract_address, &result.storage_writes)
            .map_err(|e| ContractError::StorageError(e.to_string()))?;

        // Recompute storage root from full snapshot + new writes
        let updated_snapshot = self.storage.load_snapshot(&tx.contract_address)
            .map_err(|e| ContractError::StorageError(e.to_string()))?;
        let new_root = compute_storage_root(&updated_snapshot);

        // Update contract state (root + balance)
        let new_balance = contract.balance + tx.value;
        self.registry.update_state(&tx.contract_address, new_root, new_balance)
            .map_err(|e| ContractError::StorageError(e.to_string()))?;

        // Store events
        let event_logs: Vec<ContractEventLog> = result.events.iter().map(|ev| {
            ContractEventLog {
                contract_address: tx.contract_address,
                height: block_height,
                tx_index: 0,
                topic: ev.topic,
                data: ev.data.clone(),
            }
        }).collect();
        for ev in &event_logs {
            let _ = self.events.put(ev);
        }

        // Process transfers: deduct from contract balance
        for transfer in &result.transfers {
            let current = self.registry.get(&tx.contract_address)
                .map_err(|e| ContractError::StorageError(e.to_string()))?
                .ok_or(ContractError::ContractNotFound(tx.contract_address))?;

            if current.balance < transfer.amount {
                return Err(ContractError::ExecutionFailed(format!(
                    "insufficient contract balance for transfer: {} < {}",
                    current.balance, transfer.amount
                )));
            }

            // Deduct from contract balance (recipient crediting happens
            // at the blockchain level when the block is applied to state)
            self.registry.update_state(
                &tx.contract_address,
                current.storage_root,
                current.balance - transfer.amount,
            ).map_err(|e| ContractError::StorageError(e.to_string()))?;
        }

        Ok(ContractReceipt {
            tx_hash,
            success: true,
            gas_used: result.gas_used,
            return_value: result.return_value,
            events: event_logs,
            error: None,
            contract_address: None,
        })
    }

    /// Read-only query (no state changes, no fee).
    pub fn query(
        &self,
        contract_addr: &[u8; 32],
        function_selector: [u8; 4],
        args: &[u64],
        block_height: u64,
        block_timestamp: u64,
    ) -> Result<ExecResult, ContractError> {
        let contract = self.registry.get(contract_addr)
            .map_err(|e| ContractError::StorageError(e.to_string()))?
            .ok_or(ContractError::ContractNotFound(*contract_addr))?;

        let storage_snapshot = self.storage.load_snapshot(contract_addr)
            .map_err(|e| ContractError::StorageError(e.to_string()))?;

        let ctx = ExecContext {
            caller: [0u8; 32],
            self_addr: *contract_addr,
            block_height,
            block_timestamp,
            tx_fee: 0,
            call_value: 0,
            call_depth: 0,
        };

        // Use generous gas for queries (not deducted)
        let mut vm = Vm::new(10_000_000, ctx, storage_snapshot);

        let mut query_bc = Vec::new();
        for &arg in args.iter().rev() {
            query_bc.push(crate::vm::OpCode::Push as u8);
            query_bc.extend_from_slice(&arg.to_le_bytes());
        }
        let sel = u32::from_le_bytes(function_selector);
        query_bc.push(crate::vm::OpCode::Push as u8);
        query_bc.extend_from_slice(&(sel as u64).to_le_bytes());
        query_bc.extend_from_slice(&contract.bytecode);

        Ok(vm.execute(&query_bc))
    }

    /// Estimate gas for a contract call (dry-run).
    pub fn estimate_gas(
        &self,
        contract_addr: &[u8; 32],
        function_selector: [u8; 4],
        args: &[u64],
        block_height: u64,
        block_timestamp: u64,
    ) -> Result<u64, ContractError> {
        let result = self.query(contract_addr, function_selector, args, block_height, block_timestamp)?;
        // Add 20% margin
        Ok(result.gas_used + result.gas_used / 5)
    }
}
