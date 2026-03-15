//! Contract storage engine — per-contract key-value storage backed by Sled.
//!
//! Each contract has its own namespace in the database.
//! Keys are u64 slot numbers, values are u64.

use std::collections::HashMap;

/// Contract storage backed by a Sled tree.
pub struct ContractStorage {
    tree: sled::Tree,
}

impl ContractStorage {
    /// Open or create the contract_storage tree.
    pub fn new(db: &sled::Db) -> Result<Self, sled::Error> {
        let tree = db.open_tree("contract_storage")?;
        Ok(Self { tree })
    }

    /// Read a storage slot for a contract.
    pub fn get(&self, contract_addr: &[u8; 32], slot: u64) -> Result<u64, sled::Error> {
        let key = storage_key(contract_addr, slot);
        match self.tree.get(key)? {
            Some(bytes) => {
                let val = u64::from_le_bytes(bytes.as_ref().try_into().unwrap_or([0u8; 8]));
                Ok(val)
            }
            None => Ok(0), // default value
        }
    }

    /// Write a storage slot.
    pub fn set(&self, contract_addr: &[u8; 32], slot: u64, value: u64) -> Result<(), sled::Error> {
        let key = storage_key(contract_addr, slot);
        self.tree.insert(key, &value.to_le_bytes())?;
        Ok(())
    }

    /// Load all storage slots for a contract into a HashMap (for VM execution).
    pub fn load_snapshot(&self, contract_addr: &[u8; 32]) -> Result<HashMap<u64, u64>, sled::Error> {
        let prefix = contract_addr.to_vec();
        let mut snapshot = HashMap::new();
        for entry in self.tree.scan_prefix(&prefix) {
            let (key, val) = entry?;
            if key.len() == 40 {
                let slot = u64::from_le_bytes(key[32..40].try_into().unwrap());
                let value = u64::from_le_bytes(val.as_ref().try_into().unwrap_or([0u8; 8]));
                snapshot.insert(slot, value);
            }
        }
        Ok(snapshot)
    }

    /// Apply a batch of storage writes (after successful VM execution).
    pub fn apply_writes(
        &self,
        contract_addr: &[u8; 32],
        writes: &HashMap<u64, u64>,
    ) -> Result<(), sled::Error> {
        let mut batch = sled::Batch::default();
        for (&slot, &value) in writes {
            let key = storage_key(contract_addr, slot);
            batch.insert(key, &value.to_le_bytes());
        }
        self.tree.apply_batch(batch)?;
        Ok(())
    }

    /// Delete all storage for a contract (rarely used — self-destruct).
    pub fn clear_contract(&self, contract_addr: &[u8; 32]) -> Result<(), sled::Error> {
        let prefix = contract_addr.to_vec();
        for entry in self.tree.scan_prefix(&prefix) {
            let (key, _) = entry?;
            self.tree.remove(key)?;
        }
        Ok(())
    }

    /// Count storage slots for a contract.
    pub fn slot_count(&self, contract_addr: &[u8; 32]) -> Result<u64, sled::Error> {
        let prefix = contract_addr.to_vec();
        let mut count = 0u64;
        for entry in self.tree.scan_prefix(&prefix) {
            let _ = entry?;
            count += 1;
        }
        Ok(count)
    }
}

/// Build a storage key: contract_address (32 bytes) || slot (8 bytes LE).
fn storage_key(contract_addr: &[u8; 32], slot: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(contract_addr);
    key.extend_from_slice(&slot.to_le_bytes());
    key
}

/// Contract registry backed by a Sled tree.
pub struct ContractRegistry {
    tree: sled::Tree,
}

impl ContractRegistry {
    /// Open or create the contracts tree.
    pub fn new(db: &sled::Db) -> Result<Self, sled::Error> {
        let tree = db.open_tree("contracts")?;
        Ok(Self { tree })
    }

    /// Store a contract.
    pub fn put(&self, contract: &super::types::Contract) -> Result<(), Box<dyn std::error::Error>> {
        let data = serde_json::to_vec(contract)?;
        self.tree.insert(&contract.address, data)?;
        Ok(())
    }

    /// Load a contract by address.
    pub fn get(&self, address: &[u8; 32]) -> Result<Option<super::types::Contract>, Box<dyn std::error::Error>> {
        match self.tree.get(address)? {
            Some(data) => {
                let contract: super::types::Contract = serde_json::from_slice(&data)?;
                Ok(Some(contract))
            }
            None => Ok(None),
        }
    }

    /// Check if a contract exists.
    pub fn exists(&self, address: &[u8; 32]) -> Result<bool, sled::Error> {
        Ok(self.tree.contains_key(address)?)
    }

    /// Update a contract's storage root and balance.
    pub fn update_state(
        &self,
        address: &[u8; 32],
        storage_root: [u8; 32],
        balance: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(mut contract) = self.get(address)? {
            contract.storage_root = storage_root;
            contract.balance = balance;
            self.put(&contract)?;
        }
        Ok(())
    }

    /// Count total deployed contracts.
    pub fn count(&self) -> usize {
        self.tree.len()
    }
}

/// Event log storage.
pub struct EventStore {
    tree: sled::Tree,
}

impl EventStore {
    /// Open or create the contract_events tree.
    pub fn new(db: &sled::Db) -> Result<Self, sled::Error> {
        let tree = db.open_tree("contract_events")?;
        Ok(Self { tree })
    }

    /// Store an event.
    pub fn put(&self, event: &super::types::ContractEventLog) -> Result<(), Box<dyn std::error::Error>> {
        let key = event_key(event.height, event.tx_index, event.topic);
        let data = serde_json::to_vec(event)?;
        self.tree.insert(key, data)?;
        Ok(())
    }

    /// Query events for a contract in a height range.
    pub fn query(
        &self,
        contract_addr: &[u8; 32],
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<super::types::ContractEventLog>, Box<dyn std::error::Error>> {
        let mut events = Vec::new();
        let start = from_height.to_be_bytes().to_vec();
        for entry in self.tree.range(start..) {
            let (_, val) = entry?;
            let event: super::types::ContractEventLog = serde_json::from_slice(&val)?;
            if event.height > to_height {
                break;
            }
            if event.contract_address == *contract_addr {
                events.push(event);
            }
        }
        Ok(events)
    }
}

fn event_key(height: u64, tx_index: u32, topic: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(20);
    key.extend_from_slice(&height.to_be_bytes());
    key.extend_from_slice(&tx_index.to_be_bytes());
    key.extend_from_slice(&topic.to_be_bytes());
    key
}
