//! Shielded wallet for private transactions.
//!
//! The wallet tracks owned notes and can:
//! - Scan blocks to discover incoming notes
//! - Calculate balance (sum of unspent notes)
//!
//! Note: Transaction proof generation is done in the browser wallet using
//! snarkjs/Circom. This Rust wallet is for balance tracking and note scanning.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::core::ShieldedBlock;
use crate::crypto::{
    commitment::NoteCommitment,
    note::{compute_pk_hash, decrypt_note_pq, Note, ViewingKey},
    nullifier::{derive_nullifier, Nullifier, NullifierKey},
    sign, Address, KeyPair,
};

/// A note owned by the wallet.
#[derive(Clone, Debug)]
pub struct WalletNote {
    /// The note itself.
    pub note: Note,
    /// The note commitment.
    pub commitment: NoteCommitment,
    /// Position in the commitment tree.
    pub position: u64,
    /// Block height where this note was created.
    pub height: u64,
    /// Whether this note has been spent.
    pub is_spent: bool,
    /// The nullifier for this note (computed lazily).
    nullifier: Option<Nullifier>,
}

impl WalletNote {
    /// Create a new wallet note.
    pub fn new(note: Note, commitment: NoteCommitment, position: u64, height: u64) -> Self {
        Self {
            note,
            commitment,
            position,
            height,
            is_spent: false,
            nullifier: None,
        }
    }

    /// Get or compute the nullifier.
    pub fn nullifier(&mut self, nullifier_key: &NullifierKey) -> Nullifier {
        if self.nullifier.is_none() {
            self.nullifier = Some(derive_nullifier(nullifier_key, &self.commitment, self.position));
        }
        self.nullifier.unwrap()
    }

    /// Check if this note has been spent.
    pub fn mark_spent(&mut self) {
        self.is_spent = true;
    }
}

/// A shielded wallet with privacy features.
///
/// This wallet is used for:
/// - Generating keypairs (Dilithium for ownership proofs)
/// - Scanning blocks for incoming notes
/// - Tracking balance (sum of unspent notes)
///
/// Note: ZK proof generation for transactions is done in the browser wallet
/// using snarkjs/Circom. This Rust wallet doesn't generate proofs.
pub struct ShieldedWallet {
    /// The signing keypair (Dilithium for ownership proofs).
    keypair: KeyPair,
    /// Secret nullifier key (derived from keypair secret).
    nullifier_key: NullifierKey,
    /// Viewing key for scanning blockchain.
    viewing_key: ViewingKey,
    /// Hash of our public key (for note matching).
    pk_hash: [u8; 32],
    /// Notes owned by this wallet.
    notes: Vec<WalletNote>,
    /// Last scanned block height.
    last_scanned_height: u64,
}

impl ShieldedWallet {
    /// Generate a new random wallet.
    pub fn generate() -> Self {
        let keypair = KeyPair::generate();
        let secret_bytes = keypair.secret_key_bytes();

        let nullifier_key = NullifierKey::new(&secret_bytes);
        let viewing_key = ViewingKey::new(&secret_bytes);
        let pk_hash = compute_pk_hash(&keypair.public_key_bytes());

        Self {
            keypair,
            nullifier_key,
            viewing_key,
            pk_hash,
            notes: Vec::new(),
            last_scanned_height: 0,
        }
    }

    /// Load a wallet from a JSON file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, WalletError> {
        let data = std::fs::read_to_string(path).map_err(WalletError::IoError)?;
        let stored: StoredShieldedWallet =
            serde_json::from_str(&data).map_err(WalletError::ParseError)?;

        let public_key = hex::decode(&stored.public_key).map_err(|_| WalletError::InvalidKey)?;
        let secret_key = hex::decode(&stored.secret_key).map_err(|_| WalletError::InvalidKey)?;

        let keypair =
            KeyPair::from_bytes(&public_key, &secret_key).map_err(|_| WalletError::InvalidKey)?;

        let nullifier_key = NullifierKey::new(&secret_key);
        let viewing_key = ViewingKey::new(&secret_key);
        let pk_hash = compute_pk_hash(&public_key);

        // Load notes from stored data
        let notes = stored
            .notes
            .into_iter()
            .filter_map(|sn| {
                let note = Note::from_bytes(&hex::decode(&sn.note_data).ok()?).ok()?;
                let commitment = NoteCommitment::from_bytes(
                    hex::decode(&sn.commitment).ok()?.try_into().ok()?,
                );
                Some(WalletNote {
                    note,
                    commitment,
                    position: sn.position,
                    height: sn.height,
                    is_spent: sn.is_spent,
                    nullifier: None,
                })
            })
            .collect();

        Ok(Self {
            keypair,
            nullifier_key,
            viewing_key,
            pk_hash,
            notes,
            last_scanned_height: stored.last_scanned_height,
        })
    }

    /// Save the wallet to a JSON file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), WalletError> {
        let stored_notes: Vec<StoredNote> = self
            .notes
            .iter()
            .map(|wn| StoredNote {
                note_data: hex::encode(wn.note.to_bytes()),
                commitment: hex::encode(wn.commitment.to_bytes()),
                position: wn.position,
                height: wn.height,
                is_spent: wn.is_spent,
            })
            .collect();

        let stored = StoredShieldedWallet {
            address: self.address().to_hex(),
            public_key: hex::encode(self.keypair.public_key_bytes()),
            secret_key: hex::encode(self.keypair.secret_key_bytes()),
            pk_hash: hex::encode(self.pk_hash),
            notes: stored_notes,
            last_scanned_height: self.last_scanned_height,
        };

        let data =
            serde_json::to_string_pretty(&stored).map_err(|e| WalletError::ParseError(e))?;
        std::fs::write(path, data).map_err(WalletError::IoError)?;

        Ok(())
    }

    /// Get the wallet's address.
    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    /// Get the wallet's public key hash (for receiving notes).
    pub fn pk_hash(&self) -> [u8; 32] {
        self.pk_hash
    }

    /// Get the signing keypair.
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    /// Get the viewing key.
    pub fn viewing_key(&self) -> &ViewingKey {
        &self.viewing_key
    }

    /// Get the nullifier key.
    pub fn nullifier_key(&self) -> &NullifierKey {
        &self.nullifier_key
    }

    /// Get the nullifier key as raw bytes (for PQ proof witnesses).
    pub fn nullifier_key_bytes(&self) -> [u8; 32] {
        use blake2::Digest;
        use blake2::Blake2s256;
        let mut hasher = Blake2s256::new();
        hasher.update(b"tsn_nullifier_key");
        hasher.update(self.keypair.secret_key_bytes());
        hasher.finalize().into()
    }

    /// Get the current balance (sum of unspent notes).
    pub fn balance(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| !n.is_spent)
            .map(|n| n.note.value)
            .sum()
    }

    /// Get unspent notes.
    pub fn unspent_notes(&self) -> Vec<&WalletNote> {
        self.notes.iter().filter(|n| !n.is_spent).collect()
    }

    /// Get all notes.
    pub fn notes(&self) -> &[WalletNote] {
        &self.notes
    }

    /// Get the number of unspent notes.
    pub fn unspent_count(&self) -> usize {
        self.notes.iter().filter(|n| !n.is_spent).count()
    }

    /// Alias for unspent_count.
    pub fn note_count(&self) -> usize {
        self.unspent_count()
    }

    /// Scan a block for incoming notes.
    /// Returns the number of new notes discovered.
    pub fn scan_block(&mut self, block: &ShieldedBlock, start_position: u64) -> usize {
        let height = block.height();
        let mut position = start_position;
        let mut new_notes = 0;

        // Create decryption key from our pk_hash (matches how notes are encrypted)
        let decryption_key = ViewingKey::from_pk_hash(self.pk_hash);

        // Scan transaction outputs
        for tx in &block.transactions {
            for output in &tx.outputs {
                if let Some(note) = decryption_key.decrypt_note(&output.encrypted_note) {
                    // Check if this note is for us
                    if note.recipient_pk_hash == self.pk_hash {
                        let wallet_note = WalletNote::new(
                            note,
                            output.note_commitment,
                            position,
                            height,
                        );
                        self.notes.push(wallet_note);
                        new_notes += 1;
                    }
                }
                position += 1;
            }
        }

        // Scan V2 transaction outputs (post-quantum)
        for tx in &block.transactions_v2 {
            for output in &tx.outputs {
                if let Some((value, pk_hash, _randomness)) = decrypt_note_pq(&output.encrypted_note, &self.pk_hash) {
                    if pk_hash == self.pk_hash {
                        // Create a Note with zero randomness (for balance tracking only)
                        let note = Note::with_randomness(value, pk_hash, ark_bn254::Fr::from(0u64));
                        // Use a dummy commitment for V2 notes (the real one is PQ)
                        let dummy_commitment = note.commitment();
                        let wallet_note = WalletNote::new(
                            note,
                            dummy_commitment,
                            position,
                            height,
                        );
                        self.notes.push(wallet_note);
                        new_notes += 1;
                    }
                }
                position += 1;
            }
        }

        // Scan coinbase (miner reward)
        if let Some(note) = decryption_key.decrypt_note(&block.coinbase.encrypted_note) {
            if note.recipient_pk_hash == self.pk_hash {
                let wallet_note = WalletNote::new(
                    note,
                    block.coinbase.note_commitment,
                    position,
                    height,
                );
                self.notes.push(wallet_note);
                new_notes += 1;
            }
        }

        // Scan coinbase dev fee note (in case this wallet is the treasury)
        if let Some(ref encrypted) = block.coinbase.dev_fee_encrypted_note {
            if let Some(note) = decryption_key.decrypt_note(encrypted) {
                if note.recipient_pk_hash == self.pk_hash {
                    if let Some(ref cm) = block.coinbase.dev_fee_commitment {
                        let wallet_note = WalletNote::new(note, *cm, position + 1, height);
                        self.notes.push(wallet_note);
                        new_notes += 1;
                    }
                }
            }
        }

        self.last_scanned_height = height;
        new_notes
    }

    /// Mark notes as spent based on observed nullifiers.
    pub fn mark_spent_nullifiers(&mut self, nullifiers: &[Nullifier]) {
        for note in &mut self.notes {
            if !note.is_spent {
                let nf = note.nullifier(&self.nullifier_key);
                if nullifiers.contains(&nf) {
                    note.mark_spent();
                }
            }
        }
    }

    /// Get the last scanned block height.
    pub fn last_scanned_height(&self) -> u64 {
        self.last_scanned_height
    }

    /// Set the last scanned block height (for external scanning via API).
    pub fn set_last_scanned_height(&mut self, height: u64) {
        self.last_scanned_height = height;
    }

    /// Export viewing key as hex string for sharing with third parties.
    ///
    /// The viewing key allows scanning the blockchain for incoming notes
    /// without granting spending capability.
    pub fn export_viewing_key(&self) -> String {
        hex::encode(self.viewing_key.to_bytes())
    }

    /// Create a watch-only wallet from an imported viewing key.
    ///
    /// A watch-only wallet can scan blocks and compute balances but cannot
    /// spend notes because it lacks the signing keypair and nullifier key.
    pub fn from_viewing_key(vk_hex: &str) -> Result<Self, WalletError> {
        let vk_bytes = hex::decode(vk_hex).map_err(|_| WalletError::InvalidKey)?;
        if vk_bytes.len() != 32 {
            return Err(WalletError::InvalidKey);
        }
        let mut vk_arr = [0u8; 32];
        vk_arr.copy_from_slice(&vk_bytes);

        let viewing_key = ViewingKey::from_bytes(vk_arr);

        // For a watch-only wallet we generate a throwaway keypair.
        // The pk_hash is derived from the viewing key itself so that
        // `scan_block_view_only` can attempt decryption using it.
        let keypair = KeyPair::generate();
        let nullifier_key = NullifierKey::new(&[0u8; 32]);

        // The viewing secret doubles as the pk_hash for decryption in the
        // watch-only context (ViewingKey::from_pk_hash uses pk_hash directly).
        let pk_hash = vk_arr;

        Ok(Self {
            keypair,
            nullifier_key,
            viewing_key,
            pk_hash,
            notes: Vec::new(),
            last_scanned_height: 0,
        })
    }

    /// Scan a block using only the viewing key (no spending capability).
    ///
    /// This is used by watch-only wallets to discover incoming notes.
    /// Discovered notes can be viewed but not spent because the watch-only
    /// wallet lacks the nullifier key and signing keypair.
    pub fn scan_block_view_only(&self, block: &ShieldedBlock) -> Vec<WalletNote> {
        let height = block.height();
        let mut found = Vec::new();
        let mut position = 0u64;

        // Decrypt using our viewing key (which is pk_hash-based)
        let decryption_key = ViewingKey::from_pk_hash(self.pk_hash);

        // Scan transaction outputs
        for tx in &block.transactions {
            for output in &tx.outputs {
                if let Some(note) = decryption_key.decrypt_note(&output.encrypted_note) {
                    if note.recipient_pk_hash == self.pk_hash {
                        let wallet_note = WalletNote::new(
                            note,
                            output.note_commitment,
                            position,
                            height,
                        );
                        found.push(wallet_note);
                    }
                }
                position += 1;
            }
        }

        // Scan coinbase
        if let Some(note) = decryption_key.decrypt_note(&block.coinbase.encrypted_note) {
            if note.recipient_pk_hash == self.pk_hash {
                let wallet_note = WalletNote::new(
                    note,
                    block.coinbase.note_commitment,
                    position,
                    height,
                );
                found.push(wallet_note);
            }
        }

        found
    }
}

/// Stored wallet format for serialization.
#[derive(Serialize, Deserialize)]
struct StoredShieldedWallet {
    address: String,
    public_key: String,
    secret_key: String,
    pk_hash: String,
    notes: Vec<StoredNote>,
    last_scanned_height: u64,
}

/// Stored note format.
#[derive(Serialize, Deserialize)]
struct StoredNote {
    note_data: String,
    commitment: String,
    position: u64,
    height: u64,
    is_spent: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("IO error: {0}")]
    IoError(#[source] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(#[source] serde_json::Error),

    #[error("Invalid key data")]
    InvalidKey,
}

// ============================================================================
// Legacy Wallet Support
// ============================================================================

use crate::core::LegacyTransaction;

/// Legacy wallet for backwards compatibility.
#[derive(Clone)]
pub struct LegacyWallet {
    keypair: KeyPair,
}

impl LegacyWallet {
    pub fn generate() -> Self {
        Self {
            keypair: KeyPair::generate(),
        }
    }

    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    pub fn create_transaction(
        &self,
        to: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> LegacyTransaction {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.keypair.address().as_bytes());
        msg.extend_from_slice(to.as_bytes());
        msg.extend_from_slice(&amount.to_le_bytes());
        msg.extend_from_slice(&fee.to_le_bytes());
        msg.extend_from_slice(&nonce.to_le_bytes());

        LegacyTransaction {
            from: self.keypair.address(),
            to,
            amount,
            fee,
            nonce,
            public_key: self.keypair.public_key_bytes().to_vec(),
            signature: Some(sign(&msg, &self.keypair)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_wallet() {
        let wallet = ShieldedWallet::generate();
        assert!(!wallet.address().is_zero());
        assert_eq!(wallet.balance(), 0);
    }

    #[test]
    fn test_wallet_keys() {
        let wallet = ShieldedWallet::generate();

        // pk_hash should be deterministic from public key
        let expected_pk_hash = compute_pk_hash(&wallet.keypair.public_key_bytes());
        assert_eq!(wallet.pk_hash(), expected_pk_hash);
    }

    #[test]
    fn test_save_and_load_wallet() {
        let wallet = ShieldedWallet::generate();
        let original_address = wallet.address();
        let original_pk_hash = wallet.pk_hash();

        let temp_file = NamedTempFile::new().unwrap();
        wallet.save(temp_file.path()).unwrap();

        let loaded = ShieldedWallet::load(temp_file.path()).unwrap();
        assert_eq!(loaded.address(), original_address);
        assert_eq!(loaded.pk_hash(), original_pk_hash);
    }

    #[test]
    fn test_note_discovery() {
        use crate::crypto::commitment::NoteCommitment;

        let mut wallet = ShieldedWallet::generate();

        // Create a note for this wallet
        let mut rng = ark_std::rand::thread_rng();
        let note = Note::new(1000, wallet.pk_hash(), &mut rng);
        let _commitment = note.commitment();

        // Create a mock encrypted note using pk_hash (new encryption scheme)
        let encryption_key = ViewingKey::from_pk_hash(wallet.pk_hash());
        let encrypted = encryption_key.encrypt_note(&note, &mut rng);

        // Try to decrypt using pk_hash
        let decryption_key = ViewingKey::from_pk_hash(wallet.pk_hash());
        let decrypted = decryption_key.decrypt_note(&encrypted).unwrap();
        assert_eq!(decrypted.value, 1000);
        assert_eq!(decrypted.recipient_pk_hash, wallet.pk_hash());
    }

    #[test]
    fn test_balance_calculation() {
        let mut wallet = ShieldedWallet::generate();

        // Add some fake notes
        let mut rng = ark_std::rand::thread_rng();
        for value in [100, 200, 300] {
            let note = Note::new(value, wallet.pk_hash(), &mut rng);
            let commitment = note.commitment();
            wallet.notes.push(WalletNote::new(note, commitment, 0, 0));
        }

        assert_eq!(wallet.balance(), 600);
        assert_eq!(wallet.unspent_count(), 3);

        // Mark one as spent
        wallet.notes[0].mark_spent();
        assert_eq!(wallet.balance(), 500);
        assert_eq!(wallet.unspent_count(), 2);
    }

}
