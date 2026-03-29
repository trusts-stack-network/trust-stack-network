//! Faucet module for distributing TSN tokens.
//!
//! Provides a daily faucet (50 TSN per wallet per day) that:
//! - Tracks claims by pk_hash (no IP restrictions)
//! - Maintains streak counters for consecutive daily claims
//! - Creates V2 shielded transactions using Plonky2 proofs

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{TimeZone, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::config::{
    FAUCET_COOLDOWN_SECONDS, FAUCET_DAILY_LIMIT, FAUCET_LOW_BALANCE_THRESHOLD, FAUCET_TX_FEE,
    FAUCET_TOKEN_VALUE, FAUCET_MAX_TOKENS, FAUCET_MIN_TOKENS,
};
use crate::core::{OutputDescriptionV2, ShieldedBlock, ShieldedTransactionV2, SpendDescriptionV2};
use crate::crypto::note::{decrypt_note_pq, encrypt_note_pq, ViewingKey};
use crate::crypto::pq::commitment_pq::{derive_nullifier_pq, NoteCommitmentPQ};
use crate::crypto::pq::merkle_pq::MerkleWitnessPQ;
use crate::crypto::pq::proof_pq::{OutputWitnessPQ, Plonky2Proof, SpendWitnessPQ, TransactionProver};
use crate::crypto::{sign, KeyPair};
use crate::storage::{Database, FaucetClaim};

/// Faucet service errors.
#[derive(Debug, Error)]
pub enum FaucetError {
    #[error("Faucet not enabled")]
    NotEnabled,

    #[error("Cooldown active: {0} seconds remaining")]
    CooldownActive(u64),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Insufficient faucet balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("Transaction creation failed: {0}")]
    TransactionError(String),

    #[error("Invalid pk_hash format")]
    InvalidPkHash,

    #[error("Proof generation failed: {0}")]
    ProofError(String),

    #[error("No unspent notes available")]
    NoUnspentNotes,

    #[error("Invalid token count: {0} (must be {}-{})", FAUCET_MIN_TOKENS, FAUCET_MAX_TOKENS)]
    InvalidTokenCount(u8),
}

/// A V2 note owned by the faucet wallet.
#[derive(Clone, Debug)]
pub struct FaucetNote {
    /// Note value in base units.
    pub value: u64,
    /// Recipient pk_hash (should be faucet's own pk_hash).
    pub pk_hash: [u8; 32],
    /// Note randomness.
    pub randomness: [u8; 32],
    /// Position in the V2 commitment tree.
    pub position: u64,
    /// Block height where this note was created.
    pub height: u64,
    /// Whether this note has been spent.
    pub spent: bool,
    /// The note commitment.
    pub commitment: [u8; 32],
}

/// Status information for a faucet claim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaucetStatus {
    /// Whether the wallet can claim now.
    pub can_claim: bool,
    /// Seconds until eligible (0 if can claim).
    pub seconds_until_eligible: u64,
    /// Current streak (consecutive days).
    pub streak: u32,
    /// Total amount claimed all-time (formatted).
    pub total_claimed: String,
    /// Daily claim amount (formatted).
    pub daily_amount: String,
}

/// Result of a successful faucet claim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimResult {
    /// Whether the claim was successful.
    pub success: bool,
    /// Transaction hash.
    pub tx_hash: String,
    /// Amount claimed (formatted).
    pub amount: String,
    /// New streak count.
    pub new_streak: u32,
    /// User-friendly message.
    pub message: String,
}

/// Public faucet statistics.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaucetStats {
    /// Total TSN distributed (formatted).
    pub total_distributed: String,
    /// Number of unique claimants.
    pub unique_claimants: u64,
    /// Number of active streaks.
    pub active_streaks: u64,
    /// Faucet balance (formatted).
    pub balance: Option<String>,
    /// Whether faucet is enabled.
    pub enabled: bool,
}

/// Faucet service that distributes TSN tokens.
pub struct FaucetService {
    /// Faucet's keypair (for signing).
    keypair: KeyPair,
    /// Faucet's pk_hash.
    pk_hash: [u8; 32],
    /// Nullifier key derived from secret key.
    nullifier_key: [u8; 32],
    /// Database for storing claims.
    db: Arc<Database>,
    /// Daily limit per wallet in base units.
    daily_limit: u64,
    /// Cooldown period in seconds.
    cooldown_seconds: u64,
    /// V2 notes owned by the faucet.
    notes: Vec<FaucetNote>,
    /// Last scanned block height.
    last_scanned_height: u64,
    /// Last known V2 tree position (for incremental scanning).
    last_pq_position: u64,
    /// Transaction prover (cached circuits).
    prover: TransactionProver,
}

impl FaucetService {
    /// Create a new faucet service.
    pub fn new(keypair: KeyPair, pk_hash: [u8; 32], db: Arc<Database>) -> Self {
        // Derive nullifier key from secret key (first 32 bytes of hash)
        use sha2::{Digest, Sha256};
        let sk_bytes = keypair.secret_key_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b"tsn_nullifier_key");
        hasher.update(&sk_bytes[..64.min(sk_bytes.len())]);
        let nullifier_key: [u8; 32] = hasher.finalize().into();

        Self {
            keypair,
            pk_hash,
            nullifier_key,
            db,
            daily_limit: FAUCET_DAILY_LIMIT,
            cooldown_seconds: FAUCET_COOLDOWN_SECONDS,
            notes: Vec::new(),
            last_scanned_height: 0,
            last_pq_position: 0,
            prover: TransactionProver::new(),
        }
    }

    /// Create with custom limits.
    pub fn with_limits(
        keypair: KeyPair,
        pk_hash: [u8; 32],
        db: Arc<Database>,
        daily_limit: u64,
        cooldown_seconds: u64,
    ) -> Self {
        let mut service = Self::new(keypair, pk_hash, db);
        service.daily_limit = daily_limit;
        service.cooldown_seconds = cooldown_seconds;
        service
    }

    /// Get current Unix timestamp.
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Get today's date string (UTC).
    fn today_date() -> String {
        let now = Self::now();
        Utc.timestamp_opt(now as i64, 0)
            .single()
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "1970-01-01".to_string())
    }

    /// Get yesterday's date string (UTC).
    fn yesterday_date() -> String {
        let yesterday = Self::now().saturating_sub(86400);
        Utc.timestamp_opt(yesterday as i64, 0)
            .single()
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "1970-01-01".to_string())
    }

    /// Parse a pk_hash from hex string.
    fn parse_pk_hash(pk_hash_hex: &str) -> Result<[u8; 32], FaucetError> {
        let bytes = hex::decode(pk_hash_hex).map_err(|_| FaucetError::InvalidPkHash)?;
        bytes.try_into().map_err(|_| FaucetError::InvalidPkHash)
    }

    /// Format amount in base units to human-readable TSN.
    fn format_amount(base_units: u64) -> String {
        let whole = base_units / 1_000_000_000;
        let frac = base_units % 1_000_000_000;
        if frac == 0 {
            format!("{}.0 TSN", whole)
        } else {
            format!("{}.{} TSN", whole, frac)
        }
    }

    /// Get the faucet's pk_hash.
    pub fn pk_hash(&self) -> [u8; 32] {
        self.pk_hash
    }

    /// Get the faucet's pk_hash as hex.
    pub fn pk_hash_hex(&self) -> String {
        hex::encode(self.pk_hash)
    }

    /// Get total balance of unspent notes.
    pub fn balance(&self) -> u64 {
        self.notes.iter().filter(|n| !n.spent).map(|n| n.value).sum()
    }

    /// Get count of unspent notes.
    pub fn unspent_count(&self) -> usize {
        self.notes.iter().filter(|n| !n.spent).count()
    }

    /// Add a note discovered during scanning.
    pub fn add_note(&mut self, note: FaucetNote) {
        self.notes.push(note);
    }

    /// Mark a note as spent by its commitment.
    pub fn mark_spent(&mut self, commitment: &[u8; 32]) {
        for note in &mut self.notes {
            if &note.commitment == commitment {
                note.spent = true;
            }
        }
    }

    /// Update last scanned height.
    pub fn set_last_scanned_height(&mut self, height: u64) {
        self.last_scanned_height = height;
    }

    /// Get last scanned height.
    pub fn last_scanned_height(&self) -> u64 {
        self.last_scanned_height
    }

    /// Scan a block for V2 notes belonging to the faucet wallet.
    /// Returns the number of new notes discovered.
    ///
    /// # Arguments
    /// * `block` - The block to scan
    /// * `pq_start_position` - The position in the V2 commitment tree at the start of this block
    ///
    /// Note: The commitment order in the PQ tree is:
    /// 1. V1 transaction outputs (each tx's outputs in order)
    /// 2. V2 transaction outputs (each tx's outputs in order)
    /// 3. Coinbase (LAST)
    pub fn scan_block(&mut self, block: &ShieldedBlock, pq_start_position: u64) -> usize {
        let height = block.height();
        let mut position = pq_start_position;
        let mut new_notes = 0;

        // Scan V1 transaction outputs FIRST (they also add to V2 tree)
        for tx in &block.transactions {
            for output in &tx.outputs {
                // Try PQ decryption
                if let Some((value, note_pk_hash, randomness)) =
                    decrypt_note_pq(&output.encrypted_note, &self.pk_hash)
                {
                    if note_pk_hash == self.pk_hash {
                        let expected_commitment =
                            NoteCommitmentPQ::commit(value, &note_pk_hash, &randomness);
                        // V1 outputs use the V1 commitment converted to V2
                        let output_cm_bytes = output.note_commitment.to_bytes();
                        if expected_commitment.to_bytes() == output_cm_bytes {
                            let note = FaucetNote {
                                value,
                                pk_hash: note_pk_hash,
                                randomness,
                                position,
                                height,
                                spent: false,
                                commitment: output_cm_bytes,
                            };
                            self.notes.push(note);
                            new_notes += 1;
                        }
                    }
                }
                position += 1;
            }
        }

        // Scan V2 transaction outputs SECOND
        for tx in &block.transactions_v2 {
            for output in &tx.outputs {
                // Try PQ decryption
                if let Some((value, note_pk_hash, randomness)) =
                    decrypt_note_pq(&output.encrypted_note, &self.pk_hash)
                {
                    if note_pk_hash == self.pk_hash {
                        let expected_commitment =
                            NoteCommitmentPQ::commit(value, &note_pk_hash, &randomness);
                        if expected_commitment.to_bytes() == output.note_commitment {
                            let note = FaucetNote {
                                value,
                                pk_hash: note_pk_hash,
                                randomness,
                                position,
                                height,
                                spent: false,
                                commitment: output.note_commitment,
                            };
                            self.notes.push(note);
                            new_notes += 1;
                            info!(
                                "Faucet discovered V2 tx output: {} TSN at height {}",
                                value / 1_000_000_000,
                                height
                            );
                        }
                    }
                }
                position += 1;
            }
        }

        // Scan coinbase LAST (it's added to the tree after all transactions)
        // First try PQ decryption format
        if let Some((value, note_pk_hash, randomness)) =
            decrypt_note_pq(&block.coinbase.encrypted_note, &self.pk_hash)
        {
            // Check if this note is for us
            if note_pk_hash == self.pk_hash {
                // Verify the commitment matches
                let expected_commitment =
                    NoteCommitmentPQ::commit(value, &note_pk_hash, &randomness);
                if expected_commitment.to_bytes() == block.coinbase.note_commitment_pq {
                    let note = FaucetNote {
                        value,
                        pk_hash: note_pk_hash,
                        randomness,
                        position,
                        height,
                        spent: false,
                        commitment: block.coinbase.note_commitment_pq,
                    };
                    self.notes.push(note);
                    new_notes += 1;
                    info!(
                        "Faucet discovered coinbase note: {} TSN at height {} (position {})",
                        value / 1_000_000_000,
                        height,
                        position
                    );
                }
            }
        } else {
            // Try V1 decryption format (ViewingKey from pk_hash)
            let viewing_key = ViewingKey::from_pk_hash(self.pk_hash);
            if let Some(note) = viewing_key.decrypt_note(&block.coinbase.encrypted_note) {
                if note.recipient_pk_hash == self.pk_hash {
                    // Convert V1 note randomness to bytes
                    use ark_serialize::CanonicalSerialize;
                    let mut randomness_bytes = [0u8; 32];
                    note.randomness
                        .serialize_compressed(&mut randomness_bytes[..])
                        .ok();

                    // Verify V2 commitment
                    let expected_commitment = NoteCommitmentPQ::commit(
                        note.value,
                        &note.recipient_pk_hash,
                        &randomness_bytes,
                    );
                    if expected_commitment.to_bytes() == block.coinbase.note_commitment_pq {
                        let faucet_note = FaucetNote {
                            value: note.value,
                            pk_hash: note.recipient_pk_hash,
                            randomness: randomness_bytes,
                            position,
                            height,
                            spent: false,
                            commitment: block.coinbase.note_commitment_pq,
                        };
                        self.notes.push(faucet_note);
                        new_notes += 1;
                        info!(
                            "Faucet discovered coinbase note (V1 format): {} TSN at height {} (position {})",
                            note.value / 1_000_000_000,
                            height,
                            position
                        );
                    }
                }
            }
        }
        // position += 1; // Coinbase adds one commitment (handled by scan_blockchain)

        self.last_scanned_height = height;
        new_notes
    }

    /// Mark notes as spent based on observed nullifiers in a block.
    pub fn mark_spent_from_block(&mut self, block: &ShieldedBlock) {
        // Collect nullifiers from V2 transactions
        let nullifiers: Vec<[u8; 32]> = block
            .transactions_v2
            .iter()
            .flat_map(|tx| tx.nullifiers())
            .collect();

        self.mark_spent_by_nullifiers(&nullifiers);
    }

    /// Mark notes as spent by their nullifiers.
    pub fn mark_spent_by_nullifiers(&mut self, nullifiers: &[[u8; 32]]) {
        for note in &mut self.notes {
            if note.spent {
                continue;
            }

            // Compute this note's nullifier
            let note_nullifier = derive_nullifier_pq(
                &self.nullifier_key,
                &note.commitment,
                note.position,
            );

            if nullifiers.contains(&note_nullifier) {
                note.spent = true;
                info!(
                    "Faucet note marked spent: {} TSN (position {})",
                    note.value / 1_000_000_000,
                    note.position
                );
            }
        }
    }

    /// Get the number of notes discovered (for logging).
    pub fn note_count(&self) -> usize {
        self.notes.len()
    }

    /// Scan the blockchain from the last scanned height to the current height.
    /// This should be called on startup and periodically to discover new notes.
    ///
    /// # Arguments
    /// * `get_block` - Closure to get a block by height
    /// * `current_height` - The current blockchain height
    ///
    /// Returns the number of new notes discovered.
    pub fn scan_blockchain<F>(&mut self, get_block: F, current_height: u64) -> usize
    where
        F: Fn(u64) -> Option<ShieldedBlock>,
    {
        let start_height = if self.last_scanned_height == 0 && self.last_pq_position == 0 {
            0
        } else {
            self.last_scanned_height + 1
        };

        if start_height > current_height {
            return 0;
        }

        let mut total_new_notes = 0;
        let mut pq_position = self.last_pq_position;

        info!(
            "Faucet scanning blockchain from height {} to {} (starting position {})",
            start_height, current_height, pq_position
        );

        for height in start_height..=current_height {
            if let Some(block) = get_block(height) {
                // Record the position at the start of this block
                let block_start_position = pq_position;

                // Scan the block for our notes
                let new_notes = self.scan_block(&block, block_start_position);
                total_new_notes += new_notes;

                // Mark any of our notes as spent if their nullifiers appear
                self.mark_spent_from_block(&block);

                // Update position: count commitments added by this block
                // Order in tree: V1 tx outputs, V2 tx outputs, then coinbase (LAST)
                for tx in &block.transactions {
                    pq_position += tx.outputs.len() as u64;
                }
                for tx in &block.transactions_v2 {
                    pq_position += tx.outputs.len() as u64;
                }
                pq_position += 1; // coinbase is added last
            }
        }

        // Save the final position for the next incremental scan
        self.last_pq_position = pq_position;

        if total_new_notes > 0 {
            info!(
                "Faucet scan complete: found {} new notes, balance = {} TSN",
                total_new_notes,
                self.balance() / 1_000_000_000
            );
        } else {
            info!(
                "Faucet scan complete: no new notes found (scanned {} blocks)",
                current_height.saturating_sub(start_height) + 1
            );
        }

        total_new_notes
    }

    /// Quick scan of a single new block (for incremental updates).
    /// Call this when a new block is added to the chain.
    ///
    /// # Arguments
    /// * `block` - The new block
    /// * `pq_position_before_block` - The V2 tree size before this block was added
    pub fn scan_new_block(&mut self, block: &ShieldedBlock, pq_position_before_block: u64) -> usize {
        let new_notes = self.scan_block(block, pq_position_before_block);
        self.mark_spent_from_block(block);
        new_notes
    }

    /// Select notes to spend for a given amount.
    fn select_notes(&self, amount: u64) -> Result<Vec<&FaucetNote>, FaucetError> {
        let mut selected = Vec::new();
        let mut total = 0u64;

        // Simple greedy selection - largest notes first
        let mut unspent: Vec<_> = self.notes.iter().filter(|n| !n.spent).collect();
        unspent.sort_by(|a, b| b.value.cmp(&a.value));

        for note in unspent {
            if total >= amount {
                break;
            }
            selected.push(note);
            total += note.value;
        }

        if total < amount {
            return Err(FaucetError::InsufficientBalance {
                have: total,
                need: amount,
            });
        }

        Ok(selected)
    }

    /// Check if a wallet can claim.
    pub fn can_claim(&self, pk_hash_hex: &str) -> Result<bool, FaucetError> {
        let pk_hash = Self::parse_pk_hash(pk_hash_hex)?;

        let claim = self
            .db
            .get_faucet_claim(&pk_hash)
            .map_err(|e| FaucetError::Database(e.to_string()))?;

        match claim {
            Some(c) => {
                let elapsed = Self::now().saturating_sub(c.last_claim_timestamp);
                Ok(elapsed >= self.cooldown_seconds)
            }
            None => Ok(true),
        }
    }

    /// Get claim status for a wallet.
    pub fn get_claim_info(&self, pk_hash_hex: &str) -> Result<FaucetStatus, FaucetError> {
        let pk_hash = Self::parse_pk_hash(pk_hash_hex)?;

        let claim = self
            .db
            .get_faucet_claim(&pk_hash)
            .map_err(|e| FaucetError::Database(e.to_string()))?;

        match claim {
            Some(c) => {
                let now = Self::now();
                let elapsed = now.saturating_sub(c.last_claim_timestamp);
                let can_claim = elapsed >= self.cooldown_seconds;
                let seconds_until_eligible = if can_claim {
                    0
                } else {
                    self.cooldown_seconds.saturating_sub(elapsed)
                };

                let today = Self::today_date();
                let yesterday = Self::yesterday_date();
                let streak = if c.last_streak_date == today || c.last_streak_date == yesterday {
                    c.streak
                } else {
                    0
                };

                Ok(FaucetStatus {
                    can_claim,
                    seconds_until_eligible,
                    streak,
                    total_claimed: Self::format_amount(c.total_claimed),
                    daily_amount: Self::format_amount(self.daily_limit),
                })
            }
            None => Ok(FaucetStatus {
                can_claim: true,
                seconds_until_eligible: 0,
                streak: 0,
                total_claimed: "0.0 TSN".to_string(),
                daily_amount: Self::format_amount(self.daily_limit),
            }),
        }
    }

    /// Get the positions of notes that would be spent for a claim.
    /// Used to pre-fetch witnesses before calling process_claim.
    pub fn get_note_positions_for_claim(&self) -> Result<Vec<u64>, FaucetError> {
        let total_needed = self.daily_limit + FAUCET_TX_FEE;
        let notes = self.select_notes(total_needed)?;
        Ok(notes.iter().map(|n| n.position).collect())
    }

    /// Process a faucet claim - creates and returns a V2 transaction.
    /// The witnesses map should contain witnesses for all positions returned by get_note_positions_for_claim.
    pub fn process_claim(
        &mut self,
        pk_hash_hex: &str,
        witnesses: &std::collections::HashMap<u64, MerkleWitnessPQ>,
    ) -> Result<(ClaimResult, ShieldedTransactionV2), FaucetError> {
        let recipient_pk_hash = Self::parse_pk_hash(pk_hash_hex)?;

        // Check cooldown
        let now = Self::now();
        let existing_claim = self
            .db
            .get_faucet_claim(&recipient_pk_hash)
            .map_err(|e| FaucetError::Database(e.to_string()))?;

        if let Some(ref c) = existing_claim {
            let elapsed = now.saturating_sub(c.last_claim_timestamp);
            if elapsed < self.cooldown_seconds {
                let remaining = self.cooldown_seconds.saturating_sub(elapsed);
                return Err(FaucetError::CooldownActive(remaining));
            }
        }

        // Calculate amount needed (claim amount + fee)
        let claim_amount = self.daily_limit;
        let fee = FAUCET_TX_FEE;
        let total_needed = claim_amount + fee;

        // Select notes to spend
        let notes_to_spend = self.select_notes(total_needed)?;
        let total_input: u64 = notes_to_spend.iter().map(|n| n.value).sum();
        let change = total_input - claim_amount - fee;

        info!(
            "Faucet claim: {} notes, input={}, claim={}, fee={}, change={}",
            notes_to_spend.len(),
            total_input,
            claim_amount,
            fee,
            change
        );

        // Build spend witnesses
        let mut spend_witnesses = Vec::new();
        let mut spent_commitments = Vec::new();

        for note in &notes_to_spend {
            let merkle_witness = witnesses.get(&note.position).cloned().ok_or_else(|| {
                FaucetError::TransactionError(format!(
                    "Could not get witness for position {}",
                    note.position
                ))
            })?;

            spend_witnesses.push(SpendWitnessPQ {
                value: note.value,
                recipient_pk_hash: note.pk_hash,
                randomness: note.randomness,
                nullifier_key: self.nullifier_key,
                position: note.position,
                merkle_witness,
            });

            spent_commitments.push(note.commitment);
        }

        // Build output witnesses
        let mut rng = rand::thread_rng();
        let mut output_witnesses = Vec::new();

        // Output to recipient
        let mut recipient_randomness = [0u8; 32];
        rng.fill_bytes(&mut recipient_randomness);
        output_witnesses.push(OutputWitnessPQ {
            value: claim_amount,
            recipient_pk_hash,
            randomness: recipient_randomness,
        });

        // Change output back to faucet (if any)
        let mut change_randomness = [0u8; 32];
        if change > 0 {
            rng.fill_bytes(&mut change_randomness);
            output_witnesses.push(OutputWitnessPQ {
                value: change,
                recipient_pk_hash: self.pk_hash,
                randomness: change_randomness,
            });
        }

        // Generate proof
        info!("Generating Plonky2 proof for faucet transaction...");
        let proof = self
            .prover
            .prove(&spend_witnesses, &output_witnesses, fee)
            .map_err(|e| FaucetError::ProofError(e.to_string()))?;
        info!("Proof generated: {} bytes", proof.size());

        // Build transaction
        let tx = self.build_transaction(
            &spend_witnesses,
            &output_witnesses,
            fee,
            proof,
            recipient_pk_hash,
            recipient_randomness,
            if change > 0 { Some(change_randomness) } else { None },
        )?;

        let tx_hash = hex::encode(tx.hash());

        // Mark notes as spent
        for commitment in spent_commitments {
            self.mark_spent(&commitment);
        }

        // Update claim record
        let today = Self::today_date();
        let yesterday = Self::yesterday_date();
        let new_streak = match &existing_claim {
            Some(c) => {
                if c.last_streak_date == yesterday {
                    c.streak + 1
                } else if c.last_streak_date == today {
                    c.streak
                } else {
                    1
                }
            }
            None => 1,
        };

        let new_total = existing_claim
            .as_ref()
            .map(|c| c.total_claimed)
            .unwrap_or(0)
            .saturating_add(claim_amount);

        let updated_claim = FaucetClaim {
            last_claim_timestamp: now,
            total_claimed: new_total,
            streak: new_streak,
            last_streak_date: today,
        };

        self.db
            .save_faucet_claim(&recipient_pk_hash, &updated_claim)
            .map_err(|e| FaucetError::Database(e.to_string()))?;

        info!(
            "Faucet claim processed: {} -> streak={}, total={}",
            &pk_hash_hex[..16],
            new_streak,
            Self::format_amount(new_total)
        );

        let message = if new_streak >= 30 {
            format!("Amazing! {} day streak!", new_streak)
        } else if new_streak >= 7 {
            format!("Great! {} day streak!", new_streak)
        } else if new_streak > 1 {
            format!("{} day streak continues!", new_streak)
        } else {
            "Claimed successfully!".to_string()
        };

        Ok((
            ClaimResult {
                success: true,
                tx_hash,
                amount: Self::format_amount(claim_amount),
                new_streak,
                message,
            },
            tx,
        ))
    }

    /// Build a V2 shielded transaction.
    fn build_transaction(
        &self,
        spend_witnesses: &[SpendWitnessPQ],
        output_witnesses: &[OutputWitnessPQ],
        fee: u64,
        proof: Plonky2Proof,
        recipient_pk_hash: [u8; 32],
        recipient_randomness: [u8; 32],
        change_randomness: Option<[u8; 32]>,
    ) -> Result<ShieldedTransactionV2, FaucetError> {
        // Build spend descriptions with signatures
        let mut spends = Vec::new();
        for spend in spend_witnesses {
            let nullifier = spend.nullifier();
            let anchor = spend.merkle_witness.root;

            // Sign the spend (message is just the nullifier)
            let signature = sign(&nullifier, &self.keypair);

            spends.push(SpendDescriptionV2 {
                anchor,
                nullifier,
                signature,
                public_key: self.keypair.public_key_bytes().to_vec(),
            });
        }

        // Build output descriptions
        let mut outputs = Vec::new();

        // Recipient output
        let recipient_commitment =
            NoteCommitmentPQ::commit(output_witnesses[0].value, &recipient_pk_hash, &recipient_randomness);
        let recipient_encrypted = encrypt_note_pq(
            output_witnesses[0].value,
            &recipient_pk_hash,
            &recipient_randomness,
        );
        outputs.push(OutputDescriptionV2 {
            note_commitment: recipient_commitment.to_bytes(),
            encrypted_note: recipient_encrypted,
        });

        // Change output (if any)
        if let Some(change_rand) = change_randomness {
            let change_value = output_witnesses[1].value;
            let change_commitment =
                NoteCommitmentPQ::commit(change_value, &self.pk_hash, &change_rand);
            let change_encrypted = encrypt_note_pq(change_value, &self.pk_hash, &change_rand);
            outputs.push(OutputDescriptionV2 {
                note_commitment: change_commitment.to_bytes(),
                encrypted_note: change_encrypted,
            });
        }

        Ok(ShieldedTransactionV2::new(spends, outputs, fee, proof))
    }

    /// Get the positions of notes needed for a game claim with specific token count.
    pub fn get_note_positions_for_game_claim(&self, tokens: u8) -> Result<Vec<u64>, FaucetError> {
        if tokens < FAUCET_MIN_TOKENS || tokens > FAUCET_MAX_TOKENS {
            return Err(FaucetError::InvalidTokenCount(tokens));
        }
        let claim_amount = (tokens as u64) * FAUCET_TOKEN_VALUE;
        let total_needed = claim_amount + FAUCET_TX_FEE;
        let notes = self.select_notes(total_needed)?;
        Ok(notes.iter().map(|n| n.position).collect())
    }

    /// Process a game-based faucet claim with variable token count.
    /// Similar to process_claim but uses token count to determine payout.
    pub fn process_game_claim(
        &mut self,
        pk_hash_hex: &str,
        tokens_collected: u8,
        witnesses: &std::collections::HashMap<u64, MerkleWitnessPQ>,
    ) -> Result<(ClaimResult, ShieldedTransactionV2), FaucetError> {
        // Validate token count
        if tokens_collected < FAUCET_MIN_TOKENS || tokens_collected > FAUCET_MAX_TOKENS {
            return Err(FaucetError::InvalidTokenCount(tokens_collected));
        }

        let recipient_pk_hash = Self::parse_pk_hash(pk_hash_hex)?;

        // Check cooldown
        let now = Self::now();
        let existing_claim = self
            .db
            .get_faucet_claim(&recipient_pk_hash)
            .map_err(|e| FaucetError::Database(e.to_string()))?;

        if let Some(ref c) = existing_claim {
            let elapsed = now.saturating_sub(c.last_claim_timestamp);
            if elapsed < self.cooldown_seconds {
                let remaining = self.cooldown_seconds.saturating_sub(elapsed);
                return Err(FaucetError::CooldownActive(remaining));
            }
        }

        // Calculate amount based on tokens collected
        let claim_amount = (tokens_collected as u64) * FAUCET_TOKEN_VALUE;
        let fee = FAUCET_TX_FEE;
        let total_needed = claim_amount + fee;

        // Select notes to spend
        let notes_to_spend = self.select_notes(total_needed)?;
        let total_input: u64 = notes_to_spend.iter().map(|n| n.value).sum();
        let change = total_input - claim_amount - fee;

        info!(
            "Faucet game claim: {} tokens = {} TSN, {} notes, input={}, fee={}, change={}",
            tokens_collected,
            claim_amount / 1_000_000_000,
            notes_to_spend.len(),
            total_input,
            fee,
            change
        );

        // Build spend witnesses
        let mut spend_witnesses = Vec::new();
        let mut spent_commitments = Vec::new();

        for note in &notes_to_spend {
            let merkle_witness = witnesses.get(&note.position).cloned().ok_or_else(|| {
                FaucetError::TransactionError(format!(
                    "Could not get witness for position {}",
                    note.position
                ))
            })?;

            spend_witnesses.push(SpendWitnessPQ {
                value: note.value,
                recipient_pk_hash: note.pk_hash,
                randomness: note.randomness,
                nullifier_key: self.nullifier_key,
                position: note.position,
                merkle_witness,
            });

            spent_commitments.push(note.commitment);
        }

        // Build output witnesses
        let mut rng = rand::thread_rng();
        let mut output_witnesses = Vec::new();

        // Output to recipient
        let mut recipient_randomness = [0u8; 32];
        rng.fill_bytes(&mut recipient_randomness);
        output_witnesses.push(OutputWitnessPQ {
            value: claim_amount,
            recipient_pk_hash,
            randomness: recipient_randomness,
        });

        // Change output back to faucet (if any)
        let mut change_randomness = [0u8; 32];
        if change > 0 {
            rng.fill_bytes(&mut change_randomness);
            output_witnesses.push(OutputWitnessPQ {
                value: change,
                recipient_pk_hash: self.pk_hash,
                randomness: change_randomness,
            });
        }

        // Generate proof
        info!("Generating Plonky2 proof for faucet game transaction...");
        let proof = self
            .prover
            .prove(&spend_witnesses, &output_witnesses, fee)
            .map_err(|e| FaucetError::ProofError(e.to_string()))?;
        info!("Proof generated: {} bytes", proof.size());

        // Build transaction
        let tx = self.build_transaction(
            &spend_witnesses,
            &output_witnesses,
            fee,
            proof,
            recipient_pk_hash,
            recipient_randomness,
            if change > 0 { Some(change_randomness) } else { None },
        )?;

        let tx_hash = hex::encode(tx.hash());

        // Mark notes as spent
        for commitment in spent_commitments {
            self.mark_spent(&commitment);
        }

        // Update claim record
        let today = Self::today_date();
        let yesterday = Self::yesterday_date();
        let new_streak = match &existing_claim {
            Some(c) => {
                if c.last_streak_date == yesterday {
                    c.streak + 1
                } else if c.last_streak_date == today {
                    c.streak
                } else {
                    1
                }
            }
            None => 1,
        };

        let new_total = existing_claim
            .as_ref()
            .map(|c| c.total_claimed)
            .unwrap_or(0)
            .saturating_add(claim_amount);

        let updated_claim = FaucetClaim {
            last_claim_timestamp: now,
            total_claimed: new_total,
            streak: new_streak,
            last_streak_date: today,
        };

        self.db
            .save_faucet_claim(&recipient_pk_hash, &updated_claim)
            .map_err(|e| FaucetError::Database(e.to_string()))?;

        info!(
            "Faucet game claim processed: {} -> {} tokens, streak={}, total={}",
            &pk_hash_hex[..16],
            tokens_collected,
            new_streak,
            Self::format_amount(new_total)
        );

        let message = if tokens_collected == FAUCET_MAX_TOKENS {
            format!("Perfect game! All {} tokens collected!", tokens_collected)
        } else if tokens_collected >= 7 {
            format!("Great run! {} tokens collected!", tokens_collected)
        } else {
            format!("Collected {} tokens!", tokens_collected)
        };

        Ok((
            ClaimResult {
                success: true,
                tx_hash,
                amount: Self::format_amount(claim_amount),
                new_streak,
                message,
            },
            tx,
        ))
    }

    /// Get public faucet statistics.
    pub fn get_stats(&self) -> Result<FaucetStats, FaucetError> {
        let total_distributed = self
            .db
            .get_faucet_total_distributed()
            .map_err(|e| FaucetError::Database(e.to_string()))?;

        let unique_claimants = self
            .db
            .get_faucet_claimant_count()
            .map_err(|e| FaucetError::Database(e.to_string()))?;

        let active_streaks = self
            .db
            .get_faucet_active_streaks()
            .map_err(|e| FaucetError::Database(e.to_string()))?;

        let balance = self.balance();
        let balance_str = if balance < FAUCET_LOW_BALANCE_THRESHOLD {
            Some(Self::format_amount(balance))
        } else {
            None
        };

        Ok(FaucetStats {
            total_distributed: Self::format_amount(total_distributed),
            unique_claimants,
            active_streaks,
            balance: balance_str,
            enabled: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_amount() {
        assert_eq!(FaucetService::format_amount(50_000_000_000), "50.0 TSN");
        assert_eq!(
            FaucetService::format_amount(1_500_000_000),
            "1.500000000 TSN"
        );
        assert_eq!(FaucetService::format_amount(0), "0.0 TSN");
    }

    #[test]
    fn test_parse_pk_hash() {
        let valid = "0".repeat(64);
        assert!(FaucetService::parse_pk_hash(&valid).is_ok());

        let invalid_length = "0".repeat(63);
        assert!(FaucetService::parse_pk_hash(&invalid_length).is_err());

        let invalid_hex = "g".repeat(64);
        assert!(FaucetService::parse_pk_hash(&invalid_hex).is_err());
    }

    #[test]
    fn test_date_functions() {
        let today = FaucetService::today_date();
        let yesterday = FaucetService::yesterday_date();
        assert_ne!(today, yesterday);
        assert_eq!(today.len(), 10);
        assert_eq!(yesterday.len(), 10);
    }
}
