/**
 * Shielded wallet state management.
 *
 * Handles note scanning, balance tracking, and note selection for spending.
 * Persists state to localStorage for resumable scanning.
 */

import {
  deriveViewingKey,
  deriveNullifierKey,
  computePkHash,
  tryDecryptNoteFromHex,
  deriveNullifier,
  initPoseidon,
} from './shielded-crypto';
import { hexToBytes, bytesToHex } from './crypto';
import { getOutputsSince, checkNullifiers } from './api';
import { loadProvingKeys, areProvingKeysLoaded } from './prover';
import { initBindingCrypto, isBindingCryptoReady } from './binding';
import { deriveNullifierPQ, initPQCrypto, isPQCryptoInitialized } from './commitment-pq';
import { getWorkerPool, isWorkerSupported } from './scan-worker-pool';
import type { WalletNote, ShieldedState, EncryptedOutput } from './types';

/** Whether cryptographic primitives have been initialized */
let cryptoInitialized = false;

const STORAGE_KEY = 'tsn_shielded_state';

/**
 * Shielded wallet for managing private notes and balances.
 */
export class ShieldedWallet {
  /** Viewing key for decrypting notes */
  viewingKey: Uint8Array;
  /** Nullifier key for computing nullifiers */
  nullifierKey: Uint8Array;
  /** Public key hash (recipient identifier) */
  pkHash: Uint8Array;
  /** Full public key (for verification) */
  publicKey: Uint8Array;
  /** All known notes */
  notes: WalletNote[];
  /** Last scanned block height */
  lastScannedHeight: number;
  /** Wallet birthday (block height when created) - scan starts from here */
  birthday: number = 0;
  /** Scanning state */
  private scanning: boolean = false;

  constructor(secretKey: Uint8Array, publicKey: Uint8Array) {
    this.viewingKey = deriveViewingKey(secretKey);
    this.nullifierKey = deriveNullifierKey(secretKey);
    this.pkHash = computePkHash(publicKey);
    this.publicKey = publicKey;
    this.notes = [];
    this.lastScannedHeight = -1;

    // Load persisted state
    this.loadState();
  }

  /**
   * Create a ShieldedWallet from hex-encoded keys.
   */
  static fromHex(secretKeyHex: string, publicKeyHex: string): ShieldedWallet {
    return new ShieldedWallet(hexToBytes(secretKeyHex), hexToBytes(publicKeyHex));
  }

  /**
   * Initialize cryptographic primitives required for the shielded wallet.
   * Must be called before using note commitments, nullifiers, or creating transactions.
   *
   * @param loadProver - If true, also loads ZK proving keys (required for transactions)
   * @param onProgress - Optional callback for progress updates
   */
  static async initialize(
    loadProver: boolean = false,
    onProgress?: (msg: string) => void
  ): Promise<void> {
    if (!cryptoInitialized) {
      onProgress?.('Initializing Poseidon hash...');
      await initPoseidon();
      cryptoInitialized = true;
    }

    // Initialize PQ crypto (WASM Poseidon for V2 notes)
    if (!isPQCryptoInitialized()) {
      onProgress?.('Initializing PQ crypto (Plonky2 Poseidon)...');
      await initPQCrypto();
    }

    if (loadProver && !areProvingKeysLoaded()) {
      onProgress?.('Loading ZK proving keys (~100-200MB)...');
      await loadProvingKeys();
      onProgress?.('Proving keys loaded.');
    }

    if (loadProver && !isBindingCryptoReady()) {
      onProgress?.('Initializing binding crypto (BN254)...');
      await initBindingCrypto();
      onProgress?.('Binding crypto ready.');
    }
  }

  /**
   * Check if cryptographic primitives are initialized.
   */
  static get isInitialized(): boolean {
    return cryptoInitialized;
  }

  /**
   * Check if ZK proving keys are loaded (required for creating transactions).
   */
  static get isProverReady(): boolean {
    return areProvingKeysLoaded();
  }

  /**
   * Get the public key hash as hex string (for sharing with senders).
   */
  get pkHashHex(): string {
    return bytesToHex(this.pkHash);
  }

  /**
   * Get the total balance of unspent notes.
   */
  get balance(): bigint {
    return this.notes
      .filter((n) => !n.spent)
      .reduce((sum, n) => sum + n.value, 0n);
  }

  /**
   * Get the number of unspent notes.
   */
  get unspentCount(): number {
    return this.notes.filter((n) => !n.spent).length;
  }

  /**
   * Get all unspent notes.
   */
  get unspentNotes(): WalletNote[] {
    return this.notes.filter((n) => !n.spent);
  }

  /**
   * Check if currently scanning.
   */
  get isScanning(): boolean {
    return this.scanning;
  }

  /**
   * Scan the blockchain for incoming notes.
   * Fetches all outputs since lastScannedHeight and attempts decryption.
   * Uses parallel Web Workers when available for faster scanning.
   */
  async scan(onProgress?: (msg: string) => void): Promise<number> {
    if (this.scanning) {
      return 0;
    }

    this.scanning = true;
    let newNotesFound = 0;

    try {
      // First, check current chain height to detect chain resets
      const initialResponse = await getOutputsSince(0);
      const current_height = initialResponse.current_height;

      // Detect chain reset: if chain height is lower than our last scanned height,
      // the chain was reset and we need to clear our state and rescan from 0
      if (this.lastScannedHeight > current_height) {
        onProgress?.(`Chain reset detected (height ${current_height} < last scanned ${this.lastScannedHeight}). Rescanning from genesis...`);
        this.notes = [];
        this.lastScannedHeight = -1;
      }

      // API expects unsigned height
      // When sinceHeight=0, API returns ALL outputs including genesis
      // When sinceHeight>0, API returns outputs from sinceHeight+1 onwards
      // Use birthday for first scan to skip old outputs (wallet can't have notes before creation)
      let sinceHeight: number;
      if (this.lastScannedHeight < 0) {
        // First scan - use birthday if set, otherwise scan from genesis
        sinceHeight = this.birthday > 0 ? this.birthday - 1 : 0;
        if (this.birthday > 0) {
          onProgress?.(`Using wallet birthday: starting from height ${this.birthday}`);
        }
      } else {
        sinceHeight = this.lastScannedHeight;
      }

      onProgress?.(`Fetching outputs since height ${sinceHeight}...`);

      // Use the initial response if scanning from 0, otherwise fetch again
      const response = sinceHeight === 0 ? initialResponse : await getOutputsSince(sinceHeight);
      const { outputs } = response;

      // Use parallel scanning with Web Workers if available and enough outputs
      const useParallel = isWorkerSupported() && outputs.length > 100;

      if (useParallel) {
        newNotesFound = await this.scanParallel(outputs, onProgress);
      } else {
        newNotesFound = this.scanSequential(outputs, onProgress);
      }

      this.lastScannedHeight = current_height;

      // Check for spent notes
      onProgress?.('Checking for spent notes...');
      await this.checkSpent();

      // Persist state
      this.saveState();

      onProgress?.(`Scan complete. Found ${newNotesFound} new notes.`);
    } finally {
      this.scanning = false;
    }

    return newNotesFound;
  }

  /**
   * Sequential scanning (fallback when workers unavailable).
   */
  private scanSequential(outputs: EncryptedOutput[], onProgress?: (msg: string) => void): number {
    let newNotesFound = 0;
    onProgress?.(`Processing ${outputs.length} outputs (sequential)...`);

    for (const output of outputs) {
      const note = this.tryDecryptOutput(output);
      if (note) {
        const existing = this.notes.find((n) => n.commitment === note.commitment);
        if (!existing) {
          this.notes.push(note);
          newNotesFound++;
          onProgress?.(`Found note: ${this.formatValue(note.value)} TSN at height ${note.blockHeight}`);
        }
        this.maybeAddV2Note(output, note);
      } else {
        this.maybeAddV2OnlyNote(output);
      }
    }

    return newNotesFound;
  }

  /**
   * Parallel scanning using Web Workers.
   */
  private async scanParallel(outputs: EncryptedOutput[], onProgress?: (msg: string) => void): Promise<number> {
    let newNotesFound = 0;

    try {
      const pool = await getWorkerPool();
      onProgress?.(`Processing ${outputs.length} outputs (parallel, ${pool.size} workers)...`);

      // Convert outputs for worker
      const workerOutputs = outputs.map((o) => ({
        ciphertext: o.ciphertext,
        ephemeral_pk: o.ephemeral_pk,
        note_commitment: o.note_commitment,
        position: typeof o.position === 'bigint' ? Number(o.position) : o.position,
        block_height: o.block_height,
      }));

      // Run parallel scan
      const decryptedNotes = await pool.scan(
        workerOutputs,
        this.pkHashHex,
        bytesToHex(this.nullifierKey),
        (processed, total) => {
          const pct = Math.round((processed / total) * 100);
          onProgress?.(`Scanning: ${pct}% (${processed}/${total})`);
        }
      );

      // Process results
      for (const note of decryptedNotes) {
        const existing = this.notes.find((n) => n.commitment === note.commitment);
        if (!existing) {
          this.notes.push({
            value: BigInt(note.value),
            recipientPkHash: note.recipientPkHash,
            randomness: note.randomness,
            commitment: note.commitment,
            position: BigInt(note.position),
            blockHeight: note.blockHeight,
            spent: false,
            nullifier: note.nullifier,
          });
          newNotesFound++;
          onProgress?.(`Found note: ${this.formatValue(BigInt(note.value))} TSN at height ${note.blockHeight}`);
        }
      }

      // Process V2 notes (still need to do this on main thread for now)
      // TODO: Move V2 scanning to workers as well
      for (const output of outputs) {
        const existingNote = this.notes.find((n) => n.commitment === output.note_commitment);
        if (existingNote) {
          this.maybeAddV2Note(output, existingNote);
        } else {
          this.maybeAddV2OnlyNote(output);
        }
      }
    } catch (error) {
      // Fall back to sequential on error
      console.warn('Parallel scan failed, falling back to sequential:', error);
      return this.scanSequential(outputs, onProgress);
    }

    return newNotesFound;
  }

  /**
   * Try to decrypt an encrypted output.
   * Returns a WalletNote if successful, null otherwise.
   */
  private tryDecryptOutput(output: EncryptedOutput): WalletNote | null {
    // Skip V2-only outputs that don't have a V1 commitment
    // (they can only be processed by the V2 wallet via maybeAddV2Note)
    if (!output.note_commitment || output.note_commitment.length === 0) {
      return null;
    }

    const decrypted = tryDecryptNoteFromHex(
      output.ciphertext,
      output.ephemeral_pk,
      this.pkHash  // Use pkHash for decryption (matches encryption key)
    );

    if (!decrypted) {
      return null;
    }

    // Verify the note is for our pk_hash
    const recipientPkHashHex = bytesToHex(decrypted.recipientPkHash);
    if (recipientPkHashHex !== this.pkHashHex) {
      // Note is not for us (decryption succeeded but it's for a different recipient)
      return null;
    }

    // Use the commitment from the blockchain (already verified by consensus)
    // We derive nullifier using the commitment bytes from the chain
    const commitmentBytes = hexToBytes(output.note_commitment);
    const nullifier = deriveNullifier(
      this.nullifierKey,
      commitmentBytes,
      BigInt(output.position)
    );

    return {
      value: decrypted.value,
      recipientPkHash: recipientPkHashHex,
      randomness: bytesToHex(decrypted.randomness),
      commitment: output.note_commitment,
      position: BigInt(output.position),
      blockHeight: output.block_height,
      spent: false,
      nullifier: bytesToHex(nullifier),
    };
  }

  /**
   * Hook for subclasses to add V2 notes when scanning.
   * Default implementation does nothing.
   */
  protected maybeAddV2Note(_output: EncryptedOutput, _note: WalletNote): void {
    // Base class does nothing - V2 wallet overrides this
  }

  /**
   * Hook for subclasses to process V2-only outputs (no V1 commitment).
   * Default implementation does nothing.
   */
  protected maybeAddV2OnlyNote(_output: EncryptedOutput): void {
    // Base class does nothing - V2 wallet overrides this
  }

  /**
   * Check which of our notes have been spent.
   */
  async checkSpent(): Promise<void> {
    const unspentNotes = this.notes.filter((n) => !n.spent && n.nullifier);

    if (unspentNotes.length === 0) {
      return;
    }

    const nullifiers = unspentNotes.map((n) => n.nullifier!);
    const response = await checkNullifiers(nullifiers);

    for (const spentNf of response.spent) {
      const note = this.notes.find((n) => n.nullifier === spentNf);
      if (note) {
        note.spent = true;
      }
    }

    this.saveState();
  }

  /**
   * Select notes for spending a given amount.
   * Uses a greedy algorithm: largest notes first until we have enough.
   */
  selectNotes(amount: bigint): WalletNote[] {
    const available = this.unspentNotes.sort((a, b) =>
      a.value > b.value ? -1 : a.value < b.value ? 1 : 0
    );

    const selected: WalletNote[] = [];
    let total = 0n;

    for (const note of available) {
      if (total >= amount) {
        break;
      }
      selected.push(note);
      total += note.value;
    }

    if (total < amount) {
      throw new Error(`Insufficient balance: have ${total}, need ${amount}`);
    }

    return selected;
  }

  /**
   * Format a value for display (convert from smallest units to TSN).
   */
  formatValue(value: bigint): string {
    const DECIMALS = 9;
    const divisor = 10n ** BigInt(DECIMALS);
    const whole = value / divisor;
    const frac = value % divisor;
    const fracStr = frac.toString().padStart(DECIMALS, '0').replace(/0+$/, '');
    return fracStr ? `${whole}.${fracStr}` : whole.toString();
  }

  /**
   * Parse a TSN amount string to smallest units.
   */
  static parseAmount(amountStr: string): bigint {
    const DECIMALS = 9;
    const parts = amountStr.split('.');
    const whole = BigInt(parts[0] || '0');
    const fracStr = (parts[1] || '').padEnd(DECIMALS, '0').slice(0, DECIMALS);
    const frac = BigInt(fracStr);
    return whole * 10n ** BigInt(DECIMALS) + frac;
  }

  /**
   * Load persisted state from localStorage.
   */
  private loadState(): void {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const state: ShieldedState = JSON.parse(stored, (key, value) => {
          // Convert position and value back to bigint
          if (key === 'position' || key === 'value') {
            return BigInt(value);
          }
          return value;
        });

        this.notes = state.notes;
        this.lastScannedHeight = state.lastScannedHeight;
      }
    } catch (e) {
      console.error('Failed to load shielded state:', e);
    }
  }

  /**
   * Save state to localStorage.
   */
  private saveState(): void {
    try {
      const state: ShieldedState = {
        notes: this.notes,
        lastScannedHeight: this.lastScannedHeight,
      };

      // Custom serialization to handle bigint
      const json = JSON.stringify(state, (_, value) => {
        if (typeof value === 'bigint') {
          return value.toString();
        }
        return value;
      });

      localStorage.setItem(STORAGE_KEY, json);
    } catch (e) {
      console.error('Failed to save shielded state:', e);
    }
  }

  /**
   * Clear all wallet state.
   */
  clearState(): void {
    this.notes = [];
    this.lastScannedHeight = -1;
    localStorage.removeItem(STORAGE_KEY);
  }

  /**
   * Get a summary of the wallet state.
   */
  getSummary(): {
    balance: string;
    balanceRaw: bigint;
    unspentCount: number;
    totalNotes: number;
    spentNotes: number;
    lastScannedHeight: number;
  } {
    return {
      balance: this.formatValue(this.balance),
      balanceRaw: this.balance,
      unspentCount: this.unspentCount,
      totalNotes: this.notes.length,
      spentNotes: this.notes.filter((n) => n.spent).length,
      lastScannedHeight: this.lastScannedHeight,
    };
  }
}

/**
 * Hook to use ShieldedWallet in React components.
 */
export function createShieldedWallet(secretKeyHex: string, publicKeyHex: string): ShieldedWallet {
  return ShieldedWallet.fromHex(secretKeyHex, publicKeyHex);
}

// ============================================================================
// V2 (Post-Quantum) Note Support
// ============================================================================

import { type V2Note, getMigrationStats } from './migration';

/**
 * Extended wallet note type supporting both V1 and V2.
 */
export type AnyWalletNote = WalletNote | V2Note;

/**
 * Extended shielded state supporting V2 notes.
 */
export interface ShieldedStateV2 extends ShieldedState {
  v2Notes?: V2Note[];
}

/**
 * Extended ShieldedWallet with V2 (post-quantum) support.
 */
export class ShieldedWalletV2 extends ShieldedWallet {
  /** V2 notes (post-quantum) */
  v2Notes: V2Note[] = [];

  constructor(secretKey: Uint8Array, publicKey: Uint8Array) {
    super(secretKey, publicKey);
    this.loadV2State();
  }

  /**
   * Create from hex-encoded keys.
   */
  static fromHexV2(secretKeyHex: string, publicKeyHex: string): ShieldedWalletV2 {
    return new ShieldedWalletV2(hexToBytes(secretKeyHex), hexToBytes(publicKeyHex));
  }

  /**
   * Get total balance including both V1 and V2 notes.
   */
  get totalBalance(): bigint {
    const v1Balance = this.balance;
    const v2Balance = this.v2Notes
      .filter((n) => !n.spent)
      .reduce((sum, n) => sum + n.value, 0n);
    return v1Balance + v2Balance;
  }

  /**
   * Get V1 (legacy) balance only.
   */
  get v1Balance(): bigint {
    return this.balance;
  }

  /**
   * Get V2 (post-quantum) balance only.
   */
  get v2Balance(): bigint {
    return this.v2Notes
      .filter((n) => !n.spent)
      .reduce((sum, n) => sum + n.value, 0n);
  }

  /**
   * Get number of unspent V2 notes.
   */
  get unspentV2Count(): number {
    return this.v2Notes.filter((n) => !n.spent).length;
  }

  /**
   * Get all unspent V2 notes.
   */
  get unspentV2Notes(): V2Note[] {
    return this.v2Notes.filter((n) => !n.spent);
  }

  /**
   * Get all notes (V1 and V2 combined).
   */
  get allNotes(): AnyWalletNote[] {
    return [...this.notes, ...this.v2Notes];
  }

  /**
   * Get all unspent notes (V1 and V2 combined).
   */
  get allUnspentNotes(): AnyWalletNote[] {
    return [
      ...this.notes.filter((n) => !n.spent),
      ...this.v2Notes.filter((n) => !n.spent),
    ];
  }

  /**
   * Get migration statistics.
   */
  get migrationStats() {
    return getMigrationStats(this.allNotes);
  }

  /**
   * Check if wallet needs migration (has V1 notes).
   */
  get needsMigration(): boolean {
    return this.migrationStats.migrationNeeded;
  }

  /**
   * Select V1 notes for spending (legacy transactions).
   */
  selectV1Notes(amount: bigint): WalletNote[] {
    return this.selectNotes(amount);
  }

  /**
   * Select V2 notes for spending (post-quantum transactions).
   */
  selectV2Notes(amount: bigint): V2Note[] {
    const available = this.unspentV2Notes.sort((a, b) =>
      a.value > b.value ? -1 : a.value < b.value ? 1 : 0
    );

    const selected: V2Note[] = [];
    let total = 0n;

    for (const note of available) {
      if (total >= amount) {
        break;
      }
      selected.push(note);
      total += note.value;
    }

    if (total < amount) {
      throw new Error(`Insufficient V2 balance: have ${total}, need ${amount}`);
    }

    return selected;
  }

  /**
   * Select notes for spending, preferring V2 (post-quantum) notes.
   */
  selectNotesPreferV2(amount: bigint): { v1Notes: WalletNote[]; v2Notes: V2Note[] } {
    // First try to fulfill from V2 notes only
    if (this.v2Balance >= amount) {
      return {
        v1Notes: [],
        v2Notes: this.selectV2Notes(amount),
      };
    }

    // Then try V2 + V1 combined
    const v2Notes = this.unspentV2Notes;
    const v2Total = v2Notes.reduce((sum, n) => sum + n.value, 0n);
    const remaining = amount - v2Total;

    if (remaining > 0n && this.v1Balance >= remaining) {
      return {
        v1Notes: this.selectV1Notes(remaining),
        v2Notes,
      };
    }

    // Not enough funds
    throw new Error(
      `Insufficient total balance: have ${this.totalBalance}, need ${amount}`
    );
  }

  /**
   * Add a V2 note (e.g., after migration or receiving).
   */
  addV2Note(note: V2Note): void {
    // Check if we already have this note
    const existing = this.v2Notes.find((n) => n.commitment === note.commitment);
    if (!existing) {
      this.v2Notes.push(note);
      this.saveV2State();
    }
  }

  /**
   * Override to also create V2 notes when scanning.
   */
  protected override maybeAddV2Note(output: EncryptedOutput, note: WalletNote): void {
    // Only process if V2/PQ commitment is available
    if (!output.note_commitment_pq || output.note_commitment_pq.length === 0) {
      return;
    }

    // Check if we already have this V2 note
    const existing = this.v2Notes.find((n) => n.commitment === output.note_commitment_pq);
    if (existing) {
      return;
    }

    // Derive V2 nullifier using the V2/PQ commitment
    const commitmentPqBytes = hexToBytes(output.note_commitment_pq);
    const nullifierPq = deriveNullifierPQ(this.nullifierKey, commitmentPqBytes, BigInt(output.position));

    this.v2Notes.push({
      value: note.value,
      recipientPkHash: note.recipientPkHash,
      randomness: note.randomness,
      commitment: output.note_commitment_pq,  // Use V2/PQ commitment
      position: BigInt(output.position),
      blockHeight: output.block_height,
      spent: false,
      nullifier: bytesToHex(nullifierPq),
      version: 2,
    });

    this.saveV2State();
  }

  /**
   * Process V2-only outputs (no V1 commitment).
   * These come from pure V2 transactions.
   */
  protected override maybeAddV2OnlyNote(output: EncryptedOutput): void {
    // Only process if V2/PQ commitment is available
    if (!output.note_commitment_pq || output.note_commitment_pq.length === 0) {
      return;
    }

    // Try to decrypt the note
    const decrypted = tryDecryptNoteFromHex(
      output.ciphertext,
      output.ephemeral_pk,
      this.pkHash
    );

    if (!decrypted) {
      return;
    }

    // Verify the note is for our pk_hash
    const recipientPkHashHex = bytesToHex(decrypted.recipientPkHash);
    if (recipientPkHashHex !== this.pkHashHex) {
      return;
    }

    // Check if we already have this V2 note
    const existing = this.v2Notes.find((n) => n.commitment === output.note_commitment_pq);
    if (existing) {
      return;
    }

    // Derive V2 nullifier using the V2/PQ commitment
    const commitmentPqBytes = hexToBytes(output.note_commitment_pq);
    const nullifierPq = deriveNullifierPQ(this.nullifierKey, commitmentPqBytes, BigInt(output.position));

    this.v2Notes.push({
      value: decrypted.value,
      recipientPkHash: recipientPkHashHex,
      randomness: bytesToHex(decrypted.randomness),
      commitment: output.note_commitment_pq,
      position: BigInt(output.position),
      blockHeight: output.block_height,
      spent: false,
      nullifier: bytesToHex(nullifierPq),
      version: 2,
    });

    this.saveV2State();
  }

  /**
   * Mark V2 notes as spent.
   */
  markV2NotesSpent(nullifiers: string[]): void {
    for (const nf of nullifiers) {
      const note = this.v2Notes.find((n) => n.nullifier === nf);
      if (note) {
        note.spent = true;
      }
    }
    this.saveV2State();
  }

  /**
   * Check which V2 notes have been spent.
   */
  async checkSpentV2(): Promise<void> {
    const unspentV2Notes = this.v2Notes.filter((n) => !n.spent && n.nullifier);

    if (unspentV2Notes.length === 0) {
      return;
    }

    const nullifiers = unspentV2Notes.map((n) => n.nullifier!);
    const response = await checkNullifiers(nullifiers);

    for (const spentNf of response.spent) {
      const note = this.v2Notes.find((n) => n.nullifier === spentNf);
      if (note) {
        note.spent = true;
      }
    }

    this.saveV2State();
  }

  /**
   * Override scan to also check V2 spent status.
   */
  override async scan(onProgress?: (msg: string) => void): Promise<number> {
    const result = await super.scan(onProgress);

    // Also check V2 nullifiers for spent status
    onProgress?.('Checking V2 spent notes...');
    await this.checkSpentV2();

    return result;
  }

  /**
   * Load V2 state from localStorage.
   */
  private loadV2State(): void {
    try {
      const stored = localStorage.getItem('tsn_shielded_state_v2');
      if (stored) {
        const state = JSON.parse(stored, (key, value) => {
          if (key === 'position' || key === 'value') {
            return BigInt(value);
          }
          return value;
        });
        this.v2Notes = state.v2Notes || [];
      }
    } catch (e) {
      console.error('Failed to load V2 shielded state:', e);
    }
  }

  /**
   * Save V2 state to localStorage.
   */
  private saveV2State(): void {
    try {
      const json = JSON.stringify(
        { v2Notes: this.v2Notes },
        (_, value) => {
          if (typeof value === 'bigint') {
            return value.toString();
          }
          return value;
        }
      );
      localStorage.setItem('tsn_shielded_state_v2', json);
    } catch (e) {
      console.error('Failed to save V2 shielded state:', e);
    }
  }

  /**
   * Clear all V2 state.
   */
  clearV2State(): void {
    this.v2Notes = [];
    localStorage.removeItem('tsn_shielded_state_v2');
  }

  /**
   * Clear V2 state and rescan to recompute nullifiers.
   *
   * Use this when nullifier computation has been fixed and you need
   * to recompute nullifiers for existing V2 notes.
   */
  async rescanV2Notes(onProgress?: (msg: string) => void): Promise<number> {
    onProgress?.('Clearing all state for full rescan...');

    // Clear all state (V1 + V2) to force full rescan
    this.clearState();

    onProgress?.('Rescanning blockchain for all notes...');
    const notesFound = await this.scan(onProgress);

    onProgress?.(`Rescan complete. Found ${this.v2Notes.length} V2 notes.`);
    return notesFound;
  }

  /**
   * Clear all state (V1 and V2).
   */
  override clearState(): void {
    super.clearState();
    this.clearV2State();
  }

  /**
   * Get extended summary including V2 stats.
   */
  getExtendedSummary(): {
    v1Balance: string;
    v2Balance: string;
    totalBalance: string;
    v1UnspentCount: number;
    v2UnspentCount: number;
    needsMigration: boolean;
    lastScannedHeight: number;
  } {
    return {
      v1Balance: this.formatValue(this.v1Balance),
      v2Balance: this.formatValue(this.v2Balance),
      totalBalance: this.formatValue(this.totalBalance),
      v1UnspentCount: this.unspentCount,
      v2UnspentCount: this.unspentV2Count,
      needsMigration: this.needsMigration,
      lastScannedHeight: this.lastScannedHeight,
    };
  }
}

/**
 * Create a V2-enabled shielded wallet.
 */
export function createShieldedWalletV2(
  secretKeyHex: string,
  publicKeyHex: string
): ShieldedWalletV2 {
  return ShieldedWalletV2.fromHexV2(secretKeyHex, publicKeyHex);
}
