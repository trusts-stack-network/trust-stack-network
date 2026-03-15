/**
 * UTXO Coalescing for Plonky2 transactions.
 *
 * The Plonky2 circuit only supports transactions with at most 2 spends.
 * When a transaction requires more spends, we need to first coalesce
 * (consolidate) UTXOs down to 2 or fewer.
 *
 * Coalescing works by creating (2,1) transactions that combine 2 notes
 * into 1, repeated until we have few enough notes.
 *
 * Example: 4 notes → 2 coalesce txs → 2 notes → final tx
 */

import type { V2Note } from './migration';
import type { WalletNote } from './types';
import {
  createShieldedTransactionV2,
  estimateFeeV2,
  type ShieldedTransactionV2,
} from './transaction-builder';
import { submitShieldedTransactionV2 } from './api';
import { bytesToHex, hexToBytes } from './crypto';
import { generateRandomnessPQ, deriveNullifierPQ } from './commitment-pq';
import { deriveNullifierKey } from './shielded-crypto';

/** Maximum spends supported by the Plonky2 circuit */
export const MAX_SPENDS = 10;

/** Maximum outputs supported by the Plonky2 circuit */
export const MAX_OUTPUTS = 4;

/**
 * Default spends limit for coalescing.
 * Set to 5 to match the default warmup range (1-5 spends).
 * This ensures no circuit building delay for typical transactions.
 */
export const DEFAULT_COALESCE_TARGET = 5;

/**
 * Result of a coalesce operation.
 */
export interface CoalesceResult {
  /** The coalescing transactions created */
  transactions: ShieldedTransactionV2[];
  /** The resulting coalesced notes (to be used for the final transaction) */
  coalescedNotes: V2Note[];
  /** Total fees paid for coalescing */
  totalFees: bigint;
  /** Number of coalescing transactions created */
  numTransactions: number;
}

/**
 * Parameters for coalescing.
 */
export interface CoalesceParams {
  /** Notes to coalesce */
  notes: V2Note[];
  /** Secret key for signing */
  secretKey: Uint8Array;
  /** Public key */
  publicKey: Uint8Array;
  /** Sender's pk_hash (change goes here) */
  senderPkHash: Uint8Array;
  /** Target number of notes after coalescing (default: MAX_SPENDS) */
  targetCount?: number;
  /** Progress callback */
  onProgress?: (msg: string) => void;
  /** Whether to submit transactions immediately (default: true) */
  submitImmediately?: boolean;
  /** Callback after each transaction is submitted and confirmed */
  onTransactionConfirmed?: (note: V2Note, txIndex: number) => void;
}

/**
 * Check if coalescing is needed for a transaction.
 *
 * @param numSpends - Number of spends in the planned transaction
 * @returns true if coalescing is needed
 */
export function needsCoalescing(numSpends: number): boolean {
  return numSpends > MAX_SPENDS;
}

/**
 * Calculate how many coalescing transactions are needed.
 *
 * With (2,1) coalescing:
 * - 3 notes → 1 tx (2→1) + 2 notes left = can do final tx
 * - 4 notes → 2 txs (2→1 each) = 2 notes = can do final tx
 * - 5 notes → need to get to 2: (2→1), (2→1), then have 3, need another (2→1) = 3 txs
 *
 * General formula: ceil(n - MAX_SPENDS) coalescing transactions
 * Each reduces count by 1 (2 notes become 1)
 */
export function calculateCoalescingTxCount(numNotes: number, targetCount: number = MAX_SPENDS): number {
  if (numNotes <= targetCount) return 0;
  // Each coalesce tx reduces note count by 1 (2→1)
  return numNotes - targetCount;
}

/**
 * Estimate total fees for coalescing.
 *
 * @param numNotes - Number of notes to coalesce
 * @param targetCount - Target number of notes
 * @returns Estimated total fees
 */
export function estimateCoalescingFees(numNotes: number, targetCount: number = MAX_SPENDS): bigint {
  const numTxs = calculateCoalescingTxCount(numNotes, targetCount);
  // Each coalescing tx is (2,1)
  const feePerTx = estimateFeeV2(2, 1);
  return feePerTx * BigInt(numTxs);
}

/**
 * Coalesce notes down to a target count.
 *
 * This creates and optionally submits coalescing transactions to combine
 * multiple notes into fewer notes, making them usable in a single transaction.
 *
 * @param params - Coalescing parameters
 * @returns Result with transactions and resulting notes
 */
export async function coalesceNotes(params: CoalesceParams): Promise<CoalesceResult> {
  const {
    notes,
    secretKey,
    publicKey,
    senderPkHash,
    targetCount = MAX_SPENDS,
    onProgress,
    submitImmediately = true,
    onTransactionConfirmed,
  } = params;

  const progress = (msg: string) => {
    console.log('[Coalesce]', msg);
    onProgress?.(msg);
  };

  if (notes.length <= targetCount) {
    progress(`No coalescing needed: ${notes.length} notes ≤ ${targetCount} target`);
    return {
      transactions: [],
      coalescedNotes: notes,
      totalFees: 0n,
      numTransactions: 0,
    };
  }

  const numTxs = calculateCoalescingTxCount(notes.length, targetCount);
  progress(`Coalescing ${notes.length} notes to ${targetCount} (requires ${numTxs} transactions)`);

  const transactions: ShieldedTransactionV2[] = [];
  let workingNotes = [...notes];
  let totalFees = 0n;

  // Sort by value (smallest first) to coalesce smallest notes first
  // This leaves larger notes for the final transaction
  workingNotes.sort((a, b) => (a.value < b.value ? -1 : a.value > b.value ? 1 : 0));

  for (let txIdx = 0; txIdx < numTxs; txIdx++) {
    progress(`Creating coalesce transaction ${txIdx + 1}/${numTxs}...`);

    // Take the 2 smallest notes
    const notesToCoalesce = workingNotes.splice(0, 2);
    const totalValue = notesToCoalesce.reduce((sum, n) => sum + n.value, 0n);
    const fee = estimateFeeV2(2, 1);
    const outputValue = totalValue - fee;

    if (outputValue <= 0n) {
      throw new Error(
        `Coalescing fee (${fee}) exceeds value of notes being coalesced (${totalValue}). ` +
        `Consider using larger notes or consolidating proactively when fees are lower.`
      );
    }

    totalFees += fee;

    // Convert V2Note to WalletNote format for transaction builder
    const spendNotes = notesToCoalesce.map(n => ({
      value: n.value,
      recipientPkHash: n.recipientPkHash,
      randomness: n.randomness,
      commitment: n.commitment,
      position: n.position,
      blockHeight: n.blockHeight,
      spent: n.spent,
      nullifier: n.nullifier,
    })) as WalletNote[];

    // Create coalescing transaction (self-send)
    const tx = await createShieldedTransactionV2({
      spendNotes,
      recipients: [{ pkHash: bytesToHex(senderPkHash), amount: outputValue }],
      fee,
      secretKey,
      publicKey,
      senderPkHash,
      onProgress: (msg) => progress(`  [tx ${txIdx + 1}] ${msg}`),
    });

    transactions.push(tx);

    if (submitImmediately) {
      progress(`Submitting coalesce transaction ${txIdx + 1}/${numTxs}...`);

      // Submit and wait for confirmation
      const response = await submitShieldedTransactionV2(tx);

      if ('error' in response) {
        throw new Error(`Coalesce transaction ${txIdx + 1} failed: ${response.error}`);
      }

      progress(`Coalesce transaction ${txIdx + 1} confirmed (hash: ${response.hash}). Waiting for note to be available...`);

      // Create the new V2Note that will be available after this tx confirms
      // The commitment comes from the proof's public inputs
      const newCommitment = tx.transaction_proof.public_inputs.note_commitments[0];
      const newCommitmentHex = bytesToHex(new Uint8Array(newCommitment));

      // Derive nullifier for the new note
      // Note: position will need to be fetched from a rescan
      // For now we use a placeholder - the wallet should rescan after coalescing
      const estimatedPosition = BigInt(Date.now());
      const nullifierKey = deriveNullifierKey(secretKey);
      const newNullifier = deriveNullifierPQ(
        nullifierKey,
        new Uint8Array(newCommitment),
        estimatedPosition
      );

      const newNote: V2Note = {
        value: outputValue,
        recipientPkHash: bytesToHex(senderPkHash),
        randomness: bytesToHex(notesToCoalesce[0].randomness ? hexToBytes(notesToCoalesce[0].randomness) : generateRandomnessPQ()),
        commitment: newCommitmentHex,
        position: estimatedPosition,
        blockHeight: 0, // Will be updated on rescan
        spent: false,
        nullifier: bytesToHex(newNullifier),
        version: 2,
      };

      workingNotes.push(newNote);
      onTransactionConfirmed?.(newNote, txIdx);

      // Re-sort working notes
      workingNotes.sort((a, b) => (a.value < b.value ? -1 : a.value > b.value ? 1 : 0));
    } else {
      // If not submitting immediately, we can't continue coalescing
      // because subsequent txs depend on outputs from previous ones
      if (txIdx < numTxs - 1) {
        throw new Error(
          'Cannot create multiple coalescing transactions without submitting. ' +
          'Set submitImmediately=true or coalesce one pair at a time.'
        );
      }
    }
  }

  progress(`Coalescing complete. ${workingNotes.length} notes remaining. Total fees: ${totalFees}`);

  return {
    transactions,
    coalescedNotes: workingNotes,
    totalFees,
    numTransactions: transactions.length,
  };
}

/**
 * Smart send that automatically coalesces if needed.
 *
 * This is the recommended way to send transactions when you might have
 * more UTXOs than the circuit supports.
 *
 * @param params - Standard transaction parameters plus coalescing options
 * @returns The final transaction (and any coalescing transactions)
 */
export interface SmartSendParams {
  /** Notes available for spending */
  availableNotes: V2Note[];
  /** Amount to send */
  amount: bigint;
  /** Recipient pk_hash */
  recipientPkHash: string;
  /** Transaction fee for the final transaction */
  fee: bigint;
  /** Secret key */
  secretKey: Uint8Array;
  /** Public key */
  publicKey: Uint8Array;
  /** Sender pk_hash */
  senderPkHash: Uint8Array;
  /** Progress callback */
  onProgress?: (msg: string) => void;
  /** Callback for wallet to update after coalescing */
  onCoalesceComplete?: (result: CoalesceResult) => void;
}

export interface SmartSendResult {
  /** The final transaction */
  transaction: ShieldedTransactionV2;
  /** Any coalescing transactions that were created and submitted */
  coalescingResult?: CoalesceResult;
  /** Total fees including coalescing */
  totalFees: bigint;
}

/**
 * Select notes and coalesce if needed, then create the final transaction.
 */
export async function smartSend(params: SmartSendParams): Promise<SmartSendResult> {
  const {
    availableNotes,
    amount,
    recipientPkHash,
    fee,
    secretKey,
    publicKey,
    senderPkHash,
    onProgress,
    onCoalesceComplete,
  } = params;

  const progress = (msg: string) => {
    console.log('[SmartSend]', msg);
    onProgress?.(msg);
  };

  // Select notes for the transaction
  const sortedNotes = [...availableNotes].sort((a, b) =>
    a.value > b.value ? -1 : a.value < b.value ? 1 : 0
  );

  const selectedNotes: V2Note[] = [];
  let total = 0n;
  const needed = amount + fee;

  for (const note of sortedNotes) {
    if (total >= needed) break;
    selectedNotes.push(note);
    total += note.value;
  }

  if (total < needed) {
    throw new Error(`Insufficient balance: have ${total}, need ${needed}`);
  }

  progress(`Selected ${selectedNotes.length} notes (total: ${total}) for amount ${amount} + fee ${fee}`);

  // Check if coalescing is needed
  let notesToSpend = selectedNotes;
  let coalescingResult: CoalesceResult | undefined;
  let coalescingFees = 0n;

  if (needsCoalescing(selectedNotes.length)) {
    progress(`Coalescing needed: ${selectedNotes.length} notes > ${MAX_SPENDS} max spends`);

    // Estimate coalescing fees
    const estimatedCoalesceFees = estimateCoalescingFees(selectedNotes.length);
    progress(`Estimated coalescing fees: ${estimatedCoalesceFees}`);

    // Check if we have enough after coalescing fees
    const totalNeeded = amount + fee + estimatedCoalesceFees;
    if (total < totalNeeded) {
      // Try to select more notes if available
      for (const note of sortedNotes) {
        if (!selectedNotes.includes(note) && total < totalNeeded) {
          selectedNotes.push(note);
          total += note.value;
        }
      }
      if (total < totalNeeded) {
        throw new Error(
          `Insufficient balance for transaction + coalescing: have ${total}, need ${totalNeeded}`
        );
      }
    }

    // Perform coalescing
    coalescingResult = await coalesceNotes({
      notes: selectedNotes,
      secretKey,
      publicKey,
      senderPkHash,
      targetCount: MAX_SPENDS,
      onProgress,
      submitImmediately: true,
      onTransactionConfirmed: (note, txIdx) => {
        progress(`Coalesce tx ${txIdx + 1} confirmed, new note value: ${note.value}`);
      },
    });

    notesToSpend = coalescingResult.coalescedNotes;
    coalescingFees = coalescingResult.totalFees;
    onCoalesceComplete?.(coalescingResult);
  }

  // Create the final transaction
  progress(`Creating final transaction with ${notesToSpend.length} spends...`);

  const spendNotes = notesToSpend.map(n => ({
    value: n.value,
    recipientPkHash: n.recipientPkHash,
    randomness: n.randomness,
    commitment: n.commitment,
    position: n.position,
    blockHeight: n.blockHeight,
    spent: n.spent,
    nullifier: n.nullifier,
  })) as WalletNote[];

  const transaction = await createShieldedTransactionV2({
    spendNotes,
    recipients: [{ pkHash: recipientPkHash, amount }],
    fee,
    secretKey,
    publicKey,
    senderPkHash,
    onProgress,
  });

  return {
    transaction,
    coalescingResult,
    totalFees: fee + coalescingFees,
  };
}

/**
 * Proactively coalesce notes to reduce UTXO count.
 *
 * Call this periodically or when gas fees are low to consolidate
 * small UTXOs, preventing future transactions from needing coalescing.
 *
 * @param notes - All unspent notes
 * @param params - Coalescing parameters (minus notes)
 * @param options - Proactive coalescing options
 * @returns Coalescing result
 */
export interface ProactiveCoalesceOptions {
  /** Maximum notes to keep (default: 5) */
  maxNotes?: number;
  /** Minimum value to consider for coalescing (default: 0) */
  minValue?: bigint;
  /** Only coalesce notes smaller than this value (default: no limit) */
  maxValueToCoalesce?: bigint;
}

export async function proactiveCoalesce(
  notes: V2Note[],
  params: Omit<CoalesceParams, 'notes' | 'targetCount'>,
  options: ProactiveCoalesceOptions = {}
): Promise<CoalesceResult> {
  const {
    maxNotes = 5,
    minValue = 0n,
    maxValueToCoalesce,
  } = options;

  // Filter notes eligible for coalescing
  let eligibleNotes = notes.filter(n => n.value >= minValue);
  if (maxValueToCoalesce !== undefined) {
    eligibleNotes = eligibleNotes.filter(n => n.value <= maxValueToCoalesce);
  }

  if (eligibleNotes.length <= maxNotes) {
    return {
      transactions: [],
      coalescedNotes: notes,
      totalFees: 0n,
      numTransactions: 0,
    };
  }

  return coalesceNotes({
    ...params,
    notes: eligibleNotes,
    targetCount: maxNotes,
  });
}
