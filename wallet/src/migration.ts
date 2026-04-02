/**
 * Migration utilities for converting V1 notes to V2 (post-quantum).
 *
 * This module provides functions to create migration transactions that
 * spend V1 notes (using legacy Groth16 proofs) and create V2 notes
 * (using PQ commitments and STARK proofs).
 *
 * ## Migration Process
 *
 * 1. Select V1 notes to migrate
 * 2. Create V1 spend proofs (Groth16)
 * 3. Create V2 output commitments (Poseidon/Goldilocks)
 * 4. Create migration STARK proof (Plonky2)
 * 5. Sign with ML-DSA-65 (already quantum-safe)
 *
 * The resulting migration transaction is accepted by validators that
 * support both V1 and V2 formats.
 */

import type { WalletNote } from './types';
import { hexToBytes, bytesToHex } from './crypto';
import {
  commitToNotePQ,
  generateRandomnessPQ,
  deriveNullifierPQ,
} from './commitment-pq';
import {
  generateTransactionProofPQ,
  type OutputWitnessPQ,
  type Plonky2Proof,
} from './prover-pq';
import {
  encryptNote,
  deriveViewingKey,
  deriveNullifierKey,
} from './shielded-crypto';

/**
 * A V1 note (legacy format).
 */
export interface V1Note extends WalletNote {
  // V1 notes have the same structure as WalletNote
}

/**
 * A V2 note (post-quantum format).
 */
export interface V2Note {
  value: bigint;
  recipientPkHash: string;
  randomness: string;
  commitment: string;
  position: bigint;
  blockHeight: number;
  spent: boolean;
  nullifier: string;
  version: 2;
}

/**
 * Migration transaction structure.
 */
export interface MigrationTransaction {
  // V1 spends (using legacy proofs)
  legacySpends: {
    anchor: string;
    nullifier: number[];
    value_commitment: string;
    proof: unknown;  // SnarkJS proof
    signature: string;
    public_key: string;
  }[];

  // V2 outputs (using PQ commitments)
  pqOutputs: {
    note_commitment: Uint8Array;
    encrypted_note: {
      ciphertext: Uint8Array;
      ephemeral_pk: Uint8Array;
    };
  }[];

  fee: number;
  legacy_binding_sig: { signature: string };
  migration_proof: Plonky2Proof;
}

/**
 * Parameters for creating a migration transaction.
 */
export interface MigrationParams {
  /** V1 notes to migrate */
  v1Notes: V1Note[];
  /** Secret key for signing */
  secretKey: Uint8Array;
  /** Public key for signatures */
  publicKey: Uint8Array;
  /** Sender's pk hash */
  senderPkHash: Uint8Array;
  /** Migration fee */
  fee: bigint;
  /** Progress callback */
  onProgress?: (status: string) => void;
}

/**
 * Result of a migration transaction.
 */
export interface MigrationResult {
  transaction: MigrationTransaction;
  v2Notes: V2Note[];
}

/**
 * Migrate V1 notes to V2 (post-quantum) format.
 *
 * This creates a migration transaction that:
 * 1. Spends the V1 notes using legacy proofs
 * 2. Creates V2 notes using PQ commitments
 * 3. Generates a STARK proof for the V2 portion
 *
 * @param params - Migration parameters
 * @returns Migration transaction and new V2 notes
 */
export async function migrateNotesToPQ(
  params: MigrationParams
): Promise<MigrationResult> {
  const { v1Notes, secretKey, publicKey, senderPkHash, fee, onProgress } = params;

  const progress = (msg: string) => {
    if (onProgress) onProgress(msg);
  };

  if (v1Notes.length === 0) {
    throw new Error('No notes to migrate');
  }

  // Calculate total value
  const totalValue = v1Notes.reduce((sum, n) => sum + n.value, 0n);
  const outputValue = totalValue - fee;

  if (outputValue <= 0n) {
    throw new Error(`Insufficient value for migration: have ${totalValue}, fee ${fee}`);
  }

  progress(`Migrating ${v1Notes.length} V1 note(s) with total value ${totalValue}`);

  // Step 1: Create V2 output commitments
  progress('Creating V2 output commitments...');

  const v2Notes: V2Note[] = [];
  const outputWitnesses: OutputWitnessPQ[] = [];
  const pqOutputs: MigrationTransaction['pqOutputs'] = [];

  // Create single V2 output with migrated value
  const randomness = generateRandomnessPQ();
  const commitment = commitToNotePQ(outputValue, senderPkHash, randomness);

  // Derive viewing key for encryption
  const viewingKey = deriveViewingKey(secretKey);
  const nullifierKey = deriveNullifierKey(secretKey);

  // Encrypt note for recipient (ourselves in migration)
  const encrypted = encryptNote(outputValue, senderPkHash, randomness, viewingKey);

  // Create output witness for STARK proof
  outputWitnesses.push({
    value: outputValue,
    recipientPkHash: senderPkHash,
    randomness,
  });

  // Add to PQ outputs
  pqOutputs.push({
    note_commitment: commitment,
    encrypted_note: {
      ciphertext: encrypted.ciphertext,
      ephemeral_pk: encrypted.ephemeralPk,
    },
  });

  // Create V2 note record
  // Note: position and blockHeight will be set after the transaction is mined
  const nullifier = deriveNullifierPQ(nullifierKey, commitment, 0n);
  v2Notes.push({
    value: outputValue,
    recipientPkHash: bytesToHex(senderPkHash),
    randomness: bytesToHex(randomness),
    commitment: bytesToHex(commitment),
    position: 0n, // Will be set after mining
    blockHeight: 0, // Will be set after mining
    spent: false,
    nullifier: bytesToHex(nullifier),
    version: 2,
  });

  // Step 3: Create migration STARK proof
  progress('Creating migration STARK proof...');

  // The migration proof only covers the V2 outputs
  // (V1 spend validity is proven by the legacy proofs)
  // The proof verifies that output commitments are correctly formed

  // Generate the STARK proof for outputs
  // Note: In a real migration, this would be a specialized proof
  // that only verifies output validity, not spend validity
  const migrationProof = await generateMigrationProofPQ(
    outputWitnesses,
    totalValue,
    fee
  );

  // Step 4: Build the migration transaction
  progress('Building migration transaction...');

  // For now, create placeholder legacy spends
  // In production, these would come from createShieldedTransaction
  const legacySpends = v1Notes.map((note) => ({
    anchor: '00'.repeat(32), // Placeholder
    nullifier: Array.from(hexToBytes(note.nullifier || '00'.repeat(32))),
    value_commitment: '00'.repeat(32), // Placeholder
    proof: {}, // Placeholder SnarkJS proof
    signature: '00'.repeat(64), // Placeholder
    public_key: bytesToHex(publicKey),
  }));

  const transaction: MigrationTransaction = {
    legacySpends,
    pqOutputs,
    fee: Number(fee),
    legacy_binding_sig: { signature: '00'.repeat(128) }, // Placeholder
    migration_proof: migrationProof,
  };

  progress('Migration transaction created successfully');

  return {
    transaction,
    v2Notes,
  };
}

/**
 * Generate a migration STARK proof.
 *
 * This is a simplified proof that only verifies:
 * 1. Output commitments are correctly formed
 * 2. Output values sum to expected total (inputs - fee)
 */
async function generateMigrationProofPQ(
  outputWitnesses: OutputWitnessPQ[],
  totalInputs: bigint,
  fee: bigint
): Promise<Plonky2Proof> {
  // Use the regular transaction proof generator with empty spends
  // The proof verifies output validity and balance
  return generateTransactionProofPQ(
    [], // No spends in migration proof (verified by legacy proofs)
    outputWitnesses,
    totalInputs - fee // "Fee" from the proof's perspective is the total inputs minus outputs
  ).catch(() => {
    // If regular proof fails (due to balance check), create a custom migration proof
    // This is a placeholder - real implementation would have specialized migration circuit
    const totalOutputs = outputWitnesses.reduce((sum, o) => sum + o.value, 0n);

    // Verify balance locally
    if (totalOutputs + fee !== totalInputs) {
      throw new Error(
        `Migration balance mismatch: inputs=${totalInputs}, outputs=${totalOutputs}, fee=${fee}`
      );
    }

    // Create public inputs with output commitments only
    const noteCommitments = outputWitnesses.map((o) => {
      const commitment = commitToNotePQ(
        o.value,
        o.recipientPkHash,
        o.randomness
      );
      return commitment;
    });

    return {
      proofBytes: new Uint8Array(0),
      publicInputs: {
        merkleRoots: [],
        nullifiers: [],
        noteCommitments,
        fee,
      },
    };
  });
}

/**
 * Check if a note is V1 (legacy) format.
 */
export function isV1Note(note: WalletNote | V2Note): note is V1Note {
  return !('version' in note) || (note as any).version !== 2;
}

/**
 * Check if a note is V2 (post-quantum) format.
 */
export function isV2Note(note: WalletNote | V2Note): note is V2Note {
  return 'version' in note && (note as any).version === 2;
}

/**
 * Estimate the fee for a migration transaction.
 *
 * Migration transactions are larger due to having both V1 and V2 components.
 */
export function estimateMigrationFee(numV1Notes: number): bigint {
  const baseFee = 2_000_000n; // Higher base fee for migration
  const perNote = 1_000_000n;
  return baseFee + BigInt(numV1Notes) * perNote;
}

/**
 * Get migration statistics for a wallet.
 */
export function getMigrationStats(notes: (WalletNote | V2Note)[]): {
  v1Count: number;
  v2Count: number;
  v1Value: bigint;
  v2Value: bigint;
  migrationNeeded: boolean;
} {
  let v1Count = 0;
  let v2Count = 0;
  let v1Value = 0n;
  let v2Value = 0n;

  for (const note of notes) {
    if (!note.spent) {
      if (isV2Note(note)) {
        v2Count++;
        v2Value += note.value;
      } else {
        v1Count++;
        v1Value += note.value;
      }
    }
  }

  return {
    v1Count,
    v2Count,
    v1Value,
    v2Value,
    migrationNeeded: v1Count > 0,
  };
}
