export interface Wallet {
  address: string;
  public_key: string;
  secret_key: string;
  /** Block height when wallet was created (for faster scanning) */
  birthday?: number;
}

export interface Account {
  address: string;
  balance: number;
  nonce: number;
}

export interface Transaction {
  hash: string;
  from: string;
  to: string;
  amount: number;
  fee: number;
  nonce: number;
  status?: 'pending' | 'confirmed';
}

// ============ Shielded Wallet Types ============

/**
 * A note in the wallet (decrypted private data).
 */
export interface WalletNote {
  /** Value in smallest units */
  value: bigint;
  /** Recipient's public key hash */
  recipientPkHash: string;
  /** Random blinding factor (hex) */
  randomness: string;
  /** Note commitment (hex) */
  commitment: string;
  /** Position in the commitment tree */
  position: bigint;
  /** Block height where this note was created */
  blockHeight: number;
  /** Whether this note has been spent */
  spent: boolean;
  /** Nullifier for this note (hex) - computed when needed for spending */
  nullifier?: string;
}

/**
 * Encrypted output from the blockchain.
 */
export interface EncryptedOutput {
  position: number;
  block_height: number;
  note_commitment: string;
  /** V2/PQ commitment (Goldilocks Poseidon) - empty for legacy V1 transactions */
  note_commitment_pq: string;
  ephemeral_pk: string;
  ciphertext: string;
}

/**
 * Response from GET /outputs/since/:height
 */
export interface OutputsSinceResponse {
  outputs: EncryptedOutput[];
  current_height: number;
  commitment_root: string;
}

/**
 * Response from POST /nullifiers/check
 */
export interface CheckNullifiersResponse {
  spent: string[];
}

/**
 * Response from GET /witness/:commitment
 */
export interface WitnessResponse {
  root: string;
  path: string[];
  position: number;
}

/**
 * Persisted shielded wallet state.
 */
export interface ShieldedState {
  /** All known notes (both spent and unspent) */
  notes: WalletNote[];
  /** Last scanned block height */
  lastScannedHeight: number;
}
