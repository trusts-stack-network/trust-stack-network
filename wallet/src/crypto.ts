import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

// ML-DSA-65 key sizes (FIPS 204)
export const MLDSA65_PK_SIZE = 1952;
export const MLDSA65_SK_SIZE = 4032;
export const MLDSA65_SIG_SIZE = 3309;

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export function generateKeyPair(): KeyPair {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return ml_dsa65.keygen(seed);
}

export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_dsa65.sign(message, secretKey);
}

export function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  return ml_dsa65.verify(signature, message, publicKey);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data as unknown as BufferSource);
  return new Uint8Array(hashBuffer);
}

export async function deriveAddress(publicKey: Uint8Array): Promise<string> {
  const hash = await sha256(publicKey);
  return bytesToHex(hash.slice(0, 20));
}

// Build the signing message that matches the Rust backend format exactly
export function createSigningMessage(
  from: string,
  to: string,
  amount: bigint,
  fee: bigint,
  nonce: bigint,
  publicKey: string
): Uint8Array {
  const fromBytes = hexToBytes(from);
  const toBytes = hexToBytes(to);
  const publicKeyBytes = hexToBytes(publicKey);

  // Allocate buffer: 20 + 20 + 8 + 8 + 8 + pubkey_len
  const msg = new Uint8Array(20 + 20 + 8 + 8 + 8 + publicKeyBytes.length);
  let offset = 0;

  // From address (20 bytes)
  msg.set(fromBytes, offset);
  offset += 20;

  // To address (20 bytes)
  msg.set(toBytes, offset);
  offset += 20;

  // Amount (8 bytes, little-endian)
  const amountView = new DataView(msg.buffer, offset, 8);
  amountView.setBigUint64(0, amount, true);
  offset += 8;

  // Fee (8 bytes, little-endian)
  const feeView = new DataView(msg.buffer, offset, 8);
  feeView.setBigUint64(0, fee, true);
  offset += 8;

  // Nonce (8 bytes, little-endian)
  const nonceView = new DataView(msg.buffer, offset, 8);
  nonceView.setBigUint64(0, nonce, true);
  offset += 8;

  // Public key
  msg.set(publicKeyBytes, offset);

  return msg;
}
