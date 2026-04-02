/**
 * Binding signature implementation for proving value balance.
 *
 * The binding signature proves that:
 *   sum(spend_values) = sum(output_values) + fee
 *
 * This uses Pedersen commitments on BN254 and Schnorr signatures:
 * 1. Each spend/output has a value commitment: v*G + r*H
 * 2. Due to homomorphic property: sum(spend_commits) - sum(output_commits) - fee*G = r_balance*H
 * 3. The binding signature proves knowledge of r_balance
 *
 * Uses ffjavascript (from snarkjs) for BN254 curve operations.
 */

import { buildBn128 } from 'ffjavascript';
import { blake2b, blake2s } from '@noble/hashes/blake2.js';
import { bytesToHex, hexToBytes } from './crypto';

// BN254 curve instance (initialized lazily)
let curve: Awaited<ReturnType<typeof buildBn128>> | null = null;
let VALUE_GENERATOR_G: unknown = null;
let VALUE_GENERATOR_H: unknown = null;

/**
 * Initialize the BN254 curve and generator points.
 * Must be called before using any binding functions.
 */
export async function initBindingCrypto(): Promise<void> {
  if (curve) return;

  curve = await buildBn128(true); // singleThread for browser compatibility

  const { G1, Fr } = curve;

  // Derive generator G from "nothing up my sleeve" value
  // Must match Rust: BLAKE2s256("TSN_ValueCommitment_G") -> scalar -> G1.g * scalar
  const hashG = blake2s(new TextEncoder().encode('TSN_ValueCommitment_G'));
  const scalarG = Fr.fromRprLE(hashG, 0);
  VALUE_GENERATOR_G = G1.timesFr(G1.g, scalarG);

  // Derive generator H from "nothing up my sleeve" value
  // Must match Rust: BLAKE2s256("TSN_ValueCommitment_H") -> scalar -> G1.g * scalar
  const hashH = blake2s(new TextEncoder().encode('TSN_ValueCommitment_H'));
  const scalarH = Fr.fromRprLE(hashH, 0);
  VALUE_GENERATOR_H = G1.timesFr(G1.g, scalarH);
}

/**
 * Check if binding crypto is initialized.
 */
export function isBindingCryptoReady(): boolean {
  return curve !== null;
}

/**
 * A Pedersen value commitment with its randomness.
 */
export interface ValueCommitment {
  commitment: unknown; // G1 point
  randomness: unknown; // Fr element
  value: bigint;
}

/**
 * Create a Pedersen commitment to a value.
 * C = value * G + randomness * H
 */
export function commitToValue(value: bigint, randomnessBytes?: Uint8Array): ValueCommitment {
  if (!curve) throw new Error('Binding crypto not initialized. Call initBindingCrypto() first.');

  const { G1, Fr } = curve;

  // Generate random if not provided
  let randomness: unknown;
  if (randomnessBytes) {
    randomness = Fr.fromRprLE(randomnessBytes, 0);
  } else {
    const randBytes = new Uint8Array(32);
    crypto.getRandomValues(randBytes);
    randomness = Fr.fromRprLE(randBytes, 0);
  }

  // Convert value to Fr element
  const valueFr = Fr.e(value);

  // C = v*G + r*H
  const vG = G1.timesFr(VALUE_GENERATOR_G, valueFr);
  const rH = G1.timesFr(VALUE_GENERATOR_H, randomness);
  const commitment = G1.add(vG, rH);

  return { commitment, randomness, value };
}

/**
 * Serialize a value commitment to 32 bytes (compressed G1 point).
 */
export function serializeCommitment(vc: ValueCommitment): Uint8Array {
  if (!curve) throw new Error('Binding crypto not initialized');

  const { G1 } = curve;

  // Convert to affine and serialize
  const affine = G1.toAffine(vc.commitment);

  // BN254 G1 compressed is 32 bytes (just x-coordinate with sign bit)
  // Use uncompressed for now (64 bytes) then take first 32 for compatibility
  const buff = new Uint8Array(64);
  G1.toRprUncompressed(buff, 0, affine);

  // Return first 32 bytes (x-coordinate) - matches arkworks compressed format
  return buff.slice(0, 32);
}

/**
 * Binding signature (Schnorr on BN254).
 */
export interface BindingSignature {
  rPoint: Uint8Array; // 32 bytes compressed
  sScalar: Uint8Array; // 32 bytes
}

/**
 * Compute the Fiat-Shamir challenge for the Schnorr signature.
 */
function computeChallenge(rPointBytes: Uint8Array, pubkeyBytes: Uint8Array, message: Uint8Array): unknown {
  if (!curve) throw new Error('Binding crypto not initialized');

  const { Fr } = curve;

  const hasher = blake2b.create({ dkLen: 64 });
  hasher.update(new TextEncoder().encode('TSN_BindingSignature'));
  hasher.update(rPointBytes);
  hasher.update(pubkeyBytes);
  hasher.update(message);
  const hash = hasher.digest();

  return Fr.fromRprLE(hash.slice(0, 32), 0);
}

/**
 * Serialize a G1 point to 32 bytes.
 */
function serializeG1Point(point: unknown): Uint8Array {
  if (!curve) throw new Error('Binding crypto not initialized');

  const { G1 } = curve;
  const affine = G1.toAffine(point);
  const buff = new Uint8Array(64);
  G1.toRprUncompressed(buff, 0, affine);
  return buff.slice(0, 32);
}

/**
 * Serialize an Fr element to 32 bytes (little-endian).
 */
function serializeFr(element: unknown): Uint8Array {
  if (!curve) throw new Error('Binding crypto not initialized');

  const { Fr } = curve;
  const buff = new Uint8Array(32);
  Fr.toRprLE(buff, 0, element);
  return buff;
}

/**
 * Create a binding signature.
 *
 * @param bindingRandomness - Sum of spend randomness minus output randomness (Fr element)
 * @param message - The message to sign (binding message)
 */
export function createBindingSignature(
  bindingRandomness: unknown,
  message: Uint8Array
): BindingSignature {
  if (!curve) throw new Error('Binding crypto not initialized');

  const { G1, Fr } = curve;

  // Generate random nonce k
  const kBytes = new Uint8Array(32);
  crypto.getRandomValues(kBytes);
  const k = Fr.fromRprLE(kBytes, 0);

  // R = k * H
  const rPoint = G1.timesFr(VALUE_GENERATOR_H, k);
  const rPointBytes = serializeG1Point(rPoint);

  // Compute binding public key: binding_randomness * H
  const bindingPubkey = G1.timesFr(VALUE_GENERATOR_H, bindingRandomness);
  const pubkeyBytes = serializeG1Point(bindingPubkey);

  // Compute challenge: c = H(R || pubkey || message)
  const challenge = computeChallenge(rPointBytes, pubkeyBytes, message);

  // s = k + c * binding_randomness (mod order)
  const s = Fr.add(k, Fr.mul(challenge, bindingRandomness));

  // Serialize s to bytes
  const sScalar = serializeFr(s);

  return { rPoint: rPointBytes, sScalar };
}

/**
 * Serialize a binding signature to bytes (64 bytes total).
 */
export function serializeBindingSignature(sig: BindingSignature): Uint8Array {
  const result = new Uint8Array(64);
  result.set(sig.rPoint.slice(0, 32), 0);
  result.set(sig.sScalar, 32);
  return result;
}

/**
 * Compute the binding message from transaction components.
 */
export function computeBindingMessage(
  nullifiers: Uint8Array[],
  outputCommitments: Uint8Array[],
  fee: bigint
): Uint8Array {
  const hasher = blake2b.create({ dkLen: 64 });
  hasher.update(new TextEncoder().encode('TSN_BindingMessage'));

  for (const nf of nullifiers) {
    hasher.update(nf);
  }

  for (const cm of outputCommitments) {
    hasher.update(cm);
  }

  // Fee as little-endian 8 bytes
  const feeBytes = new Uint8Array(8);
  const view = new DataView(feeBytes.buffer);
  view.setBigUint64(0, fee, true);
  hasher.update(feeBytes);

  return hasher.digest();
}

/**
 * Track value commitments during transaction building.
 */
export class BindingContext {
  private spendCommitments: ValueCommitment[] = [];
  private outputCommitments: ValueCommitment[] = [];
  private fee: bigint = 0n;

  /**
   * Add a spend (input) with its value.
   */
  addSpend(value: bigint): ValueCommitment {
    if (!curve) throw new Error('Binding crypto not initialized');
    const vc = commitToValue(value);
    this.spendCommitments.push(vc);
    return vc;
  }

  /**
   * Add an output with its value.
   */
  addOutput(value: bigint): ValueCommitment {
    if (!curve) throw new Error('Binding crypto not initialized');
    const vc = commitToValue(value);
    this.outputCommitments.push(vc);
    return vc;
  }

  /**
   * Set the transaction fee.
   */
  setFee(fee: bigint): void {
    this.fee = fee;
  }

  /**
   * Verify the value balance is correct.
   */
  verifyBalance(): boolean {
    const totalSpend = this.spendCommitments.reduce((a, b) => a + b.value, 0n);
    const totalOutput = this.outputCommitments.reduce((a, b) => a + b.value, 0n);
    return totalSpend === totalOutput + this.fee;
  }

  /**
   * Compute the binding randomness.
   * binding_randomness = sum(spend_randomness) - sum(output_randomness)
   */
  computeBindingRandomness(): unknown {
    if (!curve) throw new Error('Binding crypto not initialized');

    const { Fr } = curve;

    let total = Fr.zero;

    // Add spend randomness
    for (const vc of this.spendCommitments) {
      total = Fr.add(total, vc.randomness);
    }

    // Subtract output randomness
    for (const vc of this.outputCommitments) {
      total = Fr.sub(total, vc.randomness);
    }

    return total;
  }

  /**
   * Create the binding signature for this transaction.
   */
  createSignature(nullifiers: Uint8Array[], outputNoteCommitments: Uint8Array[]): Uint8Array {
    // Verify balance before creating signature
    if (!this.verifyBalance()) {
      throw new Error('Value balance check failed');
    }

    const bindingRandomness = this.computeBindingRandomness();
    const message = computeBindingMessage(nullifiers, outputNoteCommitments, this.fee);
    const sig = createBindingSignature(bindingRandomness, message);
    return serializeBindingSignature(sig);
  }

  /**
   * Get the serialized value commitment for a spend at index.
   */
  getSpendCommitmentBytes(index: number): Uint8Array {
    return serializeCommitment(this.spendCommitments[index]);
  }

  /**
   * Get the serialized value commitment for an output at index.
   */
  getOutputCommitmentBytes(index: number): Uint8Array {
    return serializeCommitment(this.outputCommitments[index]);
  }
}

// Re-export for convenience
export { bytesToHex, hexToBytes };
