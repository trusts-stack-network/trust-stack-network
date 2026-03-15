pragma circom 2.1.0;

include "node_modules/circomlib/circuits/poseidon.circom";

/**
 * Output circuit for proving valid note creation.
 *
 * This circuit proves:
 * 1. The note commitment was correctly computed
 *
 * The circuit MUST match the Rust implementation exactly:
 * - Domain constants must be the same
 * - Hash functions must be identical (Poseidon with same params)
 *
 * Public inputs:
 * - noteCommitment: Commitment to the new note
 * - valueCommitmentHash: Hash of value commitment (for balance verification)
 *
 * Private inputs:
 * - value: Note value (u64)
 * - recipientPkHash: Recipient public key hash
 * - noteRandomness: Note blinding factor
 */

// Domain separation constants (must match Rust)
// DOMAIN_NOTE_COMMITMENT = 1

template Output() {
    // Public inputs
    signal input noteCommitment;
    signal input valueCommitmentHash;

    // Private inputs
    signal input value;
    signal input recipientPkHash;
    signal input noteRandomness;

    // ====================
    // Constraint 1: Compute note commitment
    // cm = Poseidon(DOMAIN_NOTE_COMMITMENT=1, value, recipientPkHash, noteRandomness)
    // ====================
    component noteHash = Poseidon(4);
    noteHash.inputs[0] <== 1;  // DOMAIN_NOTE_COMMITMENT
    noteHash.inputs[1] <== value;
    noteHash.inputs[2] <== recipientPkHash;
    noteHash.inputs[3] <== noteRandomness;

    // Verify computed commitment equals public commitment
    noteHash.out === noteCommitment;

    // ====================
    // Constraint 2: Value commitment verification
    // The value commitment is verified externally through binding signature.
    // We just include valueCommitmentHash as a public input to bind it to this proof.
    // ====================

    // This signal is unused in the circuit but must be included as public input
    // for the binding signature verification.
    signal valueCommitmentHashSquared;
    valueCommitmentHashSquared <== valueCommitmentHash * valueCommitmentHash;
}

component main {public [noteCommitment, valueCommitmentHash]} = Output();
