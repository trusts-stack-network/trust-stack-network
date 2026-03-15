pragma circom 2.1.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/mux1.circom";
include "node_modules/circomlib/circuits/comparators.circom";

/**
 * Spend circuit for proving valid note consumption.
 *
 * This circuit proves:
 * 1. The note commitment was correctly computed
 * 2. The note exists in the commitment tree (Merkle proof)
 * 3. The nullifier was correctly derived
 *
 * The circuit MUST match the Rust implementation exactly:
 * - Domain constants must be the same
 * - Hash functions must be identical (Poseidon with same params)
 *
 * Public inputs:
 * - merkleRoot: Tree root at spend time
 * - nullifier: Nullifier marking the note as spent
 * - valueCommitmentHash: Hash of value commitment (for balance verification)
 *
 * Private inputs:
 * - value: Note value (u64)
 * - recipientPkHash: Recipient public key hash
 * - noteRandomness: Note blinding factor
 * - nullifierKey: Secret for nullifier derivation
 * - pathElements[]: Merkle path siblings
 * - pathIndices[]: Merkle path directions (0=left, 1=right)
 * - position: Leaf position in tree
 */

// Domain separation constants (must match Rust)
// DOMAIN_NOTE_COMMITMENT = 1
// DOMAIN_NULLIFIER = 3
// DOMAIN_MERKLE_NODE = 5

template Spend(treeDepth) {
    // Public inputs
    signal input merkleRoot;
    signal input nullifier;
    signal input valueCommitmentHash;

    // Private inputs
    signal input value;
    signal input recipientPkHash;
    signal input noteRandomness;
    signal input nullifierKey;
    signal input pathElements[treeDepth];
    signal input pathIndices[treeDepth];
    signal input position;

    // ====================
    // Constraint 1: Compute note commitment
    // cm = Poseidon(DOMAIN_NOTE_COMMITMENT=1, value, recipientPkHash, noteRandomness)
    // ====================
    component noteHash = Poseidon(4);
    noteHash.inputs[0] <== 1;  // DOMAIN_NOTE_COMMITMENT
    noteHash.inputs[1] <== value;
    noteHash.inputs[2] <== recipientPkHash;
    noteHash.inputs[3] <== noteRandomness;

    signal noteCommitment;
    noteCommitment <== noteHash.out;

    // ====================
    // Constraint 2: Verify Merkle path
    // Starting from noteCommitment, hash up the tree
    // ====================
    signal computedPath[treeDepth + 1];
    computedPath[0] <== noteCommitment;

    component merkleHashers[treeDepth];
    component muxLeft[treeDepth];
    component muxRight[treeDepth];

    for (var i = 0; i < treeDepth; i++) {
        // Select left/right based on path direction
        // If pathIndices[i] == 0, current is left child
        // If pathIndices[i] == 1, current is right child

        muxLeft[i] = Mux1();
        muxLeft[i].c[0] <== computedPath[i];     // If index=0, current is left
        muxLeft[i].c[1] <== pathElements[i];    // If index=1, sibling is left
        muxLeft[i].s <== pathIndices[i];

        muxRight[i] = Mux1();
        muxRight[i].c[0] <== pathElements[i];   // If index=0, sibling is right
        muxRight[i].c[1] <== computedPath[i];    // If index=1, current is right
        muxRight[i].s <== pathIndices[i];

        // Hash: Poseidon(DOMAIN_MERKLE_NODE=5, left, right)
        merkleHashers[i] = Poseidon(3);
        merkleHashers[i].inputs[0] <== 5;  // DOMAIN_MERKLE_NODE
        merkleHashers[i].inputs[1] <== muxLeft[i].out;
        merkleHashers[i].inputs[2] <== muxRight[i].out;

        computedPath[i + 1] <== merkleHashers[i].out;
    }

    // Verify computed root equals public merkle root
    computedPath[treeDepth] === merkleRoot;

    // ====================
    // Constraint 3: Verify nullifier derivation
    // nf = Poseidon(DOMAIN_NULLIFIER=3, nullifierKey, noteCommitment, position)
    // ====================
    component nfHash = Poseidon(4);
    nfHash.inputs[0] <== 3;  // DOMAIN_NULLIFIER
    nfHash.inputs[1] <== nullifierKey;
    nfHash.inputs[2] <== noteCommitment;
    nfHash.inputs[3] <== position;

    nfHash.out === nullifier;

    // ====================
    // Constraint 4: Value commitment verification
    // The value commitment is verified externally through binding signature.
    // Here we just expose the valueCommitmentHash as a public input
    // to bind it to this proof.
    // ====================

    // Ensure pathIndices are binary (0 or 1)
    for (var i = 0; i < treeDepth; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;
    }
}

// Instantiate with tree depth 32 (matches Rust TREE_DEPTH)
component main {public [merkleRoot, nullifier, valueCommitmentHash]} = Spend(32);
