//! Post-quantum cryptography module.
//!
//! This module provides quantum-resistant cryptographic primitives using:
//! - STARK-based proofs (Plonky2 FRI) instead of Groth16 on BN254
//! - Hash-based commitments (Poseidon over Goldilocks) instead of Pedersen
//! - In-proof balance verification instead of binding signatures
//!
//! ## Key Changes from V1
//!
//! | Component | V1 (Vulnerable) | V2 (Quantum-Safe) |
//! |-----------|-----------------|-------------------|
//! | Value Commitments | Pedersen on BN254 | Poseidon hash |
//! | Binding Signatures | Schnorr on BN254 | In-proof verification |
//! | ZK Proofs | Groth16 on BN254 | Plonky2 STARKs |
//!
//! ## Security Assumptions
//!
//! V2 relies only on:
//! - Hash function security (128-bit post-quantum)
//! - ML-DSA-65 signatures (already quantum-safe)
//! - STARK proof soundness (hash-based, no EC)
//!
//! ## Browser Support
//!
//! Plonky2 compiles to WebAssembly, enabling client-side proving in browsers.
//! This is critical for self-custody wallets.

pub mod poseidon_pq;
pub mod commitment_pq;
pub mod merkle_pq;
pub mod circuit_pq;
pub mod proof_pq;
pub mod verify_pq;
pub mod slh_dsa;

/// SLH-DSA pqcrypto-based implementation (requires pqcrypto-sphincsplus crate)
/// Activé uniquement avec la feature "pqcrypto-sphincsplus"
#[cfg(feature = "pqcrypto-sphincsplus")]
pub mod slh_dsa_impl;

// Re-export commonly used types
pub use poseidon_pq::{
    poseidon_pq_hash, bytes_to_goldilocks, goldilocks_to_bytes,
    DOMAIN_NOTE_COMMIT_PQ, DOMAIN_VALUE_COMMIT_PQ, DOMAIN_NULLIFIER_PQ,
    DOMAIN_MERKLE_NODE_PQ, DOMAIN_MERKLE_EMPTY_PQ, GoldilocksField,
};

pub use commitment_pq::{
    ValueCommitmentPQ, NoteCommitmentPQ,
    commit_to_value_pq, commit_to_note_pq,
};

pub use merkle_pq::{
    CommitmentTreePQ, MerklePathPQ, MerkleWitnessPQ,
    TREE_DEPTH_PQ,
};

pub use proof_pq::{
    Plonky2Proof, TransactionPublicInputs, SpendWitnessPQ, OutputWitnessPQ,
    TransactionProver, verify_proof, ProofError,
};

pub use circuit_pq::{
    TransactionCircuit, CircuitCache,
};

pub use verify_pq::{
    verify_transaction_v2, VerificationError,
};
