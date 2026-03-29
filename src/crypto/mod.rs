pub mod hash;
pub mod constants;
pub mod keys;
pub mod address;
pub mod signature;
pub mod poseidon;
pub mod commitment;
pub mod nullifier;
pub mod note;
pub mod merkle_tree;
pub mod proof;
pub mod snarkjs;
pub mod binding;
pub mod circuit_breaker;

// Post-quantum cryptography module (V2)
pub mod pq;

// Validateur de signatures SLH-DSA
pub mod signature_validator;

// MODULES DE DÉMONSTRATION VULNÉRABLES
// Ces modules ne sont compilés qu'en mode test ou avec la feature explicite "vulnerable-demo"
// ⚠️ NE JAMAIS UTILISER EN PRODUCTION ⚠️
#[cfg(any(test, feature = "vulnerable-demo"))]
pub mod vulnerable;

#[cfg(any(test, feature = "vulnerable-demo"))]
pub mod vulnerable_ops;

// Guard de sécurité : les modules vulnérables ne compilent qu'en test/demo (voir cfg ci-dessus)
#[cfg(all(not(test), feature = "vulnerable-demo"))]
compile_error!("Feature 'vulnerable-demo' ne doit pas être activée en production !");

pub use keys::KeyPair;
pub use address::Address;
pub use signature::{sign, verify, Signature};
pub use poseidon::{
    poseidon_hash, poseidon_hash_2, bytes32_to_field, field_to_bytes32,
    DOMAIN_NOTE_COMMITMENT, DOMAIN_VALUE_COMMITMENT_HASH, DOMAIN_NULLIFIER,
    DOMAIN_MERKLE_EMPTY, DOMAIN_MERKLE_NODE,
};
pub use commitment::{NoteCommitment, ValueCommitment, commit_to_value, commit_to_note};
pub use nullifier::{Nullifier, NullifierKey, derive_nullifier};
pub use note::{Note, EncryptedNote, ViewingKey, encrypt_note_pq, decrypt_note_pq};
pub use merkle_tree::{CommitmentTree, MerklePath};
pub use proof::{ZkProof, CircomVerifyingParams, verify_spend_proof, verify_output_proof, bytes_to_public_inputs, output_bytes_to_public_inputs};
pub use snarkjs::{CircomVerifyingKey, verify_proof, parse_proof, parse_public_signals};
pub use circuit_breaker::{
    CryptoCircuitBreaker, CryptoOperation, CircuitState, CircuitBreakerConfig,
    CircuitBreakerError, global_circuit_breaker, OperationGuard,
};
pub use constants::{
    DOMAIN_TREASURY, DOMAIN_API_AUTH, DOMAIN_RATE_LIMIT, DOMAIN_AUDIT_LOG,
    JWT_DEFAULT_EXPIRATION_SECONDS, JWT_MAX_EXPIRATION_SECONDS, JWT_MIN_EXPIRATION_SECONDS,
    JWT_ISSUER, JWT_AUDIENCE_API, JWT_AUDIENCE_EXPLORER,
    RATE_LIMIT_AUTHENTICATED_RPM, RATE_LIMIT_UNAUTHENTICATED_RPM, RATE_LIMIT_BURST,
    RATE_LIMIT_WINDOW_SECONDS, RATE_LIMIT_COOLDOWN_SECONDS,
    API_MAX_BODY_SIZE, API_MAX_HEADER_SIZE, API_KEY_LENGTH,
    API_MAX_FAILED_AUTH_ATTEMPTS, API_LOCKOUT_DURATION_SECONDS,
    AUDIT_MAX_ENTRY_SIZE, AUDIT_RETENTION_DAYS, AUDIT_BATCH_SIZE,
};
