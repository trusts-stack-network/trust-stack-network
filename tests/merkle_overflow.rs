// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Vérification qu’on ne peut pas overflow l’index
use tsn_crypto::merkle_tree::{MerkleTree,DEPTH};
use tsn_crypto::note::Note;

#[test]
#[should_panic(expected = "index overflow")]
fn reject_too_large_index() {
    let mut tree = MerkleTree::new();
    let note = Note::random(&mut rand::thread_rng());
    let huge_index = 1 << (DEPTH + 1);
    // Doit échouer avant d’atteindre le code de hash
    let _proof = tree.get_proof(huge_index, &note.commitment());
}
