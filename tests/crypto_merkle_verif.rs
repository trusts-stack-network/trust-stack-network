// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
use tsn_crypto::merkle_tree::{MerkleTree, Proof};
use rand_core::RngCore;

#[test]
fn reject_proof_with_wrong_root() {
    let mut mt = MerkleTree::new(32);
    let leaf = [1u8; 32];
    mt.insert(leaf);
    let (_, proof) = mt.get_proof(0).unwrap();

    let mut bad_root = mt.root();
    bad_root.0[0] ^= 1;

    assert!(!proof.verify(&leaf, &bad_root));
}

#[test]
fn reject_proof_out_of_bounds_index() {
    let mt = MerkleTree::new(8);
    assert!(mt.get_proof(999).is_none());
}

#[tokio::test]
async fn concurrent_insert_verify() {
    let mt = std::sync::Arc::new(std::sync::Mutex::new(MerkleTree::new(20)));
    let mut handles = vec![];

    for i in 0..10 {
        let mt = mt.clone();
        handles.push(tokio::spawn(async move {
            let mut leaf = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut leaf);
            let mut guard = mt.lock().unwrap();
            guard.insert(leaf);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let root = mt.lock().unwrap().root();
    assert!(!root.0.iter().all(|&b| b == 0));
}
