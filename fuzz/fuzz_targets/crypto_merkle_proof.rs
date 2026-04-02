#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::merkle_tree::*;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct ProofFuzzData {
    leaf: [u8; 32],
    root: [u8; 32],
    proof: Vec<[u8; 32]>,
    index: u64,
}

fuzz_target!(|data: ProofFuzzData| {
    // Fuzz la vérification de preuve Merkle
    let proof = MerkleProof {
        leaf: Hash::from_bytes(&data.leaf),
        root: Hash::from_bytes(&data.root),
        path: data.proof.iter().map(|b| Hash::from_bytes(b)).collect(),
        index: data.index,
    };
    
    // Ne doit jamais paniquer
    let _ = proof.verify();
    
    // Test avec des paramètres invalides
    let mut corrupted_proof = proof.clone();
    corrupted_proof.index = data.index.wrapping_add(1);
    let _ = corrupted_proof.verify();
});