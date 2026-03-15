#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::merkle_tree::MerkleProof;

fuzz_target!(|data: &[u8]| {
    // Le decode doit jamais panic, même sur entrées aléatoires
    let _ = MerkleProof::try_from(data);
});