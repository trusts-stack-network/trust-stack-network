#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::commitment::{Commitment, compute_commitment};
use tsn_crypto::note::Note;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    
    // Fuzzer pour les entrées de commitment
    let note = Note::from_bytes(data);
    
    // Test que le hash est déterministe
    let commit1 = compute_commitment(&note, b"domain1");
    let commit2 = compute_commitment(&note, b"domain1");
    assert_eq!(commit1, commit2, "Commitment non-déterministe");
    
    // Test de résistance aux collisions
    let commit3 = compute_commitment(&note, b"domain2");
    assert_ne!(commit1, commit3, "Collision de domaine détectée");
    
    // Vérifier que le commitment ne fuite pas d'information
    // via patterns de bits
    let commit_bytes = commit1.to_bytes();
    
    // Test d'avalanche - petit changement = grand changement
    let mut note2 = note.clone();
    note2.value = note.value.wrapping_add(1);
    
    let commit4 = compute_commitment(&note2, b"domain1");
    let commit4_bytes = commit4.to_bytes();
    
    let bit_diffs = commit_bytes.iter()
        .zip(commit4_bytes.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum::<u32>();
    
    // Avec un bon hash, ~50% des bits devraient changer
    assert!(bit_diffs > 100 && bit_diffs < 150, 
            "Faible diffusion détectée: {} bits changés", bit_diffs);
});