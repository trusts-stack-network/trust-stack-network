#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::commitment::Commitment;
use tsn_crypto::note::Note;

fuzz_target!(|data: &[u8]| {
    // Fuzzer pour les commitments et notes malformés
    if let Ok(commitment) = Commitment::from_bytes(data) {
        // Tester que les commitments malformés ne causent pas de panics
        let _ = commitment.to_bytes();
        
        // Tester l'ouverture de commitments avec des données invalides
        let random_bytes: [u8; 32] = rand::random();
        let _ = commitment.verify_opening(&random_bytes.into());
    }
    
    if let Ok(note) = Note::from_bytes(data) {
        // Vérifier que les notes malformées sont correctement gérées
        let _ = note.commitment();
        let _ = note.nullifier(&[0u8; 32]);
    }
});