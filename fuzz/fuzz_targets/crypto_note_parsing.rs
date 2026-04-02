#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::note::Note;

fuzz_target!(|data: &[u8]| {
    // Test parsing de notes malformées
    if let Ok(note) = Note::from_bytes(data) {
        // Vérifier que la note n'a pas de valeurs invalides
        let bytes = note.to_bytes();
        assert_eq!(bytes.len(), 64);
        
        // Test round-trip
        let note2 = Note::from_bytes(&bytes).unwrap();
        assert_eq!(note, note2);
    }
});