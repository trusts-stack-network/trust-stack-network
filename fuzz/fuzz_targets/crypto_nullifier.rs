#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::nullifier::compute_nullifier;
use tsn_crypto::note::Note;

fuzz_target!(|data: &[u8]| {
    if data.len() != 64 {
        return;
    }
    let mut note_bytes = [0u8; 64];
    note_bytes.copy_from_slice(data);
    // Note::from_bytes ne doit pas crasher même avec valeurs invalides
    if let Ok(note) = Note