#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::note::Note;

fuzz_target!(|data: &[u8]| {
    // Objectif : vérifier que le parsing ne panique jamais
    let _ = Note::from_bytes(data);
});