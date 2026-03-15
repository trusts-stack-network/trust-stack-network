#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::note::Note;

fuzz_target!(|data: &[u8]| {
    if data.len() != 64 {
        return;
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(data);
    let _ = Note::from_bytes(&arr); // Doit jamais panic
});