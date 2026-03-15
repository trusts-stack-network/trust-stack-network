#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::commitment::{Commitment, NoteCommitment};
use tsn_crypto::note::Note;

fuzz_target!(|data: &[u8]| {
    if data.len() < 40 {
        return;
    }
    
    // Try to deserialize a note from arbitrary bytes
    match Note::from_bytes(data) {
        Ok(note) => {
            let commitment = NoteCommitment::commit(&note);
            // Commitment should always be valid
            let _ = commitment.verify(&note);
        }
        Err(_) => {
            // Invalid note bytes should not cause panics
        }
    }
});