#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn::crypto::note::{self, Note};
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct NoteInput {
    commitment: [u8; 32],
    nullifier: [u8; 32],
    value: u64,
}

fuzz_target!(|input: NoteInput| {
    // Créer une note avec des inputs potentiellement invalides
    let note = Note {
        commitment: input.commitment,
        nullifier: input.nullifier,
        value: input.value,
    };
    
    // Vérifier que les opérations ne panic pas
    let _ = note.validate();
    let _ = note.check_nullifier_exists(&input.nullifier);
    
    // Test de double-spend simulation
    let _ = note.mark_nullifier_spent(&input.nullifier);
    let spent = note.check_nullifier_exists(&input.nullifier);
    // Si la fonction retourne une erreur, c'est OK
    let _ = spent;
});