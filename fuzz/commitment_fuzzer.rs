// Fuzzer pour les engagements cryptographiques TSN
// Utilise libfuzzer_sys pour l'intégration avec cargo-fuzz

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    // Le fuzzer reçoit des données arbitraires et les passe aux fonctions
    // de commitment pour détecter les crashs ou comportements inattendus
    
    // Note: ce fuzzer est un stub minimal qui sera étendu avec
    // les vraies fonctions de commitment quand elles seront exposées
    let _ = input.len();
    let _ = input.is_empty();
    
    // Éviter les crashs sur entrées vides
    if input.is_empty() {
        return;
    }
    
    // Vérification basique: ne pas paniquer sur des données aléatoires
    let _first_byte = input[0];
    let _len_mod_256 = input.len() % 256;
});