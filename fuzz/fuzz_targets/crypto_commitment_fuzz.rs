#![no_main]
use libfuzzer_sys::fuzz_target;
use tsn_crypto::commitment::CommitmentScheme;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct CommitmentInput {
    value: Vec<u8>,
    blinding: Vec<u8>,
    value2: Vec<u8>,
    blinding2: Vec<u8>,
}

fuzz_target!(|input: CommitmentInput| {
    let scheme = CommitmentScheme::new();
    
    // Test avec entrées de taille variable
    let comm1 = scheme.commit(&input.value, &input.blinding);
    let comm2 = scheme.commit(&input.value2, &input.blinding2);
    
    // Vérifie la cohérence
    if input.value == input.value2 && input.blinding == input.blinding2 {
        assert_eq!(comm1, comm2);
    }
    
    // Test de collision - devrait être improbable
    if input.value != input.value2 || input.blinding != input.blinding2 {
        prop_assert_ne!(comm1, comm2);
    }
    
    // Test avec valeurs extrêmes
    let empty_value = vec![];
    let empty_blinding = vec![];
    let _ = scheme.commit(&empty_value, &empty_blinding);
    
    let max_value = vec![0xff; 1_000_000]; // 1MB
    let max_blinding = vec![0xff; 1_000_000];
    let _ = std::panic::catch_unwind(|| {
        let _ = scheme.commit(&max_value, &max_blinding);
    });
});