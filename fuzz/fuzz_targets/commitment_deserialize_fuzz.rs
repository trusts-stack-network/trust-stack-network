#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct CommitmentInput {
    value: Vec<u8>,
    salt: [u8; 32],
}

fuzz_target!(|input: CommitmentInput| {
    use tsn::crypto::commitment::Commitment;
    
    // Limiter la taille pour éviter les DoS
    if input.value.len() > 1024 * 1024 {
        return;
    }
    
    // Tester différentes tailles de valeur
    for size in [0, 1, 32, 1024, 65536] {
        if input.value.len() >= size {
            let value = &input.value[..size];
            let _ = Commitment::commit_with_salt(value, &input.salt);
        }
    }
});