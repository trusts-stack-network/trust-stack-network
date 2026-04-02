//! Fuzzer pour les fonctions de hash Poseidon
//!
//! Ce fuzzer teste la robustesse de l'implémentation Poseidon contre
//! des inputs malformés, extrêmes ou malveillants.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use tsn::crypto::poseidon::{poseidon_hash, poseidon_hash_2, bytes32_to_field, field_to_bytes32};

#[derive(Arbitrary, Debug)]
struct PoseidonFuzzInput {
    domain: u64,
    inputs: Vec<FieldElement>,
}

#[derive(Arbitrary, Debug)]
struct FieldElement {
    bytes: [u8; 32],
}

impl FieldElement {
    fn to_field(&self) -> Fr {
        bytes32_to_field(&self.bytes)
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    
    // Test 1: Fuzzer poseidon_hash avec inputs arbitraires
    if let Ok(input) = PoseidonFuzzInput::arbitrary(&mut u) {
        let field_inputs: Vec<Fr> = input.inputs.iter().map(|fe| fe.to_field()).collect();
        
        // Cette opération ne doit JAMAIS paniquer
        let result = std::panic::catch_unwind(|| {
            poseidon_hash(input.domain, &field_inputs)
        });
        
        if result.is_err() {
            panic!("poseidon_hash paniqué avec domain={}, inputs.len()={}", 
                   input.domain, field_inputs.len());
        }
        
        // Si on a au moins 2 inputs, tester poseidon_hash_2
        if field_inputs.len() >= 2 {
            let result2 = std::panic::catch_unwind(|| {
                poseidon_hash_2(input.domain, field_inputs[0], field_inputs[1])
            });
            
            if result2.is_err() {
                panic!("poseidon_hash_2 paniqué avec domain={}", input.domain);
            }
        }
    }
    
    // Test 2: Fuzzer la conversion bytes <-> field
    if data.len() >= 32 {
        let bytes: [u8; 32] = data[..32].try_into().unwrap();
        
        let result = std::panic::catch_unwind(|| {
            let field = bytes32_to_field(&bytes);
            let back_to_bytes = field_to_bytes32(&field);
            
            // Vérifier que la conversion est cohérente
            // Note: Il peut y avoir une différence due à la réduction modulo le prime du field
            let field2 = bytes32_to_field(&back_to_bytes);
            assert_eq!(field, field2, "Conversion field incohérente");
        });
        
        if result.is_err() {
            panic!("Conversion bytes32_to_field/field_to_bytes32 paniquée");
        }
    }
    
    // Test 3: Fuzzer avec des domaines extrêmes
    if let Ok(domain) = u64::arbitrary(&mut u) {
        if let Ok(field_elem) = FieldElement::arbitrary(&mut u) {
            let result = std::panic::catch_unwind(|| {
                poseidon_hash(domain, &[field_elem.to_field()])
            });
            
            if result.is_err() {
                panic!("poseidon_hash paniqué avec domaine extrême: {}", domain);
            }
        }
    }
    
    // Test 4: Fuzzer avec beaucoup d'inputs (test DoS)
    if data.len() >= 100 {
        let num_inputs = (data[0] as usize % 50) + 1; // 1 à 50 inputs
        let mut inputs = Vec::new();
        
        for i in 0..num_inputs {
            let start_idx = (i * 32) % (data.len() - 32);
            if start_idx + 32 <= data.len() {
                let bytes: [u8; 32] = data[start_idx..start_idx + 32].try_into().unwrap();
                inputs.push(bytes32_to_field(&bytes));
            }
        }
        
        if !inputs.is_empty() {
            let result = std::panic::catch_unwind(|| {
                poseidon_hash(1, &inputs)
            });
            
            if result.is_err() {
                panic!("poseidon_hash paniqué avec {} inputs", inputs.len());
            }
        }
    }
});