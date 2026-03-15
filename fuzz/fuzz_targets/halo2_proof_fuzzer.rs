//! Fuzzer cargo-fuzz pour le validateur de preuves Halo2
//! 
//! Ce fuzzer utilise libfuzzer-sys pour tester la robustesse du validateur
//! contre des entrées malformées et potentiellement malveillantes.

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::convert::TryFrom;

// Import des types depuis le crate tsn
use tsn::crypto::halo2_validator::{Halo2Validator, ValidationResult, ProofError};
use tsn::crypto::halo2_proofs::Halo2Proof;

/// Structure pour fuzzer les entrées de validation
#[derive(Debug, Clone)]
struct FuzzInput {
    proof_data: Vec<u8>,
    public_inputs: Vec<u8>,
    vk_hash: [u8; 32],
}

impl<'a> arbitrary::Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let proof_data = Vec::arbitrary(u)?;
        let public_inputs = Vec::arbitrary(u)?;
        let mut vk_hash = [0u8; 32];
        u.fill_buffer(&mut vk_hash)?;
        
        Ok(FuzzInput {
            proof_data,
            public_inputs,
            vk_hash,
        })
    }
}

fuzz_target!(|input: FuzzInput| {
    // Créer une preuve depuis les données fuzzées
    let proof = Halo2Proof::new(input.proof_data.clone());
    
    // Valider la preuve - ne doit jamais paniquer
    let validator = Halo2Validator::default();
    let result = validator.validate(&proof, &input.public_inputs, &input.vk_hash);
    
    // Vérifier les invariants de sécurité
    match result {
        ValidationResult::Valid => {
            // Si valide, la preuve doit respecter les contraintes de taille
            assert!(
                input.proof_data.len() >= 128,
                "Preuve acceptée mais trop petite"
            );
            assert!(
                input.proof_data.len() <= 65536,
                "Preuve acceptée mais trop grande"
            );
        }
        ValidationResult::Invalid(_) => {
            // Rejet attendu pour la plupart des entrées aléatoires
        }
    }
    
    // Tester la sérialisation/désérialisation
    if let Ok(serialized) = proof.to_bytes() {
        if let Ok(deserialized) = Halo2Proof::try_from(serialized.as_slice()) {
            // Vérifier que la re-sérialisation est cohérente
            let re_serialized = deserialized.to_bytes();
            assert!(re_serialized.is_ok(), "Re-sérialisation échouée");
        }
    }
});
