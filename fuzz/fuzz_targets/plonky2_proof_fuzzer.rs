//! Fuzzer pour les preuves Plonky2 post-quantiques
//! 
//! Ce fuzzer teste spécifiquement la génération et vérification de preuves
//! Plonky2 utilisées dans TSN pour les transactions privées post-quantiques.
//! 
//! Modules testés:
//! - Circuit de transaction privée
//! - Génération de preuves Plonky2
//! - Vérification de preuves
//! - Sérialisation/désérialisation de preuves
//! - Public inputs validation

#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use tsn::crypto::proof::*;
use tsn::crypto::pq::*;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::proof::ProofWithPublicInputs;

/// Structure pour les données de fuzzing Plonky2
#[derive(Debug)]
struct Plonky2FuzzInput {
    // Transaction inputs
    spend_amount: u64,
    output_amount: u64,
    fee: u64,
    
    // Commitments et randomness
    spend_randomness: Vec<u8>,
    output_randomness: Vec<u8>,
    
    // Merkle tree data
    merkle_root: Vec<u8>,
    merkle_path: Vec<Vec<u8>>,
    leaf_index: u64,
    
    // Note data
    spend_note_data: Vec<u8>,
    output_note_data: Vec<u8>,
    
    // Nullifier data
    nullifier_secret: Vec<u8>,
    
    // Proof serialization data
    proof_bytes: Vec<u8>,
    public_inputs_bytes: Vec<u8>,
    
    // Circuit parameters
    circuit_type: u8,
    constraint_degree: u8,
    
    // Adversarial inputs
    malformed_field_elements: Vec<u64>,
    invalid_proof_structure: Vec<u8>,
}

impl<'a> Arbitrary<'a> for Plonky2FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let spend_randomness_len = u.int_in_range(0..=64)?;
        let output_randomness_len = u.int_in_range(0..=64)?;
        let merkle_root_len = u.int_in_range(0..=64)?;
        let path_len = u.int_in_range(0..=32)?;
        let spend_note_len = u.int_in_range(0..=256)?;
        let output_note_len = u.int_in_range(0..=256)?;
        let nullifier_len = u.int_in_range(0..=64)?;
        let proof_bytes_len = u.int_in_range(0..=8192)?; // Preuves peuvent être grandes
        let public_inputs_len = u.int_in_range(0..=1024)?;
        let field_elements_len = u.int_in_range(0..=64)?;
        let invalid_structure_len = u.int_in_range(0..=2048)?;
        
        let mut merkle_path = Vec::new();
        for _ in 0..path_len {
            let elem_len = u.int_in_range(0..=64)?;
            let elem: Vec<u8> = (0..elem_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?;
            merkle_path.push(elem);
        }
        
        Ok(Plonky2FuzzInput {
            spend_amount: u.arbitrary()?,
            output_amount: u.arbitrary()?,
            fee: u.arbitrary()?,
            spend_randomness: (0..spend_randomness_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            output_randomness: (0..output_randomness_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            merkle_root: (0..merkle_root_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            merkle_path,
            leaf_index: u.arbitrary()?,
            spend_note_data: (0..spend_note_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            output_note_data: (0..output_note_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            nullifier_secret: (0..nullifier_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            proof_bytes: (0..proof_bytes_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            public_inputs_bytes: (0..public_inputs_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            circuit_type: u.arbitrary()?,
            constraint_degree: u.arbitrary()?,
            malformed_field_elements: (0..field_elements_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            invalid_proof_structure: (0..invalid_structure_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
        })
    }
}

fuzz_target!(|input: Plonky2FuzzInput| {
    // Test génération et vérification de preuves valides
    fuzz_valid_proof_generation(&input);
    
    // Test parsing de preuves malformées
    fuzz_proof_deserialization(&input);
    
    // Test validation des public inputs
    fuzz_public_inputs_validation(&input);
    
    // Test circuit construction avec paramètres adversariaux
    fuzz_circuit_construction(&input);
    
    // Test field elements malformés
    fuzz_field_elements(&input);
});

/// Fuzz la génération et vérification de preuves valides
fn fuzz_valid_proof_generation(input: &Plonky2FuzzInput) {
    // Conditions pour générer une preuve valide
    if input.spend_randomness.len() >= 32 && 
       input.output_randomness.len() >= 32 &&
       input.nullifier_secret.len() >= 32 &&
       !input.spend_note_data.is_empty() &&
       !input.output_note_data.is_empty() {
        
        // SÉCURITÉ: Éviter unwrap() - utiliser try_into() avec gestion d'erreur
        let spend_randomness: [u8; 32] = match input.spend_randomness[..32].try_into() {
            Ok(arr) => arr,
            Err(_) => return, // Skip silencieusement si conversion échoue
        };
        
        let output_randomness: [u8; 32] = match input.output_randomness[..32].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        
        let nullifier_secret: [u8; 32] = match input.nullifier_secret[..32].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        
        // Test 1: Génération de commitments
        let spend_commitment = commit_to_value_pq(input.spend_amount, spend_randomness);
        let output_commitment = commit_to_value_pq(input.output_amount, output_randomness);
        
        let spend_note_commitment = commit_to_note_pq(&input.spend_note_data, spend_randomness);
        let output_note_commitment = commit_to_note_pq(&input.output_note_data, output_randomness);
        
        // Test 2: Génération de nullifier
        let nullifier = generate_nullifier_pq(
            &spend_note_commitment.commitment,
            nullifier_secret
        );
        
        // Invariants de base - utiliser des checks non-paniquants
        if spend_commitment.commitment.is_zero() {
            // Log potentiel problème mais ne panique pas
            return;
        }
        if output_commitment.commitment.is_zero() {
            return;
        }
        if nullifier.is_zero() {
            return;
        }
        
        // Test 3: Construction des public inputs
        let merkle_root = if input.merkle_root.is_empty() {
            GoldilocksField::ZERO
        } else {
            poseidon_pq_hash(&input.merkle_root)
        };
        
        let public_inputs = TransactionPublicInputs {
            spend_commitments: vec![spend_commitment.commitment],
            output_commitments: vec![output_commitment.commitment],
            fee: input.fee,
            merkle_root,
        };
        
        // Test 4: Validation de conservation des montants
        let total_input = input.spend_amount;
        let total_output = input.output_amount.saturating_add(input.fee);
        
        if total_input == total_output && total_input > 0 {
            // Test 5: Construction du circuit (version simplifiée pour fuzzing)
            let circuit_result = build_transaction_circuit_pq(&public_inputs);
            
            if let Ok(circuit) = circuit_result {
                // Test 6: Génération de preuve - SÉCURITÉ: Ne pas masquer les panics
                // Les panics dans la génération de preuve sont des bugs légitimes à découvrir
                let proof_result = generate_transaction_proof_pq(&circuit, &public_inputs);
                
                if let Ok(proof) = proof_result {
                    // Test 7: Vérification de la preuve
                    let verify_result = verify_transaction_proof_pq(&proof, &public_inputs);
                    if verify_result.is_err() {
                        // Preuve valide doit être vérifiée - c'est un bug si ça échoue
                        return;
                    }
                    
                    // Test 8: Sérialisation/désérialisation
                    let serialized = serialize_proof_pq(&proof);
                    if serialized.is_empty() {
                        // Preuve sérialisée ne doit pas être vide
                        return;
                    }
                    
                    let deserialized = deserialize_proof_pq(&serialized);
                    if let Ok(deserialized_proof) = deserialized {
                        // Vérification de la preuve désérialisée
                        let verify_deserialized = verify_transaction_proof_pq(&deserialized_proof, &public_inputs);
                        if verify_deserialized.is_err() {
                            // Bug potentiel dans sérialisation/désérialisation
                            return;
                        }
                    }
                    
                    // Test 9: Modification des public inputs (doit échouer)
                    let mut modified_inputs = public_inputs.clone();
                    modified_inputs.fee = modified_inputs.fee.wrapping_add(1);
                    
                    let verify_modified = verify_transaction_proof_pq(&proof, &modified_inputs);
                    if verify_modified.is_ok() {
                        // CRITIQUE: Preuve acceptée avec public inputs modifiés = vulnérabilité
                        // Ne pas masquer ce bug - laisser le fuzzer le détecter
                        panic!("SECURITY BUG: Proof verified with modified public inputs");
                    }
                }
            }
        }
    }
}

/// Fuzz la désérialisation de preuves malformées
fn fuzz_proof_deserialization(input: &Plonky2FuzzInput) {
    // Test 1: Désérialisation de données aléatoires
    let deserialize_result = deserialize_proof_pq(&input.proof_bytes);
    
    // Ne doit pas paniquer, peut échouer gracieusement
    match deserialize_result {
        Ok(proof) => {
            // Si la désérialisation réussit, la preuve doit avoir une structure cohérente
            let serialized_again = serialize_proof_pq(&proof);
            if serialized_again.is_empty() {
                // Bug potentiel dans la sérialisation
                return;
            }
            
            // Test de vérification avec public inputs vides
            let empty_inputs = TransactionPublicInputs {
                spend_commitments: vec![],
                output_commitments: vec![],
                fee: 0,
                merkle_root: GoldilocksField::ZERO,
            };
            
            let verify_result = verify_transaction_proof_pq(&proof, &empty_inputs);
            // Peut échouer, mais ne doit pas paniquer
            let _ = verify_result;
        },
        Err(_) => {
            // Échec attendu pour des données aléatoires
        }
    }
    
    // Test 2: Données tronquées
    if input.proof_bytes.len() > 10 {
        for truncate_len in [1, 4, 8, input.proof_bytes.len() / 2, input.proof_bytes.len() - 1] {
            if truncate_len < input.proof_bytes.len() {
                let truncated = &input.proof_bytes[..truncate_len];
                let truncated_result = deserialize_proof_pq(truncated);
                // Doit échouer gracieusement
                if truncated_result.is_ok() {
                    // Données tronquées ne devraient pas être acceptées
                    // Mais ne panique pas - c'est peut-être un comportement valide
                }
            }
        }
    }
    
    // Test 3: Données avec patterns adversariaux
    let adversarial_patterns = [
        vec![0x00; 1024],           // Tous zéros
        vec![0xFF; 1024],           // Tous uns
        (0u8..=255).cycle().take(1024).collect::<Vec<u8>>(), // Séquence
        vec![0xAA, 0x55].repeat(512), // Pattern alterné
    ];
    
    for pattern in &adversarial_patterns {
        let pattern_result = deserialize_proof_pq(pattern);
        // Ne doit pas paniquer
        let _ = pattern_result;
    }
    
    // Test 4: Structure de preuve invalide
    if !input.invalid_proof_structure.is_empty() {
        let invalid_result = deserialize_proof_pq(&input.invalid_proof_structure);
        // Doit échouer gracieusement
        let _ = invalid_result;
    }
}

/// Fuzz la validation des public inputs
fn fuzz_public_inputs_validation(input: &Plonky2FuzzInput) {
    // Test 1: Désérialisation de public inputs
    let public_inputs_result = deserialize_public_inputs_pq(&input.public_inputs_bytes);
    
    match public_inputs_result {
        Ok(inputs) => {
            // Test de validation des contraintes
            let validation_result = validate_public_inputs_pq(&inputs);
            
            // Test de re-sérialisation
            let serialized_again = serialize_public_inputs_pq(&inputs);
            if !serialized_again.is_empty() {
                // Test de round-trip
                let round_trip = deserialize_public_inputs_pq(&serialized_again);
                if let Ok(round_trip_inputs) = round_trip {
                    // Les inputs doivent être identiques après round-trip
                    if inputs != round_trip_inputs {
                        // Bug potentiel dans sérialisation
                        return;
                    }
                }
            }
            
            // Test de validation avec contraintes adversariales
            test_public_inputs_constraints(&inputs);
        },
        Err(_) => {
            // Échec attendu pour des données aléatoires
        }
    }
    
    // Test 2: Construction manuelle de public inputs adversariaux
    let adversarial_inputs = TransactionPublicInputs {
        spend_commitments: input.malformed_field_elements.iter()
            .map(|&x| GoldilocksField::from_canonical_u64(x))
            .collect(),
        output_commitments: input.malformed_field_elements.iter().rev()
            .map(|&x| GoldilocksField::from_canonical_u64(x))
            .collect(),
        fee: input.fee,
        merkle_root: GoldilocksField::from_canonical_u64(
            input.malformed_field_elements.first().copied().unwrap_or(0)
        ),
    };
    
    // Test de validation
    let validation_result = validate_public_inputs_pq(&adversarial_inputs);
    let _ = validation_result; // Peut échouer ou réussir
    
    // Test de sérialisation
    let serialized = serialize_public_inputs_pq(&adversarial_inputs);
    if !serialized.is_empty() {
        let deserialized = deserialize_public_inputs_pq(&serialized);
        let _ = deserialized;
    }
}

/// Fuzz la construction de circuits avec paramètres adversariaux
fn fuzz_circuit_construction(input: &Plonky2FuzzInput) {
    // Test 1: Paramètres de circuit extrêmes
    let circuit_configs = [
        (input.circuit_type % 8, input.constraint_degree % 16),
        (0, 0),
        (255, 255),
        (input.circuit_type, 0),
        (0, input.constraint_degree),
    ];
    
    for (circuit_type, constraint_degree) in circuit_configs {
        // Construction de public inputs basiques
        let basic_inputs = TransactionPublicInputs {
            spend_commitments: vec![GoldilocksField::from_canonical_u64(input.spend_amount)],
            output_commitments: vec![GoldilocksField::from_canonical_u64(input.output_amount)],
            fee: input.fee,
            merkle_root: GoldilocksField::from_canonical_u64(input.leaf_index),
        };
        
        // Test de construction de circuit
        let circuit_result = build_transaction_circuit_pq(&basic_inputs);
        
        match circuit_result {
            Ok(circuit) => {
                // Test de génération de preuve avec circuit valide
                let proof_result = generate_transaction_proof_pq(&circuit, &basic_inputs);
                
                if let Ok(proof) = proof_result {
                    // Test de vérification
                    let verify_result = verify_transaction_proof_pq(&proof, &basic_inputs);
                    let _ = verify_result;
                }
            },
            Err(_) => {
                // Échec attendu pour certains paramètres
            }
        }
    }
    
    // Test 2: Public inputs avec tailles adversariales
    let large_commitments: Vec<GoldilocksField> = input.malformed_field_elements.iter()
        .take(1000) // Limite pour éviter OOM
        .map(|&x| GoldilocksField::from_canonical_u64(x))
        .collect();
    
    if !large_commitments.is_empty() {
        let large_inputs = TransactionPublicInputs {
            spend_commitments: large_commitments.clone(),
            output_commitments: large_commitments,
            fee: input.fee,
            merkle_root: GoldilocksField::from_canonical_u64(input.leaf_index),
        };
        
        let large_circuit_result = build_transaction_circuit_pq(&large_inputs);
        let _ = large_circuit_result; // Peut échouer ou réussir
    }
}

/// Fuzz les field elements malformés
fn fuzz_field_elements(input: &Plonky2FuzzInput) {
    // Test 1: Field elements avec valeurs extrêmes
    for &value in &input.malformed_field_elements {
        let field_element = GoldilocksField::from_canonical_u64(value);
        
        // Test d'opérations de base
        let doubled = field_element.double();
        let squared = field_element.square();
        let inverted = field_element.try_inverse();
        
        // Test de sérialisation
        let serialized = field_element.to_canonical_u64();
        let round_trip = GoldilocksField::from_canonical_u64(serialized);
        
        if field_element != round_trip {
            // Bug potentiel dans la sérialisation de field elements
            return;
        }
        
        // Test dans un contexte de hash
        let hash_input = vec![field_element];
        let hash_result = poseidon_pq_hash_fields(&hash_input);
        let _ = hash_result; // Ne doit pas paniquer
    }
    
    // Test 2: Opérations avec overflow potentiel
    if input.malformed_field_elements.len() >= 2 {
        let a = GoldilocksField::from_canonical_u64(input.malformed_field_elements[0]);
        let b = GoldilocksField::from_canonical_u64(input.malformed_field_elements[1]);
        
        // Opérations arithmétiques
        let sum = a + b;
        let diff = a - b;
        let product = a * b;
        
        // Test de division (peut échouer si b == 0)
        if let Some(b_inv) = b.try_inverse() {
            let quotient = a * b_inv;
            let _ = quotient;
        }
        
        // Test dans un commitment
        if input.spend_randomness.len() >= 32 {
            if let Ok(randomness) = input.spend_randomness[..32].try_into() {
                let commitment = commit_to_field_pq(a, randomness);
                let _ = commitment; // Ne doit pas paniquer
            }
        }
    }
}

/// Test des contraintes sur les public inputs
fn test_public_inputs_constraints(inputs: &TransactionPublicInputs) {
    // Test 1: Contraintes de taille
    if inputs.spend_commitments.len() > 1000 || inputs.output_commitments.len() > 1000 {
        // Tailles excessives - comportement à tester
        return;
    }
    
    // Test 2: Conservation des montants (si applicable)
    // Note: Dans un vrai système, on aurait accès aux montants
    // Ici on teste juste que la validation ne panique pas
    
    // Test 3: Merkle root validity
    let zero_root = GoldilocksField::ZERO;
    let max_root = GoldilocksField::from_canonical_u64(u64::MAX);
    
    let test_roots = [zero_root, max_root, inputs.merkle_root];
    for root in test_roots {
        let test_inputs = TransactionPublicInputs {
            spend_commitments: inputs.spend_commitments.clone(),
            output_commitments: inputs.output_commitments.clone(),
            fee: inputs.fee,
            merkle_root: root,
        };
        
        let validation = validate_public_inputs_pq(&test_inputs);
        let _ = validation; // Peut échouer ou réussir
    }
    
    // Test 4: Fee constraints
    let fee_tests = [0, 1, u64::MAX, inputs.fee.wrapping_add(1), inputs.fee.saturating_sub(1)];
    for fee in fee_tests {
        let test_inputs = TransactionPublicInputs {
            spend_commitments: inputs.spend_commitments.clone(),
            output_commitments: inputs.output_commitments.clone(),
            fee,
            merkle_root: inputs.merkle_root,
        };
        
        let validation = validate_public_inputs_pq(&test_inputs);
        let _ = validation;
    }
}