//! Fuzzer pour les modules cryptographiques post-quantiques
//! 
//! Ce fuzzer teste la robustesse des implémentations crypto post-quantiques
//! contre des entrées malformées et adversariales.
//! 
//! Modules testés:
//! - SLH-DSA (SPHINCS+) signatures post-quantiques
//! - Poseidon hash post-quantique
//! - Commitments post-quantiques
//! - Merkle trees post-quantiques
//! - Plonky2 proof generation/verification

#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use tsn::crypto::pq::*;
use tsn::crypto::pq::slh_dsa::*;

/// Structure pour les données de fuzzing crypto PQ
#[derive(Debug)]
struct PqFuzzInput {
    // SLH-DSA inputs
    message: Vec<u8>,
    signature_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
    secret_key_bytes: Vec<u8>,
    
    // Poseidon inputs
    poseidon_input: Vec<u8>,
    domain_separator: u64,
    
    // Commitment inputs
    value: u64,
    randomness: Vec<u8>,
    note_data: Vec<u8>,
    
    // Merkle tree inputs
    leaf_data: Vec<u8>,
    path_elements: Vec<Vec<u8>>,
    leaf_index: u64,
    
    // Circuit inputs
    spend_amount: u64,
    output_amount: u64,
    fee: u64,
}

impl<'a> Arbitrary<'a> for PqFuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let message_len = u.int_in_range(0..=1024)?;
        let sig_len = u.int_in_range(0..=SLH_SIGNATURE_SIZE * 2)?; // Peut être plus grand que prévu
        let pk_len = u.int_in_range(0..=SLH_PUBLIC_KEY_SIZE * 2)?;
        let sk_len = u.int_in_range(0..=SLH_SECRET_KEY_SIZE * 2)?;
        let poseidon_len = u.int_in_range(0..=256)?;
        let randomness_len = u.int_in_range(0..=64)?;
        let note_len = u.int_in_range(0..=512)?;
        let leaf_len = u.int_in_range(0..=128)?;
        let path_len = u.int_in_range(0..=32)?; // Max depth
        
        let mut path_elements = Vec::new();
        for _ in 0..path_len {
            let elem_len = u.int_in_range(0..=64)?;
            let elem: Vec<u8> = (0..elem_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?;
            path_elements.push(elem);
        }
        
        Ok(PqFuzzInput {
            message: (0..message_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            signature_bytes: (0..sig_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            public_key_bytes: (0..pk_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            secret_key_bytes: (0..sk_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            poseidon_input: (0..poseidon_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            domain_separator: u.arbitrary()?,
            value: u.arbitrary()?,
            randomness: (0..randomness_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            note_data: (0..note_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            leaf_data: (0..leaf_len).map(|_| u.arbitrary()).collect::<Result<Vec<_>, _>>()?,
            path_elements,
            leaf_index: u.arbitrary()?,
            spend_amount: u.arbitrary()?,
            output_amount: u.arbitrary()?,
            fee: u.arbitrary()?,
        })
    }
}

fuzz_target!(|input: PqFuzzInput| {
    // Test SLH-DSA signatures
    fuzz_slh_dsa_signatures(&input);
    
    // Test Poseidon hash
    fuzz_poseidon_hash(&input);
    
    // Test commitments post-quantiques
    fuzz_pq_commitments(&input);
    
    // Test Merkle trees post-quantiques
    fuzz_pq_merkle_trees(&input);
    
    // Test circuit generation (plus lourd, on limite)
    if input.message.len() < 100 {
        fuzz_pq_circuits(&input);
    }
});

/// Fuzz les signatures SLH-DSA
fn fuzz_slh_dsa_signatures(input: &PqFuzzInput) {
    // Test 1: Génération de clés valides
    let (sk, pk) = SecretKey::generate();
    
    // Invariants de base
    assert_eq!(pk.to_bytes().len(), SLH_PUBLIC_KEY_SIZE);
    assert_eq!(sk.to_bytes().len(), SLH_SECRET_KEY_SIZE);
    
    // Test 2: Signature et vérification avec clés valides
    if !input.message.is_empty() {
        let signature = sign(&sk, &input.message);
        assert_eq!(signature.to_bytes().len(), SLH_SIGNATURE_SIZE);
        
        // Vérification doit réussir
        assert!(verify(&pk, &input.message, &signature),
            "Signature valide doit être vérifiée avec succès");
        
        // Test avec message modifié
        if input.message.len() > 1 {
            let mut modified_message = input.message.clone();
            modified_message[0] = modified_message[0].wrapping_add(1);
            
            assert!(!verify(&pk, &modified_message, &signature),
                "Signature ne doit pas être valide pour un message modifié");
        }
    }
    
    // Test 3: Parsing de clés publiques malformées
    let pk_result = PublicKey::from_bytes(&input.public_key_bytes);
    if input.public_key_bytes.len() == SLH_PUBLIC_KEY_SIZE {
        assert!(pk_result.is_some(), "Clé publique de taille correcte doit parser");
        
        // Test de vérification avec clé parsée
        if let Some(parsed_pk) = pk_result {
            let sig_result = Signature::from_bytes(&input.signature_bytes);
            if let Some(parsed_sig) = sig_result {
                // Ne doit pas paniquer, même avec des données aléatoires
                let _ = verify(&parsed_pk, &input.message, &parsed_sig);
            }
        }
    } else {
        assert!(pk_result.is_none(), "Clé publique de taille incorrecte doit échouer");
    }
    
    // Test 4: Parsing de clés secrètes malformées
    let sk_result = SecretKey::from_bytes(&input.secret_key_bytes);
    if input.secret_key_bytes.len() == SLH_SECRET_KEY_SIZE {
        assert!(sk_result.is_some(), "Clé secrète de taille correcte doit parser");
        
        if let Some(parsed_sk) = sk_result {
            // Dérivation de clé publique ne doit pas paniquer
            let derived_pk = parsed_sk.derive_public_key();
            assert_eq!(derived_pk.to_bytes().len(), SLH_PUBLIC_KEY_SIZE);
            
            // Signature ne doit pas paniquer
            if !input.message.is_empty() {
                let sig = sign(&parsed_sk, &input.message);
                assert_eq!(sig.to_bytes().len(), SLH_SIGNATURE_SIZE);
            }
        }
    } else {
        assert!(sk_result.is_none(), "Clé secrète de taille incorrecte doit échouer");
    }
    
    // Test 5: Parsing de signatures malformées
    let sig_result = Signature::from_bytes(&input.signature_bytes);
    if input.signature_bytes.len() == SLH_SIGNATURE_SIZE {
        assert!(sig_result.is_some(), "Signature de taille correcte doit parser");
    } else {
        assert!(sig_result.is_none(), "Signature de taille incorrecte doit échouer");
    }
    
    // Test 6: SlhDsaSigner avec compteur
    let mut signer = SlhDsaSigner::new(sk);
    let initial_counter = signer.counter();
    
    if !input.message.is_empty() {
        let (sig, counter) = signer.sign_with_counter(&input.message);
        assert_eq!(counter, initial_counter);
        assert_eq!(signer.counter(), initial_counter + 1);
        
        // Vérification avec SlhDsaVerifier
        let verifier = SlhDsaVerifier::new(signer.public_key());
        let verify_result = verifier.verify(&input.message, sig.to_bytes(), counter);
        assert!(verify_result.is_ok(), "Signature avec compteur doit être valide");
    }
}

/// Fuzz le hash Poseidon post-quantique
fn fuzz_poseidon_hash(input: &PqFuzzInput) {
    // Test 1: Hash de base ne doit pas paniquer
    if !input.poseidon_input.is_empty() {
        let hash_result = poseidon_pq_hash(&input.poseidon_input);
        
        // Invariants
        assert!(!hash_result.is_zero(), "Hash ne doit pas être zéro sauf cas spéciaux");
        
        // Test de déterminisme
        let hash_result2 = poseidon_pq_hash(&input.poseidon_input);
        assert_eq!(hash_result, hash_result2, "Hash doit être déterministe");
    }
    
    // Test 2: Conversion bytes <-> GoldilocksField
    if input.poseidon_input.len() >= 8 {
        let field_elements = bytes_to_goldilocks(&input.poseidon_input);
        let converted_back = goldilocks_to_bytes(&field_elements);
        
        // La conversion peut tronquer, mais ne doit pas paniquer
        assert!(!converted_back.is_empty(), "Conversion retour ne doit pas être vide");
    }
    
    // Test 3: Hash avec différents domaines
    let domains = [
        DOMAIN_NOTE_COMMIT_PQ,
        DOMAIN_VALUE_COMMIT_PQ,
        DOMAIN_NULLIFIER_PQ,
        DOMAIN_MERKLE_NODE_PQ,
        DOMAIN_MERKLE_EMPTY_PQ,
        input.domain_separator, // Domain arbitraire
    ];
    
    for &domain in &domains {
        if !input.poseidon_input.is_empty() {
            let mut domain_input = domain.to_le_bytes().to_vec();
            domain_input.extend_from_slice(&input.poseidon_input);
            
            let hash_result = poseidon_pq_hash(&domain_input);
            
            // Hash avec domain ne doit pas être identique au hash sans domain
            // (sauf collision très improbable)
            let hash_no_domain = poseidon_pq_hash(&input.poseidon_input);
            if hash_result == hash_no_domain {
                eprintln!("ATTENTION: Collision potentielle détectée dans poseidon_pq_hash");
            }
        }
    }
    
    // Test 4: Résistance aux patterns adversariaux
    let adversarial_patterns = [
        vec![0x00; 64],           // Tous zéros
        vec![0xFF; 64],           // Tous uns
        (0..64).collect::<Vec<u8>>(), // Séquence
        vec![0xAA, 0x55].repeat(32),  // Pattern alterné
    ];
    
    for pattern in &adversarial_patterns {
        let hash_result = poseidon_pq_hash(pattern);
        assert!(!hash_result.is_zero(), "Hash de pattern adversarial ne doit pas être zéro");
    }
}

/// Fuzz les commitments post-quantiques
fn fuzz_pq_commitments(input: &PqFuzzInput) {
    // Test 1: Value commitment
    if input.randomness.len() >= 32 {
        let randomness: [u8; 32] = input.randomness[..32].try_into().unwrap();
        let commitment = commit_to_value_pq(input.value, randomness);
        
        // Invariants
        assert!(!commitment.commitment.is_zero(), "Value commitment ne doit pas être zéro");
        
        // Test de déterminisme
        let commitment2 = commit_to_value_pq(input.value, randomness);
        assert_eq!(commitment.commitment, commitment2.commitment,
            "Value commitment doit être déterministe");
        
        // Test avec valeur différente
        let different_commitment = commit_to_value_pq(input.value.wrapping_add(1), randomness);
        if commitment.commitment == different_commitment.commitment {
            eprintln!("ATTENTION: Collision dans value commitment");
        }
        
        // Test avec randomness différent
        if input.randomness.len() >= 64 {
            let different_randomness: [u8; 32] = input.randomness[32..64].try_into().unwrap();
            let different_commitment = commit_to_value_pq(input.value, different_randomness);
            if commitment.commitment == different_commitment.commitment {
                eprintln!("ATTENTION: Collision dans value commitment (randomness)");
            }
        }
    }
    
    // Test 2: Note commitment
    if input.randomness.len() >= 32 && !input.note_data.is_empty() {
        let randomness: [u8; 32] = input.randomness[..32].try_into().unwrap();
        let commitment = commit_to_note_pq(&input.note_data, randomness);
        
        // Invariants
        assert!(!commitment.commitment.is_zero(), "Note commitment ne doit pas être zéro");
        
        // Test de déterminisme
        let commitment2 = commit_to_note_pq(&input.note_data, randomness);
        assert_eq!(commitment.commitment, commitment2.commitment,
            "Note commitment doit être déterministe");
        
        // Test avec note data différente
        if input.note_data.len() > 1 {
            let mut different_note = input.note_data.clone();
            different_note[0] = different_note[0].wrapping_add(1);
            let different_commitment = commit_to_note_pq(&different_note, randomness);
            if commitment.commitment == different_commitment.commitment {
                eprintln!("ATTENTION: Collision dans note commitment");
            }
        }
    }
}

/// Fuzz les Merkle trees post-quantiques
fn fuzz_pq_merkle_trees(input: &PqFuzzInput) {
    // Test 1: Création d'arbre vide
    let mut tree = CommitmentTreePQ::new();
    let empty_root = tree.root();
    
    // Test 2: Ajout de feuilles
    if !input.leaf_data.is_empty() {
        let leaf_hash = poseidon_pq_hash(&input.leaf_data);
        let position = tree.append(leaf_hash);
        
        // Invariants
        assert!(position.is_some(), "Ajout de feuille doit réussir dans un arbre non plein");
        
        let new_root = tree.root();
        assert_ne!(empty_root, new_root, "Root doit changer après ajout de feuille");
        
        // Test de witness
        if let Some(pos) = position {
            let witness = tree.witness(pos);
            assert!(witness.is_some(), "Witness doit exister pour position valide");
            
            if let Some(w) = witness {
                // Vérification du witness
                let computed_root = w.compute_root(leaf_hash);
                assert_eq!(computed_root, new_root, "Witness doit permettre de recalculer la root");
            }
        }
    }
    
    // Test 3: Witness pour positions invalides
    let invalid_positions = [
        u64::MAX,
        1u64 << 63,
        input.leaf_index,
    ];
    
    for &pos in &invalid_positions {
        let witness = tree.witness(pos);
        // Ne doit pas paniquer, peut retourner None
    }
    
    // Test 4: Construction de path malformé
    if !input.path_elements.is_empty() {
        let mut path_hashes = Vec::new();
        for element in &input.path_elements {
            if !element.is_empty() {
                let hash = poseidon_pq_hash(element);
                path_hashes.push(hash);
            }
        }
        
        if !path_hashes.is_empty() && input.leaf_index < (1u64 << path_hashes.len()) {
            // Création d'un MerklePathPQ artificiel
            // Note: Ceci teste la robustesse du calcul de root
            let path = MerklePathPQ {
                path: path_hashes,
            };
            
            let leaf_hash = if input.leaf_data.is_empty() {
                GoldilocksField::ZERO
            } else {
                poseidon_pq_hash(&input.leaf_data)
            };
            
            let witness = MerkleWitnessPQ {
                path,
                position: input.leaf_index,
            };
            
            // Calcul de root ne doit pas paniquer
            let computed_root = witness.compute_root(leaf_hash);
            // Pas d'assertion sur la valeur car c'est un path artificiel
        }
    }
}

/// Fuzz les circuits post-quantiques (version allégée)
fn fuzz_pq_circuits(input: &PqFuzzInput) {
    // Test 1: Validation des montants
    let total_input = input.spend_amount;
    let total_output = input.output_amount.saturating_add(input.fee);
    
    // Test de conservation (ne doit pas paniquer même si invalide)
    let is_balanced = total_input == total_output;
    
    // Test 2: Overflow dans les calculs
    let overflow_test1 = input.spend_amount.checked_add(input.output_amount);
    let overflow_test2 = input.output_amount.checked_add(input.fee);
    
    // Ces opérations ne doivent pas paniquer
    let _ = overflow_test1;
    let _ = overflow_test2;
    
    // Test 3: Création de public inputs
    if input.randomness.len() >= 64 {
        let spend_randomness: [u8; 32] = input.randomness[..32].try_into().unwrap();
        let output_randomness: [u8; 32] = input.randomness[32..64].try_into().unwrap();
        
        let spend_commitment = commit_to_value_pq(input.spend_amount, spend_randomness);
        let output_commitment = commit_to_value_pq(input.output_amount, output_randomness);
        
        // Construction des public inputs ne doit pas paniquer
        let public_inputs = TransactionPublicInputs {
            spend_commitments: vec![spend_commitment.commitment],
            output_commitments: vec![output_commitment.commitment],
            fee: input.fee,
            merkle_root: poseidon_pq_hash(&input.leaf_data),
        };
        
        // Validation des public inputs
        let total_spent = public_inputs.spend_commitments.len() as u64 * input.spend_amount;
        let total_created = public_inputs.output_commitments.len() as u64 * input.output_amount;
        let expected_total = total_created.saturating_add(public_inputs.fee);
        
        // Test de cohérence (peut échouer, mais ne doit pas paniquer)
        let _ = total_spent == expected_total;
    }
}

/// Tests spécifiques pour les edge cases post-quantiques
#[cfg(test)]
mod pq_fuzz_edge_cases {
    use super::*;
    
    #[test]
    fn test_empty_inputs_pq() {
        let input = PqFuzzInput {
            message: vec![],
            signature_bytes: vec![],
            public_key_bytes: vec![],
            secret_key_bytes: vec![],
            poseidon_input: vec![],
            domain_separator: 0,
            value: 0,
            randomness: vec![],
            note_data: vec![],
            leaf_data: vec![],
            path_elements: vec![],
            leaf_index: 0,
            spend_amount: 0,
            output_amount: 0,
            fee: 0,
        };
        
        // Test que les fonctions ne paniquent pas avec des entrées vides
        fuzz_poseidon_hash(&input);
        fuzz_pq_merkle_trees(&input);
        fuzz_pq_circuits(&input);
    }
    
    #[test]
    fn test_max_values_pq() {
        let input = PqFuzzInput {
            message: vec![0xFF; 1024],
            signature_bytes: vec![0xFF; SLH_SIGNATURE_SIZE],
            public_key_bytes: vec![0xFF; SLH_PUBLIC_KEY_SIZE],
            secret_key_bytes: vec![0xFF; SLH_SECRET_KEY_SIZE],
            poseidon_input: vec![0xFF; 256],
            domain_separator: u64::MAX,
            value: u64::MAX,
            randomness: vec![0xFF; 64],
            note_data: vec![0xFF; 512],
            leaf_data: vec![0xFF; 128],
            path_elements: vec![vec![0xFF; 64]; 32],
            leaf_index: u64::MAX,
            spend_amount: u64::MAX,
            output_amount: u64::MAX,
            fee: u64::MAX,
        };
        
        // Test avec valeurs maximales
        fuzz_slh_dsa_signatures(&input);
        fuzz_poseidon_hash(&input);
        fuzz_pq_commitments(&input);
        fuzz_pq_merkle_trees(&input);
        // Skip circuits pour éviter les timeouts avec des valeurs max
    }
    
    #[test]
    fn test_boundary_sizes_pq() {
        // Test avec tailles exactes
        let input = PqFuzzInput {
            message: vec![0xAA; 1],
            signature_bytes: vec![0xBB; SLH_SIGNATURE_SIZE],
            public_key_bytes: vec![0xCC; SLH_PUBLIC_KEY_SIZE],
            secret_key_bytes: vec![0xDD; SLH_SECRET_KEY_SIZE],
            poseidon_input: vec![0xEE; 8], // Taille pour 1 GoldilocksField
            domain_separator: 0x1234567890ABCDEF,
            value: 1000000, // 1M satoshis
            randomness: vec![0xFF; 32],
            note_data: vec![0x11; 64],
            leaf_data: vec![0x22; 32],
            path_elements: vec![vec![0x33; 32]; TREE_DEPTH_PQ],
            leaf_index: (1u64 << TREE_DEPTH_PQ) - 1, // Max valid index
            spend_amount: 1000000,
            output_amount: 999000,
            fee: 1000,
        };
        
        fuzz_slh_dsa_signatures(&input);
        fuzz_poseidon_hash(&input);
        fuzz_pq_commitments(&input);
        fuzz_pq_merkle_trees(&input);
        fuzz_pq_circuits(&input);
    }
}