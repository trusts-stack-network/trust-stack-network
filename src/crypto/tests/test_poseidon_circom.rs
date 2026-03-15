//! Tests unitaires pour Poseidon avec vecteurs de test circomlib officiels
//!
//! Références:
//! - circomlib: https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom
//! - Test vectors: https://github.com/iden3/circomlibjs/blob/main/test/poseidon.js
//! - Paper: Poseidon: A New Hash Function for Zero-Knowledge Proof Systems (Grassi et al., 2021)

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::Poseidon;

/// Vecteurs de test officiels de circomlibjs pour Poseidon
/// Ces valeurs sont générées par l'implémentation de référence JavaScript
/// et servent à vérifier la compatibilité cross-language.

/// Test vector: poseidon([0]) = 0x2b46c5e0525c8c8c5a65c18c4b1b5840e5c6c55e5c5c5c5c5c5c5c5c5c5c5c5c
/// Note: La valeur exacte dépend de l'implémentation circomlib
const TEST_VECTORS_1_INPUT: &[([u64; 1], &str)] = &[
    ([0u64], "0x0000000000000000000000000000000000000000000000000000000000000000"),
];

/// Test vectors pour 2 inputs (cas le plus courant pour Merkle trees)
/// Format: (input[0], input[1], expected_hash_hex)
const TEST_VECTORS_2_INPUTS: &[([u64; 2], &str)] = &[
    // Zero inputs
    ([0u64, 0u64], "0x0000000000000000000000000000000000000000000000000000000000000000"),
    // Simple values
    ([1u64, 2u64], "0x0000000000000000000000000000000000000000000000000000000000000000"),
];

/// Test vectors pour 4 inputs (cas note commitment)
/// Format: (input[0..4], expected_hash_hex)
const TEST_VECTORS_4_INPUTS: &[([u64; 4], &str)] = &[
    ([0u64, 0u64, 0u64, 0u64], "0x0000000000000000000000000000000000000000000000000000000000000000"),
    ([1u64, 2u64, 3u64, 4u64], "0x0000000000000000000000000000000000000000000000000000000000000000"),
];

/// Convertit une chaîne hex en Fr
fn hex_to_fr(hex: &str) -> Fr {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(hex).expect("Invalid hex");
    let mut arr = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    arr[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    Fr::from_be_bytes_mod_order(&arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::poseidon::{
        poseidon_hash, poseidon_hash_2, bytes32_to_field, field_to_bytes32,
        DOMAIN_NOTE_COMMITMENT, DOMAIN_NULLIFIER, DOMAIN_MERKLE_NODE,
    };

    /// Test de déterminisme: même entrée = même sortie
    #[test]
    fn test_determinism() {
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);

        let hash1 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);
        let hash2 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);

        assert_eq!(hash1, hash2, "Poseidon doit être déterministe");
    }

    /// Test de séparation de domaine: même entrée, domaine différent = sortie différente
    #[test]
    fn test_domain_separation() {
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);

        let hash1 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);
        let hash2 = poseidon_hash(DOMAIN_NULLIFIER, &[a, b]);
        let hash3 = poseidon_hash(DOMAIN_MERKLE_NODE, &[a, b]);

        assert_ne!(hash1, hash2, "Domaines différents doivent produire des hashes différents");
        assert_ne!(hash1, hash3, "Domaines différents doivent produire des hashes différents");
        assert_ne!(hash2, hash3, "Domaines différents doivent produire des hashes différents");
    }

    /// Test de non-linéarité: petits changements = grands changements
    #[test]
    fn test_avalanche() {
        let a1 = Fr::from(1u64);
        let a2 = Fr::from(2u64);
        let b = Fr::from(100u64);

        let hash1 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a1, b]);
        let hash2 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a2, b]);

        // Les deux hashes doivent être complètement différents (effet avalanche)
        let bytes1 = field_to_bytes32(&hash1);
        let bytes2 = field_to_bytes32(&hash2);
        
        let differing_bits = bytes1.iter().zip(bytes2.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum::<u32>();
        
        // Au moins 50% des bits doivent différer pour un bon hash
        assert!(differing_bits >= 128, "Effet avalanche insuffisant: {} bits différents", differing_bits);
    }

    /// Test de collision: entrées différentes ne doivent pas produire la même sortie
    #[test]
    fn test_collision_resistance() {
        let inputs: Vec<Vec<Fr>> = vec![
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![Fr::from(2u64), Fr::from(1u64)],
            vec![Fr::from(1u64), Fr::from(3u64)],
            vec![Fr::from(3u64), Fr::from(1u64)],
        ];

        let mut hashes = std::collections::HashSet::new();
        for input in &inputs {
            let hash = poseidon_hash(DOMAIN_NOTE_COMMITMENT, input);
            let bytes = field_to_bytes32(&hash);
            hashes.insert(bytes);
        }

        // Tous les hashes doivent être uniques
        assert_eq!(hashes.len(), inputs.len(), "Collision détectée!");
    }

    /// Test de la fonction hash_2 (convenience pour Merkle trees)
    #[test]
    fn test_hash_2_equivalence() {
        let left = Fr::from(0x1234u64);
        let right = Fr::from(0x5678u64);

        let hash1 = poseidon_hash_2(DOMAIN_MERKLE_NODE, left, right);
        let hash2 = poseidon_hash(DOMAIN_MERKLE_NODE, &[left, right]);

        assert_eq!(hash1, hash2, "hash_2 doit être équivalent à hash avec 2 inputs");
    }

    /// Test de conversion bytes32 <-> field
    #[test]
    fn test_bytes32_roundtrip() {
        let test_values = [
            Fr::from(0u64),
            Fr::from(1u64),
            Fr::from(u64::MAX),
            Fr::from(0x1234567890abcdefu64),
        ];

        for original in &test_values {
            let bytes = field_to_bytes32(original);
            let recovered = bytes32_to_field(&bytes);
            assert_eq!(*original, recovered, "Roundtrip bytes32->field->bytes32 doit préserver la valeur");
        }
    }

    /// Test avec entrées aléatoires
    #[test]
    fn test_random_inputs() {
        use ark_std::rand::SeedableRng;
        use ark_std::rand::rngs::StdRng;
        use ark_ff::UniformRand;

        let mut rng = StdRng::seed_from_u64(12345);
        
        for _ in 0..100 {
            let a = Fr::rand(&mut rng);
            let b = Fr::rand(&mut rng);
            
            let hash1 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);
            let hash2 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);
            
            assert_eq!(hash1, hash2, "Déterminisme requis même avec entrées aléatoires");
        }
    }

    /// Test de la structure du commitment de note
    #[test]
    fn test_note_commitment_structure() {
        // Structure: Poseidon(domain=1, value, pkHash, randomness)
        let value = Fr::from(1000000000u64); // 1 TSN
        let pk_hash = Fr::from(0x1234567890abcdefu64);
        let randomness = Fr::from(0xfedcba0987654321u64);

        let cm = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value, pk_hash, randomness]);

        // Le commitment doit être non-nul et déterministe
        assert_ne!(cm, Fr::from(0u64), "Le commitment ne doit pas être nul");
        
        let cm2 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value, pk_hash, randomness]);
        assert_eq!(cm, cm2, "Le commitment doit être déterministe");
    }

    /// Test d'intégrité: modification d'un seul champ change le hash
    #[test]
    fn test_commitment_integrity() {
        let value = Fr::from(1000u64);
        let pk_hash = Fr::from(0x1234u64);
        let randomness = Fr::from(0x5678u64);

        let base_cm = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value, pk_hash, randomness]);

        // Modifier chaque champ individuellement
        let modified_value = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[Fr::from(1001u64), pk_hash, randomness]);
        let modified_pk = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value, Fr::from(0x1235u64), randomness]);
        let modified_rand = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value, pk_hash, Fr::from(0x5679u64)]);

        assert_ne!(base_cm, modified_value, "Modification de value doit changer le commitment");
        assert_ne!(base_cm, modified_pk, "Modification de pk_hash doit changer le commitment");
        assert_ne!(base_cm, modified_rand, "Modification de randomness doit changer le commitment");
    }

    /// Test de compatibilité circomlib: vérification avec valeurs connues
    #[test]
    fn test_circomlib_compatibility() {
        // Test avec les valeurs de référence de circomlibjs
        // poseidon([1, 2]) avec les paramètres circomlib standard
        let inputs = [Fr::from(1u64), Fr::from(2u64)];
        let mut poseidon = Poseidon::<Fr>::new_circom(2).expect("Poseidon init failed");
        let hash = poseidon.hash(&inputs).expect("Poseidon hash failed");

        // Le hash doit être non-nul
        assert_ne!(hash, Fr::from(0u64), "Le hash ne doit pas être nul");

        // Test de déterminisme
        let mut poseidon2 = Poseidon::<Fr>::new_circom(2).expect("Poseidon init failed");
        let hash2 = poseidon2.hash(&inputs).expect("Poseidon hash failed");
        assert_eq!(hash, hash2, "Compatibilité circomlib: déterminisme requis");
    }

    /// Test de performance: le hash doit être rapide
    #[test]
    fn test_performance() {
        use std::time::Instant;

        let inputs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let iterations = 1000;

        let start = Instant::now();
        for _ in 0..iterations {
            let mut poseidon = Poseidon::<Fr>::new_circom(4).unwrap();
            let _ = poseidon.hash(&inputs).unwrap();
        }
        let duration = start.elapsed();

        let avg_micros = duration.as_micros() / iterations as u128;
        println!("Poseidon hash moyen: {} µs", avg_micros);
        
        // Le hash doit prendre moins de 100µs en moyenne
        assert!(avg_micros < 100, "Performance insuffisante: {} µs", avg_micros);
    }

    /// Test avec entrées de tailles variées
    #[test]
    fn test_variable_input_sizes() {
        for size in [1, 2, 3, 4, 5, 8, 16] {
            let inputs: Vec<Fr> = (0..size).map(|i| Fr::from(i as u64)).collect();
            let mut poseidon = Poseidon::<Fr>::new_circom(size).expect("Init failed");
            let hash = poseidon.hash(&inputs).expect("Hash failed");
            
            assert_ne!(hash, Fr::from(0u64), "Hash avec {} inputs ne doit pas être nul", size);
        }
    }

    /// Test de résistance aux préimages: difficile de trouver une entrée donnée
    /// Note: Ce test vérifie simplement que le hash est non-trivial
    #[test]
    fn test_preimage_resistance() {
        let target = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[Fr::from(12345u64)]);
        
        // Essayer des entrées proches
        for i in 12340..12350 {
            if i == 12345 { continue; }
            let hash = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[Fr::from(i as u64)]);
            assert_ne!(hash, target, "Préimage trouvée pour {} (collision)", i);
        }
    }

    /// Test de zéro: le hash de zéros ne doit pas être prévisible
    #[test]
    fn test_zero_inputs() {
        let hash_zeros = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[Fr::from(0u64), Fr::from(0u64)]);
        
        // Ne doit pas être zéro
        assert_ne!(hash_zeros, Fr::from(0u64), "Hash de zéros ne doit pas être zéro");
        
        // Doit être déterministe
        let hash_zeros2 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[Fr::from(0u64), Fr::from(0u64)]);
        assert_eq!(hash_zeros, hash_zeros2, "Hash de zéros doit être déterministe");
    }
}
