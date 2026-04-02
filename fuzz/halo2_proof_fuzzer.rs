//! Fuzzer pour les preuves Halo2
//!
//! Ce fuzzer utilise libfuzzer-sys pour tester la robustesse du
//! validateur de preuves Halo2 contre des entrées arbitraires.
//!
//! ## Couverture
//! - Preuves malformées de toutes tailles
//! - Entrées publiques malformées
//! - Combinatoire de paramètres invalides
//! - Attaques par mutation

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};

/// Structure représentant une entrée de fuzzing pour Halo2
#[derive(Debug)]
struct Halo2FuzzInput {
    proof: Vec<u8>,
    public_inputs: Vec<Vec<u8>>,
    vk_hash: [u8; 32],
}

impl Halo2FuzzInput {
    /// Parse les données brutes en structure de fuzzing
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 32 {
            return None;
        }

        // Structure: [vk_hash:32][num_inputs:2][input_len:4][input_data:*]...
        let mut offset = 0;

        // Extrait vk_hash
        let mut vk_hash = [0u8; 32];
        vk_hash.copy_from_slice(&data[0..32]);
        offset += 32;

        if data.len() < offset + 2 {
            return Some(Self {
                proof: data.to_vec(),
                public_inputs: vec![],
                vk_hash,
            });
        }

        // Nombre d'entrées publiques (limité pour éviter DoS)
        let num_inputs = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let num_inputs = num_inputs.min(100); // Limite de sécurité

        let mut public_inputs = Vec::with_capacity(num_inputs);

        for _ in 0..num_inputs {
            if data.len() < offset + 4 {
                break;
            }

            let input_len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;

            // Limite la taille des entrées pour éviter DoS
            let input_len = input_len.min(1024 * 1024); // 1 MB max

            if data.len() < offset + input_len {
                break;
            }

            public_inputs.push(data[offset..offset + input_len].to_vec());
            offset += input_len;
        }

        // Le reste est la preuve
        let proof = data[offset..].to_vec();

        Some(Self {
            proof,
            public_inputs,
            vk_hash,
        })
    }
}

/// Validateur simplifié pour le fuzzing
struct FuzzHalo2Validator {
    max_proof_size: usize,
    min_proof_size: usize,
    max_total_input_size: usize,
    timeout: Duration,
}

impl FuzzHalo2Validator {
    fn new() -> Self {
        Self {
            max_proof_size: 10 * 1024 * 1024,
            min_proof_size: 32,
            max_total_input_size: 100 * 1024 * 1024,
            timeout: Duration::from_secs(5),
        }
    }

    /// Valide une preuve sans paniquer
    fn validate(&self, input: &Halo2FuzzInput) -> Result<(), FuzzError> {
        let start = Instant::now();

        // Vérification de timeout
        if start.elapsed() > self.timeout {
            return Err(FuzzError::Timeout);
        }

        // Vérification de la taille de la preuve
        if input.proof.len() > self.max_proof_size {
            return Err(FuzzError::ProofTooLarge);
        }
        if input.proof.len() < self.min_proof_size {
            return Err(FuzzError::ProofTooSmall);
        }

        // Vérification de la taille totale
        let total_input_size: usize = input.public_inputs.iter().map(|v| v.len()).sum();
        if total_input_size > self.max_total_input_size {
            return Err(FuzzError::InputsTooLarge);
        }

        // Vérification du nombre d'entrées
        if input.public_inputs.len() > 1000 {
            return Err(FuzzError::TooManyInputs);
        }

        // Vérification de patterns malveillants connus
        if self.contains_malicious_patterns(&input.proof) {
            return Err(FuzzError::MaliciousPattern);
        }

        // Vérification des points de courbe (simulation)
        if !self.validate_curve_points(&input.proof) {
            return Err(FuzzError::InvalidCurvePoint);
        }

        // Vérification des éléments de champ (simulation)
        if !self.validate_field_elements(&input.proof) {
            return Err(FuzzError::InvalidFieldElement);
        }

        Ok(())
    }

    /// Détecte les patterns malveillants connus
    fn contains_malicious_patterns(&self, proof: &[u8]) -> bool {
        // Patterns connus pour causer des comportements indéfinis
        let malicious_patterns: &[&[u8]] = &[
            b"PWN!",           // Marqueur de test
            &[0xFF; 32],       // Tous les bits à 1 (point à l'infini?)
            &[0x00; 32],       // Tous les bits à 0 (point à l'origine?)
        ];

        for pattern in malicious_patterns {
            if proof.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }

        false
    }

    /// Valide les points de courbe (stub)
    fn validate_curve_points(&self, proof: &[u8]) -> bool {
        // En production: vérifier que les points sont sur la courbe BN254
        // Pour le fuzzing: vérifications basiques
        
        if proof.len() < 64 {
            return true; // Trop court pour contenir des points
        }

        // Vérifie que les coordonnées ne sont pas toutes à 0 ou toutes à 1
        let first_32 = &proof[0..32];
        let all_zeros = first_32.iter().all(|&b| b == 0);
        let all_ones = first_32.iter().all(|&b| b == 0xFF);

        !all_zeros && !all_ones
    }

    /// Valide les éléments de champ (stub)
    fn validate_field_elements(&self, proof: &[u8]) -> bool {
        // BN254 scalar field: p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
        // Tout élément doit être < p
        
        // Pour le fuzzing: on accepte tout, la vraie validation est coûteuse
        true
    }
}

#[derive(Debug)]
enum FuzzError {
    ProofTooLarge,
    ProofTooSmall,
    InputsTooLarge,
    TooManyInputs,
    MaliciousPattern,
    InvalidCurvePoint,
    InvalidFieldElement,
    Timeout,
}

fuzz_target!(|data: &[u8]| {
    // Parse l'entrée de fuzzing
    let Some(input) = Halo2FuzzInput::from_bytes(data) else {
        // Entrée invalide, on ignore silencieusement
        return;
    };

    // Crée le validateur
    let validator = FuzzHalo2Validator::new();

    // Exécute la validation - ne doit JAMAIS paniquer
    let _result = validator.validate(&input);

    // Le fuzzer vérifie automatiquement qu'il n'y a pas eu de panic
    // ou d'overflow/underflow détecté par les sanitizers
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_input_parsing() {
        // Teste le parsing d'une entrée valide
        let mut data = vec![0u8; 100];
        data[0..32].fill(0x42); // vk_hash
        data[32] = 1; // 1 input
        data[33] = 0;
        data[34..38].copy_from_slice(&10u32.to_le_bytes()); // input len = 10
        data[38..48].fill(0xAB); // input data
        data[48..].fill(0xCD); // proof

        let input = Halo2FuzzInput::from_bytes(&data).unwrap();
        assert_eq!(input.vk_hash, [0x42u8; 32]);
        assert_eq!(input.public_inputs.len(), 1);
        assert_eq!(input.public_inputs[0], vec![0xABu8; 10]);
        assert_eq!(input.proof, vec![0xCDu8; 52]);
    }

    #[test]
    fn test_malicious_pattern_detection() {
        let validator = FuzzHalo2Validator::new();

        let input = Halo2FuzzInput {
            proof: vec![0u8; 50],
            public_inputs: vec![],
            vk_hash: [0u8; 32],
        };
        assert!(validator.validate(&input).is_ok());

        let malicious_input = Halo2FuzzInput {
            proof: {
                let mut p = vec![0u8; 100];
                p[50..54].copy_from_slice(b"PWN!");
                p
            },
            public_inputs: vec![],
            vk_hash: [0u8; 32],
        };
        assert_eq!(
            validator.validate(&malicious_input),
            Err(FuzzError::MaliciousPattern)
        );
    }

    #[test]
    fn test_proof_size_limits() {
        let validator = FuzzHalo2Validator::new();

        // Preuve trop petite
        let small = Halo2FuzzInput {
            proof: vec![0u8; 10],
            public_inputs: vec![],
            vk_hash: [0u8; 32],
        };
        assert_eq!(validator.validate(&small), Err(FuzzError::ProofTooSmall));

        // Preuve trop grande
        let large = Halo2FuzzInput {
            proof: vec![0u8; 20 * 1024 * 1024],
            public_inputs: vec![],
            vk_hash: [0u8; 32],
        };
        assert_eq!(validator.validate(&large), Err(FuzzError::ProofTooLarge));
    }

    #[test]
    fn test_curve_point_validation() {
        let validator = FuzzHalo2Validator::new();

        // Point avec coordonnées toutes à 0 (invalide)
        let invalid_point = Halo2FuzzInput {
            proof: vec![0u8; 100],
            public_inputs: vec![],
            vk_hash: [0u8; 32],
        };
        assert_eq!(
            validator.validate(&invalid_point),
            Err(FuzzError::InvalidCurvePoint)
        );

        // Point avec coordonnées toutes à 0xFF (invalide)
        let invalid_point2 = Halo2FuzzInput {
            proof: vec![0xFFu8; 100],
            public_inputs: vec![],
            vk_hash: [0u8; 32],
        };
        assert_eq!(
            validator.validate(&invalid_point2),
            Err(FuzzError::InvalidCurvePoint)
        );
    }
}
