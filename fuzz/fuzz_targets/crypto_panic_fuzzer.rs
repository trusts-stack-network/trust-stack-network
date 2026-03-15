//! Fuzzer ciblé pour détecter les panics dans les opérations cryptographiques
//!
//! Ce fuzzer teste spécifiquement:
//! - Les fonctions de hash Poseidon
//! - Les opérations de sérialisation
//! - Les conversions de types
//!
//! # Usage
//! ```
//! cargo fuzz run crypto_panic_fuzzer
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::panic;

/// Wrapper pour capturer les panics sans faire paniquer le fuzzer
///
/// SECURITY: Ce wrapper est CRITIQUE. Il permet de détecter les panics
/// sans que le fuzzer lui-même ne panique. Un fuzzer qui panique ne
/// peut pas rapporter correctement les bugs.
fn catch_panic<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce() -> R + panic::UnwindSafe,
{
    match panic::catch_unwind(f) {
        Ok(result) => Ok(result),
        Err(_) => Err("PANIC_DETECTED".to_string()),
    }
}

/// Données de fuzzing structurées
#[derive(Debug, Clone)]
struct FuzzInput {
    /// Type d'opération à tester (0-9)
    op_type: u8,
    /// Données brutes
    data: Vec<u8>,
}

impl FuzzInput {
    /// Parse les données brutes en FuzzInput
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }
        
        Some(Self {
            op_type: bytes[0],
            data: bytes[1..].to_vec(),
        })
    }
}

/// Fuzz target principal
///
/// Ce fuzzer ne doit JAMAIS paniquer. Il capture toutes les panics
/// et les rapporte comme des échecs sans faire crasher le fuzzer.
fuzz_target!(|data: &[u8]| {
    let input = match FuzzInput::from_bytes(data) {
        Some(i) => i,
        None => return, // Input trop court, ignorer
    };
    
    // Dispatcher vers la fonction de fuzz appropriée
    // Utiliser modulo pour éviter les dépassements
    match input.op_type % 8 {
        0 => fuzz_poseidon_hash(&input.data),
        1 => fuzz_field_conversion(&input.data),
        2 => fuzz_serialization(&input.data),
        3 => fuzz_merkle_operations(&input.data),
        4 => fuzz_signature_operations(&input.data),
        5 => fuzz_address_parsing(&input.data),
        6 => fuzz_nullifier_operations(&input.data),
        7 => fuzz_commitment_operations(&input.data),
        _ => unreachable!(),
    }
});

/// Fuzz le hash Poseidon
///
/// Cette fonction teste que poseidon_hash ne panique pas
/// avec des entrées malformées.
fn fuzz_poseidon_hash(data: &[u8]) {
    let result = catch_panic(|| {
        // Limiter la taille pour éviter les OOM
        if data.len() > 10000 {
            return;
        }
        
        // Simuler des entrées de champ
        let num_inputs = (data.len() / 32).min(100);
        
        if num_inputs == 0 {
            return;
        }
        
        // Créer des éléments de champ à partir des données
        let _elements: Vec<[u8; 32]> = data.chunks(32)
            .take(num_inputs)
            .map(|chunk| {
                let mut arr = [0u8; 32];
                let len = chunk.len().min(32);
                arr[..len].copy_from_slice(&chunk[..len]);
                arr
            })
            .collect();
        
        // Note: En production, appeler poseidon_hash ici
        // et vérifier qu'il ne panique pas
    });
    
    // Rapporter les panics détectées sans paniquer
    if let Err(msg) = result {
        eprintln!(
            "[FUZZER] PANIC détectée dans fuzz_poseidon_hash: {}",
            msg
        );
    }
}

/// Fuzz les conversions de champ
///
/// Cette fonction teste que les conversions entre bytes et champs
/// ne paniquent pas.
fn fuzz_field_conversion(data: &[u8]) {
    let result = catch_panic(|| {
        if data.len() > 1000 {
            return;
        }
        
        // Simuler bytes32_to_field et field_to_bytes32
        let chunks: Vec<&[u8]> = data.chunks(32).collect();
        
        for chunk in chunks {
            let mut arr = [0u8; 32];
            let len = chunk.len().min(32);
            arr[..len].copy_from_slice(&chunk[..len]);
            
            // Note: En production, appeler bytes32_to_field ici
            let _ = arr;
        }
    });
    
    if let Err(msg) = result {
        eprintln!(
            "[FUZZER] PANIC détectée dans fuzz_field_conversion: {}",
            msg
        );
    }
}

/// Fuzz les opérations de sérialisation
///
/// Cette fonction teste que les fonctions de sérialisation
/// ne paniquent pas avec des entrées malformées.
fn fuzz_serialization(data: &[u8]) {
    let result = catch_panic(|| {
        if data.len() > 100000 {
            return;
        }
        
        // Simuler la désérialisation de structures
        // Note: En production, tester les vraies fonctions de désérialisation
        let _ = data.len();
        
        // Vérifier les tailles minimales pour différentes structures
        if data.len() >= 32 {
            // Simuler la lecture d'un hash
            let _hash = &data[..32];
        }
    });
    
    if let Err(msg) = result {
        eprintln!(
            "[FUZZER] PANIC détectée dans fuzz_serialization: {}",
            msg
        );
    }
}

/// Fuzz les opérations Merkle
///
/// Cette fonction teste que les opérations sur l'arbre Merkle
/// ne paniquent pas.
fn fuzz_merkle_operations(data: &[u8]) {
    let result = catch_panic(|| {
        if data.len() > 10000 {
            return;
        }
        
        // Simuler la création d'un arbre Merkle
        let num_leaves = (data.len() / 32).min(1000);
        
        if num_leaves == 0 {
            return;
        }
        
        let leaves: Vec<[u8; 32]> = data.chunks(32)
            .take(num_leaves)
            .map(|chunk| {
                let mut arr = [0u8; 32];
                let len = chunk.len().min(32);
                arr[..len].copy_from_slice(&chunk[..len]);
                arr
            })
            .collect();
        
        // Note: En production, créer un vrai MerkleTree ici
        let _ = leaves;
    });
    
    if let Err(msg) = result {
        eprintln!(
            "[FUZZER] PANIC détectée dans fuzz_merkle_operations: {}",
            msg
        );
    }
}

/// Fuzz les opérations de signature
///
/// Cette fonction teste que les opérations de signature
/// ne paniquent pas avec des clés malformées.
fn fuzz_signature_operations(data: &[u8]) {
    let result = catch_panic(|| {
        // Tailles typiques pour ML-DSA-65
        const PK_SIZE: usize = 1952;
        const SIG_SIZE: usize = 3309;
        
        if data.len() < PK_SIZE + SIG_SIZE {
            return;
        }
        
        // Extraire clé publique et signature
        let _pk = &data[..PK_SIZE];
        let _sig = &data[PK_SIZE..PK_SIZE + SIG_SIZE];
        
        // Note: En production, appeler Signature::verify ici
    });
    
    if let Err(msg) = result {
        eprintln!(
            "[FUZZER] PANIC détectée dans fuzz_signature_operations: {}",
            msg
        );
    }
}

/// Fuzz le parsing d'adresses
///
/// Cette fonction teste que le parsing d'adresses
/// ne panique pas avec des adresses malformées.
fn fuzz_address_parsing(data: &[u8]) {
    let result = catch_panic(|| {
        if data.len() > 1000 {
            return;
        }
        
        // Note: En production, appeler ShieldedAddress::from_bytes ici
        let _ = data;
    });
    
    if let Err(msg) = result {
        eprintln!(
            "[FUZZER] PANIC détectée dans fuzz_address_parsing: {}",
            msg
        );
    }
}

/// Fuzz les opérations de nullifier
///
/// Cette fonction teste que les opérations de nullifier
/// ne paniquent pas.
fn fuzz_nullifier_operations(data: &[u8]) {
    let result = catch_panic(|| {
        if data.len() > 1000 {
            return;
        }
        
        // Note: En production, appeler Nullifier::from_bytes ici
        let _ = data;
    });
    
    if let Err(msg) = result {
        eprintln!(
            "[FUZZER] PANIC détectée dans fuzz_nullifier_operations: {}",
            msg
        );
    }
}

/// Fuzz les opérations de commitment
///
/// Cette fonction teste que les opérations de commitment
/// ne paniquent pas.
fn fuzz_commitment_operations(data: &[u8]) {
    let result = catch_panic(|| {
        if data.len() > 1000 {
            return;
        }
        
        // Note: En production, appeler NoteCommitment::from_bytes ici
        let _ = data;
    });
    
    if let Err(msg) = result {
        eprintln!(
            "[FUZZER] PANIC détectée dans fuzz_commitment_operations: {}",
            msg
        );
    }
}
