#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::panic;
use std::time::Instant;

// Import des structures TSN à fuzzer
use tsn::core::{
    transaction::{
        Transaction, ShieldedTransaction, ShieldedTransactionV2, 
        CoinbaseTransaction, LegacyTransaction, MigrationTransaction,
        SpendDescription, OutputDescription, SpendDescriptionV2, OutputDescriptionV2
    },
    block::{BlockHeader, ShieldedBlock}
};

/// **PANIC HUNTER FUZZER**
/// 
/// Fuzzer ultra-agressif spécialement conçu pour détecter les panics
/// dans les désérialiseurs TSN. Cible les vulnérabilités critiques :
/// 
/// 1. **Panics non gérés** : unwrap(), expect(), index bounds
/// 2. **Stack overflow** : récursion infinie, structures imbriquées
/// 3. **Integer overflow** : calculs non vérifiés, débordements
/// 4. **Memory exhaustion** : allocations excessives
/// 5. **Timing attacks** : désérialisation non constant-time
/// 6. **Post-quantum vulns** : attaques hybrides V1/V2
/// 
/// **RÈGLE ABSOLUE** : Ce fuzzer ne doit JAMAIS paniquer.
/// Tout panic détecté = vulnérabilité critique à corriger.
#[derive(Arbitrary, Debug)]
struct PanicHunterInput {
    // Données brutes pour désérialisation
    raw_data: Vec<u8>,
    
    // Stratégies d'attaque ciblées
    target_type: DeserializeTarget,
    attack_vector: AttackVector,
    
    // Paramètres de mutation
    corruption_intensity: u8,      // 0-255: intensité de corruption
    amplification_factor: u16,     // 1-65535: facteur d'amplification
    recursion_depth: u8,           // 0-255: profondeur de récursion simulée
    memory_pressure: u8,           // 0-255: pression mémoire
}

#[derive(Arbitrary, Debug, Clone)]
enum DeserializeTarget {
    ShieldedTransactionV1,
    ShieldedTransactionV2,
    CoinbaseTransaction,
    LegacyTransaction,
    MigrationTransaction,
    BlockHeader,
    ShieldedBlock,
    SpendDescription,
    OutputDescription,
    SpendDescriptionV2,
    OutputDescriptionV2,
}

#[derive(Arbitrary, Debug, Clone)]
enum AttackVector {
    StackOverflow,          // Structures imbriquées infiniment
    IntegerOverflow,        // Valeurs proches de MAX
    MemoryExhaustion,       // Allocations massives
    CorruptedLengths,       // Longueurs incohérentes
    MalformedSignatures,    // Signatures corrompues
    TimingAttack,           // Mesure des temps de parsing
    HybridAttack,           // Mélange V1/V2
    BoundaryConditions,     // Valeurs limites
    RecursionBomb,          // Récursion profonde
    NullPointerDeref,       // Déréférencement null
}

fuzz_target!(|input: PanicHunterInput| {
    // **PROTECTION GLOBALE ANTI-PANIC**
    // Tout panic dans ce fuzzer indique une vulnérabilité critique
    let panic_result = panic::catch_unwind(|| {
        execute_attack(&input)
    });
    
    if let Err(panic_info) = panic_result {
        // VULNÉRABILITÉ CRITIQUE DÉTECTÉE !
        let panic_msg = if let Some(s) = panic_info.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = panic_info.downcast_ref::<&str>() {
            s.to_string()
        } else {
            "Unknown panic".to_string()
        };
        
        // Log détaillé pour debugging
        eprintln!("🚨 PANIC DÉTECTÉ - VULNÉRABILITÉ CRITIQUE 🚨");
        eprintln!("Target: {:?}", input.target_type);
        eprintln!("Attack: {:?}", input.attack_vector);
        eprintln!("Data size: {} bytes", input.raw_data.len());
        eprintln!("Panic message: {}", panic_msg);
        eprintln!("Corruption intensity: {}", input.corruption_intensity);
        eprintln!("Amplification: {}", input.amplification_factor);
        
        // Re-panic pour que libfuzzer capture la vulnérabilité
        panic!("CRITICAL VULNERABILITY: {} | Target: {:?} | Attack: {:?}", 
               panic_msg, input.target_type, input.attack_vector);
    }
});

fn execute_attack(input: &PanicHunterInput) {
    match input.attack_vector {
        AttackVector::StackOverflow => attack_stack_overflow(input),
        AttackVector::IntegerOverflow => attack_integer_overflow(input),
        AttackVector::MemoryExhaustion => attack_memory_exhaustion(input),
        AttackVector::CorruptedLengths => attack_corrupted_lengths(input),
        AttackVector::MalformedSignatures => attack_malformed_signatures(input),
        AttackVector::TimingAttack => attack_timing_analysis(input),
        AttackVector::HybridAttack => attack_hybrid_v1_v2(input),
        AttackVector::BoundaryConditions => attack_boundary_conditions(input),
        AttackVector::RecursionBomb => attack_recursion_bomb(input),
        AttackVector::NullPointerDeref => attack_null_pointer_deref(input),
    }
}

/// **ATTAQUE 1: STACK OVERFLOW**
/// Tente de créer des structures imbriquées qui causent un débordement de pile
fn attack_stack_overflow(input: &PanicHunterInput) {
    let mut nested_data = input.raw_data.clone();
    
    // Créer une structure profondément imbriquée
    for depth in 0..input.recursion_depth {
        let mut layer = Vec::new();
        
        // Ajouter des marqueurs de début de structure
        layer.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]); // Magic bytes
        layer.extend_from_slice(&(depth as u32).to_le_bytes()); // Profondeur
        layer.extend_from_slice(&nested_data);
        layer.extend_from_slice(&[0xFC, 0xFD, 0xFE, 0xFF]); // Magic bytes fin
        
        nested_data = layer;
        
        // Limite de sécurité pour éviter OOM dans le fuzzer lui-même
        if nested_data.len() > 50_000_000 { // 50MB max
            break;
        }
    }
    
    // Tenter la désérialisation avec timeout
    let start = Instant::now();
    let _ = attempt_deserialize(&input.target_type, &nested_data);
    let elapsed = start.elapsed();
    
    // Vérifier qu'on n'a pas de hang (potentiel stack overflow récupéré)
    if elapsed.as_secs() > 5 {
        panic!("STACK OVERFLOW SUSPECTED: Parsing took {}s for nested structure depth {}", 
               elapsed.as_secs(), input.recursion_depth);
    }
}

/// **ATTAQUE 2: INTEGER OVERFLOW**
/// Injecte des valeurs proches de MAX pour déclencher des overflows
fn attack_integer_overflow(input: &PanicHunterInput) {
    let mut overflow_data = input.raw_data.clone();
    
    // Valeurs dangereuses à injecter
    let dangerous_values = [
        u64::MAX,
        u64::MAX - 1,
        u64::MAX / 2,
        u32::MAX as u64,
        u32::MAX as u64 + 1,
        0x8000_0000_0000_0000u64, // i64::MIN as u64
        0x7FFF_FFFF_FFFF_FFFFu64, // i64::MAX as u64
    ];
    
    // Injecter ces valeurs à différents offsets
    for (i, &dangerous_val) in dangerous_values.iter().enumerate() {
        let offset = (i * 8) % overflow_data.len().max(1);
        let bytes = dangerous_val.to_le_bytes();
        
        // Remplacer 8 octets à partir de l'offset
        for (j, &byte) in bytes.iter().enumerate() {
            if offset + j < overflow_data.len() {
                overflow_data[offset + j] = byte;
            }
        }
    }
    
    // Amplifier selon le facteur d'amplification
    if input.amplification_factor > 1 {
        let multiplier = (input.amplification_factor as usize).min(1000);
        let mut amplified = Vec::new();
        for _ in 0..multiplier {
            amplified.extend_from_slice(&overflow_data);
        }
        overflow_data = amplified;
    }
    
    let _ = attempt_deserialize(&input.target_type, &overflow_data);
}

/// **ATTAQUE 3: MEMORY EXHAUSTION**
/// Tente d'allouer des quantités massives de mémoire
fn attack_memory_exhaustion(input: &PanicHunterInput) {
    // Créer des données qui suggèrent de grandes allocations
    let mut memory_bomb = input.raw_data.clone();
    
    // Injecter des "longueurs" énormes au début
    let fake_length = match input.memory_pressure {
        0..=63 => 1_000_000u64,      // 1MB
        64..=127 => 10_000_000u64,   // 10MB
        128..=191 => 100_000_000u64, // 100MB
        192..=223 => 500_000_000u64, // 500MB
        224..=239 => 1_000_000_000u64, // 1GB
        240..=247 => 2_000_000_000u64, // 2GB
        248..=251 => 4_000_000_000u64, // 4GB
        252..=254 => 8_000_000_000u64, // 8GB
        255 => u64::MAX,             // MAX (16 exabytes)
    };
    
    // Injecter cette longueur à plusieurs endroits
    let length_bytes = fake_length.to_le_bytes();
    for offset in (0..memory_bomb.len()).step_by(16) {
        for (i, &byte) in length_bytes.iter().enumerate() {
            if offset + i < memory_bomb.len() {
                memory_bomb[offset + i] = byte;
            }
        }
    }
    
    // Mesurer l'allocation mémoire avant/après
    let memory_before = get_approximate_memory_usage();
    let start = Instant::now();
    
    let _ = attempt_deserialize(&input.target_type, &memory_bomb);
    
    let elapsed = start.elapsed();
    let memory_after = get_approximate_memory_usage();
    let memory_delta = memory_after.saturating_sub(memory_before);
    
    // Alerter si allocation excessive ou temps excessif
    if memory_delta > 100_000_000 { // > 100MB
        panic!("MEMORY DOS: Allocated {}MB during parsing", memory_delta / 1_000_000);
    }
    
    if elapsed.as_millis() > 1000 { // > 1s
        panic!("TIMING DOS: Parsing took {}ms", elapsed.as_millis());
    }
}

/// **ATTAQUE 4: LONGUEURS CORROMPUES**
/// Injecte des longueurs incohérentes pour tromper les parsers
fn attack_corrupted_lengths(input: &PanicHunterInput) {
    let mut corrupted = input.raw_data.clone();
    
    // Stratégies de corruption des longueurs
    match input.corruption_intensity % 4 {
        0 => {
            // Longueurs négatives (interprétées comme très grandes)
            for i in (0..corrupted.len()).step_by(4) {
                if i + 4 <= corrupted.len() {
                    corrupted[i..i+4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
                }
            }
        },
        1 => {
            // Longueurs incohérentes (plus grandes que les données disponibles)
            let fake_len = corrupted.len() as u64 * 1000;
            for i in (0..corrupted.len()).step_by(8) {
                if i + 8 <= corrupted.len() {
                    corrupted[i..i+8].copy_from_slice(&fake_len.to_le_bytes());
                }
            }
        },
        2 => {
            // Longueurs nulles là où elles ne devraient pas l'être
            for i in (0..corrupted.len()).step_by(4) {
                if i + 4 <= corrupted.len() {
                    corrupted[i..i+4].copy_from_slice(&0u32.to_le_bytes());
                }
            }
        },
        _ => {
            // Longueurs avec des valeurs limites
            let boundary_values = [1, 2, 3, 4, 8, 16, 32, 64, 128, 255, 256, 65535, 65536];
            for (idx, &val) in boundary_values.iter().enumerate() {
                let offset = (idx * 4) % corrupted.len().max(4);
                if offset + 4 <= corrupted.len() {
                    corrupted[offset..offset+4].copy_from_slice(&(val as u32).to_le_bytes());
                }
            }
        }
    }
    
    let _ = attempt_deserialize(&input.target_type, &corrupted);
}

/// **ATTAQUE 5: SIGNATURES MALFORMÉES**
/// Corrompt spécifiquement les zones de signature pour tester la robustesse crypto
fn attack_malformed_signatures(input: &PanicHunterInput) {
    let mut corrupted = input.raw_data.clone();
    
    // Patterns de corruption de signature
    let corruption_patterns = [
        vec![0x00; 64],  // Signature nulle
        vec![0xFF; 64],  // Signature max
        vec![0xAA; 64],  // Pattern répétitif
        vec![0x55; 64],  // Pattern alternatif
    ];
    
    let pattern = &corruption_patterns[input.corruption_intensity as usize % corruption_patterns.len()];
    
    // Injecter le pattern à plusieurs endroits (zones potentielles de signature)
    for offset in (0..corrupted.len()).step_by(64) {
        if offset + 64 <= corrupted.len() {
            corrupted[offset..offset+64].copy_from_slice(pattern);
        }
    }
    
    // Ajouter du bruit crypto-spécifique
    for i in 0..corrupted.len() {
        if i % 32 == 0 {
            // Corrompre les premiers octets de chaque bloc de 32 (taille hash typique)
            corrupted[i] = corrupted[i].wrapping_add(input.corruption_intensity);
        }
    }
    
    let _ = attempt_deserialize(&input.target_type, &corrupted);
}

/// **ATTAQUE 6: ANALYSE TEMPORELLE**
/// Mesure les temps de parsing pour détecter les timing attacks
fn attack_timing_analysis(input: &PanicHunterInput) {
    let mut timings = Vec::new();
    
    // Effectuer plusieurs mesures avec des données légèrement différentes
    for variation in 0..10 {
        let mut variant_data = input.raw_data.clone();
        
        // Appliquer une variation mineure
        if !variant_data.is_empty() {
            let idx = variation % variant_data.len();
            variant_data[idx] = variant_data[idx].wrapping_add(variation as u8);
        }
        
        let start = Instant::now();
        let _ = attempt_deserialize(&input.target_type, &variant_data);
        let elapsed = start.elapsed();
        
        timings.push(elapsed);
    }
    
    // Analyser la variance des temps
    if timings.len() >= 2 {
        let min_time = timings.iter().min().unwrap();
        let max_time = timings.iter().max().unwrap();
        let variance = max_time.saturating_sub(*min_time);
        
        // Alerter si variance temporelle suspecte (> 10ms)
        if variance.as_millis() > 10 {
            panic!("TIMING ATTACK VECTOR: Variance {}ms between similar inputs", 
                   variance.as_millis());
        }
    }
}

/// **ATTAQUE 7: HYBRIDE V1/V2**
/// Mélange des structures V1 et V2 pour tester la robustesse des transitions
fn attack_hybrid_v1_v2(input: &PanicHunterInput) {
    let mut hybrid_data = input.raw_data.clone();
    
    // Injecter des marqueurs V1 et V2 de manière incohérente
    let v1_marker = b"BN254_GROTH16";
    let v2_marker = b"MLDSA65_PLONKY2";
    
    // Alterner les marqueurs
    for (i, chunk) in hybrid_data.chunks_mut(32).enumerate() {
        let marker = if i % 2 == 0 { v1_marker } else { v2_marker };
        let copy_len = chunk.len().min(marker.len());
        chunk[..copy_len].copy_from_slice(&marker[..copy_len]);
    }
    
    // Tenter de désérialiser comme V1 puis V2
    let _ = attempt_deserialize(&DeserializeTarget::ShieldedTransactionV1, &hybrid_data);
    let _ = attempt_deserialize(&DeserializeTarget::ShieldedTransactionV2, &hybrid_data);
}

/// **ATTAQUE 8: CONDITIONS LIMITES**
/// Teste les valeurs aux frontières des types
fn attack_boundary_conditions(input: &PanicHunterInput) {
    let boundary_values = [
        0u8, 1u8, 127u8, 128u8, 255u8,
        0u16, 1u16, 32767u16, 32768u16, 65535u16,
        0u32, 1u32, 2147483647u32, 2147483648u32, 4294967295u32,
        0u64, 1u64, 9223372036854775807u64, 9223372036854775808u64, 18446744073709551615u64,
    ];
    
    let mut boundary_data = input.raw_data.clone();
    
    // Injecter des valeurs limites
    for (i, &val) in boundary_values.iter().enumerate() {
        let offset = (i * 8) % boundary_data.len().max(1);
        let bytes = val.to_le_bytes();
        
        for (j, &byte) in bytes.iter().enumerate() {
            if offset + j < boundary_data.len() {
                boundary_data[offset + j] = byte;
            }
        }
    }
    
    let _ = attempt_deserialize(&input.target_type, &boundary_data);
}

/// **ATTAQUE 9: BOMBE DE RÉCURSION**
/// Crée des structures auto-référentielles
fn attack_recursion_bomb(input: &PanicHunterInput) {
    let mut recursive_data = input.raw_data.clone();
    
    // Créer une référence circulaire en copiant le début vers la fin
    if recursive_data.len() > 64 {
        let mid = recursive_data.len() / 2;
        recursive_data[mid..].copy_from_slice(&recursive_data[..mid]);
    }
    
    // Ajouter des marqueurs de récursion
    for depth in 0..input.recursion_depth {
        if recursive_data.len() > depth as usize * 4 + 4 {
            let offset = depth as usize * 4;
            recursive_data[offset..offset+4].copy_from_slice(&depth.to_le_bytes());
        }
    }
    
    let _ = attempt_deserialize(&input.target_type, &recursive_data);
}

/// **ATTAQUE 10: DÉRÉFÉRENCEMENT NULL**
/// Tente de créer des conditions de déréférencement null
fn attack_null_pointer_deref(input: &PanicHunterInput) {
    let mut null_data = input.raw_data.clone();
    
    // Injecter des patterns qui pourraient être interprétés comme des pointeurs null
    let null_patterns = [
        vec![0x00; 8],  // Pointeur null 64-bit
        vec![0x00; 4],  // Pointeur null 32-bit
        vec![0xFF; 8],  // Pointeur invalide
    ];
    
    for (i, pattern) in null_patterns.iter().enumerate() {
        let offset = (i * pattern.len()) % null_data.len().max(pattern.len());
        if offset + pattern.len() <= null_data.len() {
            null_data[offset..offset+pattern.len()].copy_from_slice(pattern);
        }
    }
    
    let _ = attempt_deserialize(&input.target_type, &null_data);
}

/// Tente de désérialiser selon le type cible
fn attempt_deserialize(target: &DeserializeTarget, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    match target {
        DeserializeTarget::ShieldedTransactionV1 => {
            let _: ShieldedTransaction = bincode::deserialize(data)?;
        },
        DeserializeTarget::ShieldedTransactionV2 => {
            let _: ShieldedTransactionV2 = bincode::deserialize(data)?;
        },
        DeserializeTarget::CoinbaseTransaction => {
            let _: CoinbaseTransaction = bincode::deserialize(data)?;
        },
        DeserializeTarget::LegacyTransaction => {
            let _: LegacyTransaction = bincode::deserialize(data)?;
        },
        DeserializeTarget::MigrationTransaction => {
            let _: MigrationTransaction = bincode::deserialize(data)?;
        },
        DeserializeTarget::BlockHeader => {
            let _: BlockHeader = bincode::deserialize(data)?;
        },
        DeserializeTarget::ShieldedBlock => {
            let _: ShieldedBlock = bincode::deserialize(data)?;
        },
        DeserializeTarget::SpendDescription => {
            let _: SpendDescription = bincode::deserialize(data)?;
        },
        DeserializeTarget::OutputDescription => {
            let _: OutputDescription = bincode::deserialize(data)?;
        },
        DeserializeTarget::SpendDescriptionV2 => {
            let _: SpendDescriptionV2 = bincode::deserialize(data)?;
        },
        DeserializeTarget::OutputDescriptionV2 => {
            let _: OutputDescriptionV2 = bincode::deserialize(data)?;
        },
    }
    Ok(())
}

/// Estimation approximative de l'usage mémoire
fn get_approximate_memory_usage() -> usize {
    // Dans un vrai environnement de production, on utiliserait jemalloc ou similar
    // Ici on simule avec une estimation basée sur les variables d'environnement
    std::env::var("MEMORY_USAGE_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}