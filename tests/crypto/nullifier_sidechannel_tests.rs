use tsn_crypto::nullifier::{derive_nullifier, Nullifier};
use tsn_crypto::note::Note;
use tsn_crypto::keys::SecretKey;
use rand::{Rng, thread_rng};
use std::collections::HashMap;

/// Test de détection de side-channel sur la dérivation de nullifier
/// Un attaquant pourrait observer les patterns mémoire/cache
#[test]
fn test_nullifier_derivation_sidechannel() {
    let mut rng = thread_rng();
    let secret = SecretKey::generate(&mut rng);
    
    // Crée plusieurs notes avec des valeurs différentes
    let notes: Vec<Note> = (0..100).map(|i| {
        Note::new(
            secret.public_key(),
            (i as u64) * 1000, // valeurs distinctes
            &mut rng
        )
    }).collect();
    
    // Mesure le temps de dérivation pour chaque note
    let mut derivation_times = HashMap::new();
    
    for (idx, note) in notes.iter().enumerate() {
        let start = std::time::Instant::now();
        let nullifier = derive_nullifier(&secret, note);
        let duration = start.elapsed();
        
        derivation_times.insert(idx, (duration, nullifier));
    }
    
    // Analyse les patterns de timing
    // Si le temps varie significativement avec la valeur, il y a un leak
    let times: Vec<_> = derivation_times.values()
        .map(|(dur, _)| dur.as_nanos())
        .collect();
    
    // Calcule la variance
    let mean = times.iter().sum::<u128>() / times.len() as u128;
    let variance = times.iter()
        .map(|&x| (x as i128 - mean as i128).pow(2))
        .sum::<i128>() / times.len() as i128;
    
    // Une variance > 1000 ns² suggère une dépendance aux données
    assert!(
        variance < 1000,
        "Side-channel detected: high timing variance {}ns²", variance
    );
    
    // Vérifie que les nullifiers sont uniques
    let nullifiers: Vec<_> = derivation_times.values()
        .map(|(_, n)| *n)
        .collect();
    
    let unique_nullifiers: std::collections::HashSet<_> = nullifiers.iter().collect();
    assert_eq!(
        nullifiers.len(),
        unique_nullifiers.len(),
        "Duplicate nullifiers detected - critical vulnerability!"
    );
}

/// Test de détection de patterns dans les nullifiers
#[test]
fn test_nullifier_randomness() {
    let mut rng = thread_rng();
    let secret = SecretKey::generate(&mut rng);
    
    let mut nullifiers = Vec::new();
    
    // Génère 1000 nullifiers
    for _ in 0..1000 {
        let note = Note::new(secret.public_key(), 1000, &mut rng);
        let nullifier = derive_nullifier(&secret, &note);
        nullifiers.push(nullifier);
    }
    
    // Test 1: Distribution des bits doit être uniforme
    let bit_counts = count_bits(&nullifiers);
    let expected_per_bit = nullifiers.len() / 8; // 8 bits par byte
    
    for (byte_idx, byte_counts) in bit_counts.iter().enumerate() {
        for (bit_idx, &count) in byte_counts.iter().enumerate() {
            // Chaque bit devrait être setté ~50% du temps
            let ratio = count as f64 / nullifiers.len() as f64;
            assert!(
                (0.4..=0.6).contains(&ratio),
                "