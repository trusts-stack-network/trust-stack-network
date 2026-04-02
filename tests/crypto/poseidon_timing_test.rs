use tsn_crypto::poseidon::Poseidon2;
use criterion::black_box;
use rand::rngs::OsRng;

/// Test de side-channel sur Poseidon2
#[test]
fn test_poseidon_cache_timing() {
    let mut rng = OsRng;
    let hasher = Poseidon2::new();
    
    // Génère des entrées similaires
    let input1 = [1u8; 32];
    let mut input2 = input1.clone();
    input2[31] ^= 0x01; // Change un bit
    
    let mut timings1 = Vec::new();
    let mut timings2 = Vec::new();
    
    // Réchauffe le cache
    for _ in 0..100 {
        let _ = hasher.hash(&input1);
    }
    
    // Mesure le temps avec cache chaud
    for _ in 0..1000 {
        let start = std::time::Instant::now();
        let _ = hasher.hash(&input1);
        timings1.push(start.elapsed().as_nanos());
        
        let start = std::time::Instant::now();
        let _ = hasher.hash(&input2);
        timings2.push(start.elapsed().as_nanos());
    }
    
    // Calcule les statistiques
    let avg1 = timings1.iter().sum::<u128>() / timings1.len() as u128;
    let avg2 = timings2.iter().sum::<u128>() / timings2.len() as u128;
    
    // La différence doit être négligeable (< 2%)
    let diff = ((avg1 as i128 - avg2 as i128).abs() as u128 * 100) / avg1;
    assert!(diff < 2, "Cache timing attack détecté: {}% de différence", diff);
}