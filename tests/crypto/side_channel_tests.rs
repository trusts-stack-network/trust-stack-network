use tsn::crypto::keys::{generate_keypair, PublicKey};
use tsn::crypto::signature::sign;
use std::hint::black_box;
use std::time::{Instant, Duration};

#[test]
fn test_constant_time_scalar_multiplication() {
    let rng = &mut rand::thread_rng();
    let (sk1, pk1) = generate_keypair(rng);
    let (sk2, pk2) = generate_keypair(rng);
    
    // Mesure temps pour différentes clés privées
    let iterations = 1000;
    let mut times1 = Vec::with_capacity(iterations);
    let mut times2 = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        black_box(sign(&sk1, b"test message"));
        times1.push(start.elapsed());
        
        let start = Instant::now();
        black_box(sign(&sk2, b"test message"));
        times2.push(start.elapsed());
    }
    
    // Calcule écarts types
    let avg1: f64 = times1.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / iterations as f64;
    let avg2: f64 = times