// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Teste que la vérification de signature est en temps constant
//! (pas de leakage par timing).
use plonky2_crypto::U512;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::time::{Duration, Instant};
use tsn_crypto::signature::SigPair;

proptest::proptest! {
    #[test]
    fn sig_verify_constant_time(msg in proptest::collection::vec(0u8..255, 100..500)) {
        let mut rng = StdRng::from_seed([0x42; 32]);
        let pair = SigPair::generate(&mut rng);

        let sig = pair.sign(&msg);

        // Mesure 1000 fois sur le même message
        let mut durations = Vec::with_capacity(1000);
        for _ in 0..1000 {
            let start = Instant::now();
            let _ = pair.pk.verify(&sig, &msg);
            durations.push(start.elapsed());
        }

        // Calcul moyenne et écart-type
        let mean = durations.iter().sum::<Duration>() / durations.len() as u32;
        let variance: f64 = durations
            .iter()
            .map(|d| {
                let diff = d.as_nanos() as i128 - mean.as_nanos() as i128;
                (diff * diff) as f64
            })
            .sum::<f64>()
            / durations.len() as f64;
        let stddev = variance.sqrt();

        // On accepte ±5 % de la moyenne
        let tolerance_ns = (mean.as_nanos() as f64 * 0.05) as i128;
        for d in durations {
            let diff = (d.as_nanos() as i128 - mean.as_nanos() as i128).abs();
            prop_assert!(diff <= tolerance_ns, "Timing non constant: stddev={stddev}, diff={diff}");
        }
    }
}
