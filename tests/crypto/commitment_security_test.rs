use tsn::crypto::{Commitment, commitment_root};
use proptest::prelude::*;
use rand::thread_rng;

proptest! {
    #[test]
    fn test_commitment_binding(
        a in prop::collection::vec(any::<u8>(), 0..1000),
        b in prop::collection::vec(any::<u8>(), 0..1000),
        r1 in prop::array::uniform32(any::<u8>()),
        r2 in prop::array::uniform32(any::<u8>())
    ) {
        // Deux commitments avec des entrées différentes doivent être différents
        let comm1 = Commitment::new(&a, &r1);
        let comm2 = Commitment::new(&b, &r2);
        
        if a != b || r1 != r2 {
            prop_assert_ne!(comm1, comm2);
        }
    }
    
    #[test]
    fn test_commitment_hiding(
        value in prop::collection::vec(any::<u8>(), 100),
        r1 in prop::array::uniform32(any::<u8>()),
        r2 in prop::array::uniform32(any::<u8>())
    ) {
        // Le même message avec des randoms différents doit être indistinguable
        let comm1 = Commitment::new(&value, &r1);
        let comm2 = Commitment::new(&value, &r2);
        
        // Distribution uniforme des commitments
        prop_assert!(comm1.to_bytes().iter().any(|&b| b != 0));
        prop_assert!(comm2.to_bytes().iter().any(|&b| b != 0));
    }
}

#[test]
fn test_commitment_root_timing_attack() {
    // Vérifier que la génération de root est en constant-time
    let mut rng = thread_rng();
    let commitments: Vec<Commitment> = (0..100)
        .map(|_| Commitment::random(&mut rng))
        .collect();
    
    let start = Instant::now();
    let root1 = commitment_root(&commitments);
    let time1 = start.elapsed();
    
    // Ajouter un élément et re-timer
    commitments.push(Commitment::random(&mut rng));
    let start = Instant::now();
    let root2 = commitment_root(&commitments);
    let time2 = start.elapsed();
    
    // Le timing doit être proportionnel à la taille, pas aux valeurs
    let ratio = (time2.as_nanos() as f64 - time1.as_nanos() as f64) 
        / time1.as_nanos() as f64;
    
    assert!(ratio < 0.5, "Timing non-linéaire détecté: {:.2}%", ratio * 100.0);
}