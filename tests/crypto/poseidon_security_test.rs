use tsn::crypto::poseidon::{Poseidon, PoseidonParams};
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_poseidon_collision_resistance(
        inputs1 in prop::collection::vec(prop::num::u64::ANY, 1..16),
        inputs2 in prop::collection::vec(prop::num::u64::ANY, 1..16)
    ) {
        let params = PoseidonParams::new();
        let mut poseidon1 = Poseidon::new(&params);
        let mut poseidon2 = Poseidon::new(&params);
        
        for input in &inputs1 {
            poseidon1.update(&input.to_le_bytes());
        }
        for input in &inputs2 {
            poseidon2.update(&input.to_le_bytes());
        }
        
        let hash1 = poseidon1.finalize();
        let hash2 = poseidon2.finalize();
        
        // Collision extrêmement improbable
        if inputs1 != inputs2 {
            prop_assert_ne!(hash1, hash2);
       