//! Property-test : absence de collision Poseidon2
use crypto::poseidon::Poseidon2;
use proptest::prelude::*;

proptest! {
    #[test]
    fn no_collision_2_inputs(
        a1 in prop::collection::vec(0u8.., 32..33),
        b1 in prop::collection::vec(0u8.., 32..33),
        a2 in prop::collection::vec(0u8.., 32..33),
        b2 in prop::collection::vec(0u8.., 32..33),
    ) {
        let h1 = Poseidon2::hash(&[&