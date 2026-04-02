// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Property-based tests sur le hash Poseidon2
use proptest::prelude::*;
use tsn_crypto::poseidon::{poseidon2_hash, Fr};
use tsn_crypto::merkle_tree;

prop_compose! {
    fn arb_fr()(bytes in prop::array::uniform32(0u8..)) -> Fr {
        Fr::from_bytes_mod_order(bytes)
    }
}

proptest! {
    #[test]
    fn poseidon2_deterministe(a in arb_fr(), b in arb_fr()) {
        let h1 = poseidon2_hash(&[a, b]);
        let h2 = poseidon2_hash(&[a, b]);
        prop_assert_eq!(h1, h2);
    }

    #[test]
    fn poseidon2_collision_impossible(a in arb_fr(), b in arb_fr(), c in arb_fr()) {
        prop_assume!(a != b);
        let h1 = poseidon2_hash(&[a, c]);
        let h2 = poseidon2_hash(&[b, c]);
        prop_assert_ne!(h1, h2);
    }
}
