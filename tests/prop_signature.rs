// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
//! Property-based tests pour signatures post-quantique
use proptest::prelude::*;
use tsn_crypto::keys::{MlDsaSecretKey, MlDsaPublicKey};
use tsn_crypto::signature::sign;
use rand::rngs::StdRng;
use rand::SeedableRng;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_024))]

    #[test]
    fn sign_verify_deterministic(msg in any::<Vec<u8>>()) {
        let mut rng = StdRng::seed_from_u64(42);
        let (sk, pk) = MlDsaSecretKey::generate(&mut rng);
        let sig = sign(&sk, &msg, &mut rng);
        prop_assert!(sig.verify(&pk, &msg).is_ok());
    }

    #[test]
    fn signature_malleability_fails(
        msg in any::<Vec<u8>>(),
        flip in prop::sample::select(0..32_usize)
    ) {
        let mut rng = StdRng::seed_from_u64(123);
        let (sk, pk) = MlDsaSecretKey::generate(&mut rng);
        let mut sig = sign(&sk, &msg, &mut rng);
        // On flip un byte aléatoire de la signature
        let idx = flip % sig.as_ref().len();
        sig.as_mut()[idx] = sig.as_mut()[idx].wrapping_add(1);
        prop_assert!(sig.verify(&pk, &msg).is_err());
    }
}
