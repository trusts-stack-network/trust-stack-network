use tsn_crypto::nullifier::Nullifier;
use tsn_crypto::note::Note;
use tsn_crypto::keys::SecretKey;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Vérification que la dérivation de nullifier ne fuit pas d'information
#[test]
fn test_nullifier_derivation_constant_time() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    
    let secret1 = SecretKey::generate(&mut rng);
    let secret2 = SecretKey::generate(&mut rng);
    
    let note1 = Note::new(&secret1, 1000, &mut rng);
    let note2 = Note::new(&secret2, 1000, &mut rng);
    
    // Temps de dérivation pour note1
    let start = std::time::Instant::now();
