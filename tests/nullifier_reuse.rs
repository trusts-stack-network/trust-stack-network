// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
use rand::rngs::StdRng;
use rand::SeedableRng;
use tsn_crypto::note::Note;
use tsn_crypto::nullifier::NullifierSet;
use tsn_crypto::state::InMemoryState;

#[tokio::test]
async fn prevent_nullifier_reuse_on_reorg() {
    let mut rng = StdRng::from_seed([0x13; 32]);
    let note = Note::rand(&mut rng);
    let nf = note.nullifier();

    let mut set = NullifierSet::new(InMemoryState::new());

    // Dépense initiale
    assert!(set.insert(nf).await.is_ok());

    // Tente un re-insert (double-spend simulé)
    assert!(set.insert(nf).await.is_err());
}
