use tsn_crypto::nullifier::Nullifier;
use tsn_crypto::note::Note;
use rand::rngs::OsRng;

/// Test que les nullifiers ne peuvent pas être réutilisés
#[test]
fn test_nullifier_double_spend() {
    let mut rng = OsRng;
    
    // Crée une note
    let note = Note::new(100, &mut rng);
    let nullifier = note.nullify();
    
    // Premier spend doit réussir
    assert!(nullifier.verify(&note).is_ok());
    
    // Deuxième spend doit échouer
    assert!(nullifier.verify(&note).is_err(),
        "Double dépense non détectée");
}

/// Test la persistance des nullifiers utilisés
#[test]
