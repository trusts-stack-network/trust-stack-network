use tsn_crypto::nullifier::{Nullifier, NullifierSet};
use tsn_crypto::note::Note;
use tsn_crypto::commitment::Commitment;
use proptest::prelude::*;
use std::collections::HashSet;

#[test]
fn test_nullifier_double_spend_prevention() {
    /// Test critique: un nullifier ne peut être utilisé qu'une seule fois
    /// Fail ici = fail économique total (double spend possible)
    
    let mut nullifier_set = NullifierSet::new();
    let note = Note::new(100u64.into(), [1u8; 32]);
    let nullifier = Nullifier::from_note(&note, 0u32);
    
    // Premier usage doit marcher
    assert!(nullifier_set.insert(nullifier).is_ok());
    assert!(nullifier_set.contains(&nullifier));
    
    // Deuxième usage doit échouer
    assert!(nullifier_set.insert(nullifier).is_err());
}

proptest! {
    #[test]
    fn prop_nullifier_uniqueness(
        notes in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 32..64),
            1..100
        )
    ) {
        let mut nullifier_set = NullifierSet::new();
        let mut seen_nullifiers = HashSet::new();
        
        for (i, note_data) in notes.iter().enumerate() {
            let note = Note::new(
                (i as u64).into(),
                note_data[..32].try_into().unwrap()
            );
            let nullifier = Nullifier::from_note(&note, i as u32);
            
            // Chaque nullifier doit être unique
            prop_assert!(!seen_nullifiers.contains(&nullifier));
            prop_assert!(!nullifier_set.contains(&nullifier));
            
            seen_nullifiers.insert(nullifier);
            prop_assert!(nullifier_set.insert(nullifier).is_ok());
        }
        
        // Vérifie qu'on ne peut pas réinsérer
        for nullifier in &seen_nullifiers {
            prop_assert!(nullifier_set.insert(*nullifier).is_err());
        }
    }
}