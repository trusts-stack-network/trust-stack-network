use proptest::prelude::*;
use tsn_crypto::commitment::{Commitment, CommitmentScheme};
use tsn_crypto::note::{Note, NoteCommitment};
use tsn_crypto::nullifier::Nullifier;
use tsn_crypto::merkle_tree::MerkleTree;

proptest! {
    /// Test d'inviolabilité des commitments
    #[test]
    fn test_commitment_binding(
        value1 in 0u64..1_000_000_000u64,
        value2 in 0u64..1_000_000_000u64,
        blinding1: [u8; 32],
        blinding2: [u8; 32]
    ) {
        let scheme = CommitmentScheme::new();
        
        let comm1 = scheme.commit(&value1.to_le_bytes(), &blinding1);
        let comm2 = scheme.commit(&value2.to_le_bytes(), &blinding2);
        
        // Deux commitments différents doivent être différents
        if value1 != value2 || blinding1 != blinding2 {
            prop_assert_ne!(comm1, comm2);
        }
    }

    /// Test de masquage des commitments
    #[test]
    fn test_commitment_hiding(
        value in 0u64..1_000_000_000u64,
        blinding1: [u8; 32],
        blinding2: [u8; 32]
    ) {
        let scheme = CommitmentScheme::new();
        
        let comm1 = scheme.commit(&value.to_le_bytes(), &blinding1);
        let comm2 = scheme.commit(&value.to_le_bytes(), &blinding2);
        
        // Même valeur avec blindings différents doit donner des commitments différents
        prop_assert_ne!(comm1, comm2);
    }

    /// Test d'unicité des nullifiers
    #[test]
    fn test_nullifier_uniqueness(
        note_data1: [u8; 64],
        note_data2: [u8; 64],
        pos1 in 0u32..1000u32,
        pos2 in 0u32..1000u32
    ) {
        let nullifier1 = Nullifier::from_note(&note_data1, pos1);
        let nullifier2 = Nullifier::from_note(&note_data2, pos2);
        
        if note_data1 != note_data2 || pos1 != pos2 {
            prop_assert_ne!(nullifier1, nullifier2);
        }
    }
}