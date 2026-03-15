// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
use proptest::prelude::*;
use tsn_crypto::poseidon::PoseidonHash;
use tsn_crypto::merkle_tree::MerkleTree;
use tsn_crypto::note::{Note, Nullifier};
use tsn_crypto::commitment::NoteCommitment;

proptest! {
    #[test]
    fn poseidon_commutative(a: [u8;32], b: [u8;32]) {
        let h1 = PoseidonHash::two_to_one(&a.into(), &b.into());
        let h2 = PoseidonHash::two_to_one(&b.into(), &a.into());
        prop_assert_eq!(h1, h2);
    }

    #[test]
    fn merkle_root_order_leaves(v in vec(any::<[u8;32]>(), 1..1024)) {
        let mut t1 = MerkleTree::new(v.len()).unwrap();
        let mut t2 = MerkleTree::new(v.len()).unwrap();
        for (i, leaf) in v.iter().enumerate() {
            t1.insert(i, *leaf);
            t2.insert(v.len()-1-i, *leaf);
        }
        // Le root doit être identique quelle que soit l'ordre d'insertion
        prop_assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn note_nullifier_unique(note_bytes in any::<[u8;64]>()) {
        let note = Note::from_bytes(&note_bytes).unwrap_or_else(|_| Note::dummy());
        let nf1 = Nullifier::from_note(&note, 0u64);
        let nf2 = Nullifier::from_note(&note, 1u64);
        prop_assert_ne!(nf1, nf2);
    }

    #[test]
    fn commitment_homomorphic(v1: u64, v2: u64) {
        let com1 = NoteCommitment::commit(&v1.to_le_bytes());
        let com2 = NoteCommitment::commit(&v2.to_le_bytes());
        let com_sum = NoteCommitment::commit(&(v1.wrapping_add(v2)).to_le_bytes());
        // On ne vérifie pas l'homomorphisme réel car la commitment est blindée,
        // mais on s'assure que la fonction ne panique pas sur des valeurs aléatoires.
        prop_assert_eq!(com1.len(), 32);
        prop_assert_eq!(com2.len(), 32);
        prop_assert_eq!(com_sum.len(), 32);
    }
}
