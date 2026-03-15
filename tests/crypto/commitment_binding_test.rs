use tsn_crypto::commitment::*;
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_commitment_binding(
        value in 0u64..1_000_000_000u64,
        r1 in any::<[u8; 32]>(),
        r2 in any::<[u8; 32]>()
    ) {
        let note1 = Note { value, r: r1 };
        let note2 = Note { value, r: r2 };
        
        let commit1 = compute_commitment(&note1, b"domain");
        let commit2 = compute_commitment(&note2, b"domain");
        
        if r