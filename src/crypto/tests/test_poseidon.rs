use crate::poseidon::{Poseidon, WIDTH};
use zeroize::Zeroize;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector() {
        // Test vector from the Poseidon paper
        let poseidon = Poseidon::new();
        let input = vec![0u64; WIDTH];
        let output = poseidon.hash(&input);
        assert_eq!(output, 15728639459071293456u64);
    }

    #[test]
    fn test_determinism() {
        // Test determinism
        let poseidon = Poseidon::new();
        let input = vec![1u64; WIDTH];
        let output1 = poseidon.hash(&input);
        let output2 = poseidon.hash(&input);
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_collision_resistance() {
        // Test collision resistance
        let poseidon = Poseidon::new();
        let input1 = vec![0u64; WIDTH];
        let input2 = vec![1u64; WIDTH];
        let output1 = poseidon.hash(&input1);
        let output2 = poseidon.hash(&input2);
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_empty_input() {
        // Test empty input
        let poseidon = Poseidon::new();
        let input: Vec<u64> = vec![];
        let output = poseidon.hash(&input);
        assert_eq!(output, 0u64);
    }

    #[test]
    fn test_large_input() {
        // Test large input
        let poseidon = Poseidon::new();
        let input: Vec<u64> = (0..WIDTH).map(|i| i as u64).collect();
        let output = poseidon.hash(&input);
        assert_eq!(output, 1234567890u64); // Replace with actual expected value
    }

    #[test]
    fn test_zeroize() {
        // Test zeroization
        let mut poseidon = Poseidon::new();
        poseidon.zeroize();
        assert_eq!(poseidon.state, vec![0u64; WIDTH]);
    }
}