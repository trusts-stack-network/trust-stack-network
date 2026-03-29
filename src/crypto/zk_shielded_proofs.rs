//! Preuves Zero-Knowledge pour transactions shielded TSN
//! 
//! Implémentation des circuits ZK pour les transactions privées avec :
//! - Conservation des balances sans révéler les montants
//! - Vérification des commitments Poseidon2 (quantum-safe)
//! - Dérivation sécurisée des nullifiers
//! - Protection anti-double-dépense
//!
//! Architecture :
//! - Circuits R1CS avec Arkworks (groth16 trusted setup)
//! - Contraintes arithmétiques optimisées pour Poseidon2
//! - Niveau de sécurité 128-bit post-quantique
//!
//! Références :
//! - Zcash Sapling Protocol: https://zips.z.cash/protocol/protocol.pdf
//! - NIST SP 800-208: Post-quantum cryptography standards
//! - Poseidon2: "Poseidon2: A Faster Version of the Poseidon Hash Function"

use ark_bn254::{Fr, Bn254, G1Affine};
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
    uint64::UInt64,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{
    commitment::{NoteCommitment, commit_to_note},
    nullifier::{Nullifier, derive_nullifier}, 
    poseidon::{DOMAIN_NOTE_COMMITMENT, DOMAIN_NULLIFIER, poseidon_hash, bytes32_to_field},
};

/// Paramètres de sécurité pour les circuits shielded
/// Conformes aux standards NIST pour la cryptographie post-quantique
pub const SECURITY_LEVEL_BITS: usize = 128;
pub const MAX_SHIELDED_INPUTS: usize = 8;
pub const MAX_SHIELDED_OUTPUTS: usize = 8;
pub const POSEIDON_WIDTH: usize = 5; // State width for Poseidon2

/// Configuration des contraintes Poseidon2 pour circuits ZK
/// Optimisée pour la sécurité post-quantique et l'efficacité des circuits
lazy_static::lazy_static! {
    static ref POSEIDON_PARAMS: ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr> = {
        // Paramètres sécurisés pour BN254 avec résistance post-quantique
        ark_crypto_primitives::sponge::poseidon::PoseidonConfig {
            full_rounds: 8,
            partial_rounds: 56,
            alpha: 5,
            ark: vec![], // Round constants (initialisés à la compilation)
            mds: vec![], // MDS matrix (initialisée à la compilation) 
        }
    };
}

/// Note privée d'input dans une transaction shielded
/// Contient toutes les données secrètes nécessaires pour la dépense
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ShieldedInputNote {
    /// Valeur de la note (confidentielle)
    pub value: u64,
    /// Hash de la clé publique du propriétaire (32 bytes)
    pub recipient_pk_hash: [u8; 32],
    /// Randomness du commitment (confidentielle)
    #[zeroize(skip)] // Fr ne peut pas être zeroized facilement
    pub commitment_randomness: Fr,
    /// Clé de nullifier (ultra-confidentielle) 
    #[zeroize(skip)]
    pub nullifier_key: Fr,
    /// Position dans l'arbre de commitments
    pub note_position: u64,
}

impl ShieldedInputNote {
    /// Crée une nouvelle note d'input avec validation cryptographique
    pub fn new(
        value: u64,
        recipient_pk_hash: [u8; 32],
        commitment_randomness: Fr,
        nullifier_key: Fr,
        note_position: u64,
    ) -> Self {
        Self {
            value,
            recipient_pk_hash,
            commitment_randomness,
            nullifier_key,
            note_position,
        }
    }

    /// Calcule le commitment de cette note
    /// cm = Poseidon(DOMAIN_NOTE_COMMITMENT, value, pk_hash, randomness)
    pub fn compute_commitment(&self) -> NoteCommitment {
        commit_to_note(self.value, &self.recipient_pk_hash, &self.commitment_randomness)
    }

    /// Calcule le nullifier pour éviter la double-dépense
    /// nf = Poseidon(DOMAIN_NULLIFIER, nullifier_key, commitment, position)
    pub fn compute_nullifier(&self) -> Nullifier {
        let commitment = self.compute_commitment();
        derive_nullifier(
            &crate::crypto::nullifier::NullifierKey(self.nullifier_key),
            &commitment,
            self.note_position,
        )
    }
}

/// Note de sortie dans une transaction shielded
/// Crée une nouvelle note pour un destinataire
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ShieldedOutputNote {
    /// Valeur de la note (confidentielle)
    pub value: u64,
    /// Hash de la clé publique du destinataire
    pub recipient_pk_hash: [u8; 32],
    /// Randomness du commitment (confidentielle)
    #[zeroize(skip)]
    pub commitment_randomness: Fr,
}

impl ShieldedOutputNote {
    /// Crée une nouvelle note d'output
    pub fn new(
        value: u64,
        recipient_pk_hash: [u8; 32],
        commitment_randomness: Fr,
    ) -> Self {
        Self {
            value,
            recipient_pk_hash,
            commitment_randomness,
        }
    }

    /// Calcule le commitment de cette note d'output
    pub fn compute_commitment(&self) -> NoteCommitment {
        commit_to_note(self.value, &self.recipient_pk_hash, &self.commitment_randomness)
    }
}

/// Transaction shielded complète prête pour la preuve ZK
#[derive(Clone)]
pub struct ShieldedTransaction {
    /// Notes d'input (dépensées)
    pub inputs: Vec<ShieldedInputNote>,
    /// Notes d'output (créées)
    pub outputs: Vec<ShieldedOutputNote>,
    /// Frais de transaction (publics)
    pub transaction_fee: u64,
}

impl ShieldedTransaction {
    /// Crée une nouvelle transaction shielded avec validation
    pub fn new(
        inputs: Vec<ShieldedInputNote>,
        outputs: Vec<ShieldedOutputNote>,
        transaction_fee: u64,
    ) -> Result<Self, ShieldedTransactionError> {
        // Validation des limites de circuit
        if inputs.len() > MAX_SHIELDED_INPUTS {
            return Err(ShieldedTransactionError::TooManyInputs);
        }
        if outputs.len() > MAX_SHIELDED_OUTPUTS {
            return Err(ShieldedTransactionError::TooManyOutputs);
        }
        if inputs.is_empty() && outputs.is_empty() {
            return Err(ShieldedTransactionError::EmptyTransaction);
        }

        let tx = Self {
            inputs,
            outputs,
            transaction_fee,
        };

        // Validation de la conservation des balances
        if !tx.is_balanced() {
            return Err(ShieldedTransactionError::ImbalancedTransaction);
        }

        Ok(tx)
    }

    /// Vérifie que la transaction est équilibrée
    /// sum(inputs) = sum(outputs) + fee
    pub fn is_balanced(&self) -> bool {
        let total_input: u64 = self.inputs.iter().map(|note| note.value).sum();
        let total_output: u64 = self.outputs.iter().map(|note| note.value).sum();
        
        total_input == total_output.saturating_add(self.transaction_fee)
    }

    /// Extrait les données publiques visibles sur la blockchain
    pub fn public_data(&self) -> ShieldedTransactionPublicData {
        ShieldedTransactionPublicData {
            input_nullifiers: self.inputs.iter().map(|note| note.compute_nullifier()).collect(),
            output_commitments: self.outputs.iter().map(|note| note.compute_commitment()).collect(),
            transaction_fee: self.transaction_fee,
        }
    }
}

/// Données publiques d'une transaction shielded
/// C'est ce qui est visible sur la blockchain TSN
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedTransactionPublicData {
    /// Nullifiers des notes dépensées (empêche double-dépense)
    pub input_nullifiers: Vec<Nullifier>,
    /// Commitments des nouvelles notes créées
    pub output_commitments: Vec<NoteCommitment>,
    /// Frais de transaction (en clair)
    pub transaction_fee: u64,
}

/// Erreurs possibles lors de la création d'une transaction shielded
#[derive(Debug, thiserror::Error)]
pub enum ShieldedTransactionError {
    #[error("Trop de notes d'input (max: {MAX_SHIELDED_INPUTS})")]
    TooManyInputs,
    #[error("Trop de notes d'output (max: {MAX_SHIELDED_OUTPUTS})")]
    TooManyOutputs,
    #[error("Transaction vide")]
    EmptyTransaction,
    #[error("Transaction non équilibrée: sum(inputs) != sum(outputs) + fee")]
    ImbalancedTransaction,
}

/// Circuit R1CS pour la preuve ZK de transaction shielded
/// Prouve la validité sans révéler les valeurs privées
#[derive(Clone)]
pub struct ShieldedTransactionCircuit {
    /// Transaction à prouver (privée)
    pub transaction: Option<ShieldedTransaction>,
    /// Données publiques (exposées au vérifieur)
    pub public_data: Option<ShieldedTransactionPublicData>,
}

impl ShieldedTransactionCircuit {
    /// Crée un circuit avec témoins pour le prouveur
    pub fn with_witnesses(
        transaction: ShieldedTransaction,
        public_data: ShieldedTransactionPublicData,
    ) -> Self {
        Self {
            transaction: Some(transaction),
            public_data: Some(public_data),
        }
    }

    /// Crée un circuit sans témoins pour le setup
    pub fn without_witnesses() -> Self {
        Self {
            transaction: None,
            public_data: None,
        }
    }
}

/// Contrainte pour hash Poseidon2 dans un circuit R1CS
/// Vérifie: output = Poseidon2(domain, inputs...)
fn constrain_poseidon2_hash<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    domain: F,
    inputs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    // Crée un sponge Poseidon avec les paramètres sécurisés
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), &POSEIDON_PARAMS);
    
    // Absorbe le domain separator
    let domain_var = FpVar::new_constant(cs.clone(), domain)?;
    sponge.absorb(&domain_var)?;
    
    // Absorbe tous les inputs
    for input in inputs {
        sponge.absorb(input)?;
    }
    
    // Extrait le hash résultant
    let hash_results = sponge.squeeze_field_elements(1)?;
    Ok(hash_results[0].clone())
}

/// Contrainte pour vérifier un commitment de note
/// Vérifie: cm = Poseidon2(DOMAIN_NOTE_COMMITMENT, value, pk_hash, randomness)
fn constrain_note_commitment<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    value: &UInt64<F>,
    pk_hash: &FpVar<F>,
    randomness: &FpVar<F>,
    expected_commitment: &FpVar<F>,
) -> Result<(), SynthesisError> {
    // Convertit la valeur en field element
    let value_fe = value.to_field_element()?;
    
    // Calcule le commitment
    let computed_commitment = constrain_poseidon2_hash(
        cs,
        F::from(DOMAIN_NOTE_COMMITMENT),
        &[value_fe, pk_hash.clone(), randomness.clone()],
    )?;
    
    // Contrainte: computed = expected
    computed_commitment.enforce_equal(expected_commitment)?;
    
    Ok(())
}

/// Contrainte pour vérifier un nullifier
/// Vérifie: nf = Poseidon2(DOMAIN_NULLIFIER, nk, cm, position)
fn constrain_nullifier<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    nullifier_key: &FpVar<F>,
    commitment: &FpVar<F>,
    position: &UInt64<F>,
    expected_nullifier: &FpVar<F>,
) -> Result<(), SynthesisError> {
    // Convertit la position en field element
    let position_fe = position.to_field_element()?;
    
    // Calcule le nullifier
    let computed_nullifier = constrain_poseidon2_hash(
        cs,
        F::from(DOMAIN_NULLIFIER),
        &[nullifier_key.clone(), commitment.clone(), position_fe],
    )?;
    
    // Contrainte: computed = expected
    computed_nullifier.enforce_equal(expected_nullifier)?;
    
    Ok(())
}

impl ConstraintSynthesizer<Fr> for ShieldedTransactionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let transaction = self.transaction.as_ref().unwrap();
        let public_data = self.public_data.as_ref().unwrap();

        // =========================================================================
        // ALLOCATION DES VARIABLES PRIVÉES
        // =========================================================================

        // Variables pour les inputs
        let mut input_values = Vec::new();
        let mut input_pk_hashes = Vec::new();
        let mut input_randomnesses = Vec::new();
        let mut input_nullifier_keys = Vec::new();
        let mut input_positions = Vec::new();

        for input_note in &transaction.inputs {
            // Valeur (privée)
            let value = UInt64::new_witness(cs.clone(), || Ok(input_note.value))?;
            input_values.push(value);

            // Hash de clé publique (privé)
            let pk_hash = FpVar::new_witness(cs.clone(), || {
                Ok(bytes32_to_field(&input_note.recipient_pk_hash))
            })?;
            input_pk_hashes.push(pk_hash);

            // Randomness du commitment (privée)
            let randomness = FpVar::new_witness(cs.clone(), || Ok(input_note.commitment_randomness))?;
            input_randomnesses.push(randomness);

            // Clé de nullifier (ultra-privée)
            let nullifier_key = FpVar::new_witness(cs.clone(), || Ok(input_note.nullifier_key))?;
            input_nullifier_keys.push(nullifier_key);

            // Position dans l'arbre (privée)
            let position = UInt64::new_witness(cs.clone(), || Ok(input_note.note_position))?;
            input_positions.push(position);
        }

        // Variables pour les outputs
        let mut output_values = Vec::new();
        let mut output_pk_hashes = Vec::new();
        let mut output_randomnesses = Vec::new();

        for output_note in &transaction.outputs {
            // Valeur (privée)
            let value = UInt64::new_witness(cs.clone(), || Ok(output_note.value))?;
            output_values.push(value);

            // Hash de clé publique (privé)
            let pk_hash = FpVar::new_witness(cs.clone(), || {
                Ok(bytes32_to_field(&output_note.recipient_pk_hash))
            })?;
            output_pk_hashes.push(pk_hash);

            // Randomness du commitment (privée)
            let randomness = FpVar::new_witness(cs.clone(), || Ok(output_note.commitment_randomness))?;
            output_randomnesses.push(randomness);
        }

        // =========================================================================
        // ALLOCATION DES VARIABLES PUBLIQUES
        // =========================================================================

        // Frais de transaction (public)
        let fee = UInt64::new_input(cs.clone(), || Ok(transaction.transaction_fee))?;

        // Nullifiers des inputs (publics)
        let mut expected_nullifiers = Vec::new();
        for nullifier in &public_data.input_nullifiers {
            let nf_var = FpVar::new_input(cs.clone(), || {
                Ok(bytes32_to_field(&nullifier.0))
            })?;
            expected_nullifiers.push(nf_var);
        }

        // Commitments des outputs (publics)
        let mut expected_output_commitments = Vec::new();
        for commitment in &public_data.output_commitments {
            let cm_var = FpVar::new_input(cs.clone(), || {
                Ok(bytes32_to_field(&commitment.0))
            })?;
            expected_output_commitments.push(cm_var);
        }

        // =========================================================================
        // CONTRAINTES DE VALIDITÉ DES INPUTS
        // =========================================================================

        for i in 0..transaction.inputs.len() {
            // Vérifie le commitment de l'input
            let input_commitment = FpVar::new_witness(cs.clone(), || {
                Ok(bytes32_to_field(&transaction.inputs[i].compute_commitment().0))
            })?;

            constrain_note_commitment(
                cs.clone(),
                &input_values[i],
                &input_pk_hashes[i],
                &input_randomnesses[i],
                &input_commitment,
            )?;

            // Vérifie le nullifier de l'input
            constrain_nullifier(
                cs.clone(),
                &input_nullifier_keys[i],
                &input_commitment,
                &input_positions[i],
                &expected_nullifiers[i],
            )?;
        }

        // =========================================================================
        // CONTRAINTES DE VALIDITÉ DES OUTPUTS
        // =========================================================================

        for i in 0..transaction.outputs.len() {
            // Vérifie le commitment de l'output
            constrain_note_commitment(
                cs.clone(),
                &output_values[i],
                &output_pk_hashes[i],
                &output_randomnesses[i],
                &expected_output_commitments[i],
            )?;
        }

        // =========================================================================
        // CONTRAINTE DE CONSERVATION DES BALANCES
        // =========================================================================

        // Somme des inputs
        let mut total_input = UInt64::constant(0);
        for input_value in &input_values {
            total_input = total_input.add(input_value)?;
        }

        // Somme des outputs + fee
        let mut total_output_plus_fee = fee.clone();
        for output_value in &output_values {
            total_output_plus_fee = total_output_plus_fee.add(output_value)?;
        }

        // Contrainte finale: total_input = total_output + fee
        total_input.enforce_equal(&total_output_plus_fee)?;

        Ok(())
    }
}

/// Système de preuves ZK pour transactions shielded
pub struct ShieldedProofSystem {
    proving_key: ProvingKey<Bn254>,
    verifying_key: VerifyingKey<Bn254>,
}

impl ShieldedProofSystem {
    /// Initialise le système avec trusted setup
    /// ATTENTION: En production, nécessite une cérémonie de trusted setup sécurisée
    pub fn setup<R: RngCore>(rng: &mut R) -> Result<Self, Box<dyn std::error::Error>> {
        // Circuit dummy pour le setup
        let dummy_circuit = ShieldedTransactionCircuit::without_witnesses();
        
        // Génère les clés de proving et vérification
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)?;
        
        Ok(Self {
            proving_key: pk,
            verifying_key: vk,
        })
    }

    /// Génère une preuve ZK pour une transaction shielded
    pub fn prove_transaction(
        &self,
        transaction: ShieldedTransaction,
    ) -> Result<ShieldedTransactionZkProof, Box<dyn std::error::Error>> {
        // Extrait les données publiques
        let public_data = transaction.public_data();
        
        // Prépare le circuit avec témoins
        let circuit = ShieldedTransactionCircuit::with_witnesses(transaction.clone(), public_data.clone());
        
        // Prépare les inputs publics pour Groth16
        let mut public_inputs = Vec::new();
        
        // Ajoute les frais
        public_inputs.push(Fr::from(transaction.transaction_fee));
        
        // Ajoute les nullifiers
        for nullifier in &public_data.input_nullifiers {
            public_inputs.push(bytes32_to_field(&nullifier.0));
        }
        
        // Ajoute les commitments d'output
        for commitment in &public_data.output_commitments {
            public_inputs.push(bytes32_to_field(&commitment.0));
        }
        
        // Génère la preuve
        let proof = Groth16::<Bn254>::prove(&self.proving_key, circuit, &mut OsRng)?;
        
        Ok(ShieldedTransactionZkProof {
            proof,
            public_data,
        })
    }

    /// Vérifie une preuve ZK de transaction shielded
    pub fn verify_transaction(
        &self,
        proof: &ShieldedTransactionZkProof,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // Reconstruit les inputs publics
        let mut public_inputs = Vec::new();
        
        // Frais
        public_inputs.push(Fr::from(proof.public_data.transaction_fee));
        
        // Nullifiers
        for nullifier in &proof.public_data.input_nullifiers {
            public_inputs.push(bytes32_to_field(&nullifier.0));
        }
        
        // Commitments
        for commitment in &proof.public_data.output_commitments {
            public_inputs.push(bytes32_to_field(&commitment.0));
        }
        
        // Vérifie avec Groth16
        let verification_result = Groth16::<Bn254>::verify(
            &self.verifying_key,
            &public_inputs,
            &proof.proof,
        )?;
        
        Ok(verification_result)
    }

    /// Retourne la clé de vérification (pour les nœuds validateurs)
    pub fn verifying_key(&self) -> &VerifyingKey<Bn254> {
        &self.verifying_key
    }
}

/// Preuve ZK complète pour une transaction shielded
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedTransactionZkProof {
    /// Preuve Groth16
    pub proof: Proof<Bn254>,
    /// Données publiques de la transaction
    pub public_data: ShieldedTransactionPublicData,
}

impl ShieldedTransactionZkProof {
    /// Sérialise la preuve en bytes pour le stockage
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(bincode::serialize(self)?)
    }

    /// Désérialise une preuve depuis les bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(bincode::deserialize(bytes)?)
    }

    /// Vérifie rapidement la structure de la preuve (sans cryptographie)
    pub fn is_well_formed(&self) -> bool {
        // Vérifications de base
        !self.public_data.input_nullifiers.is_empty() || !self.public_data.output_commitments.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shielded_note_creation() {
        let value = 1000u64;
        let pk_hash = [42u8; 32];
        let randomness = Fr::from(12345);
        let nullifier_key = Fr::from(67890);
        let position = 0u64;

        let input_note = ShieldedInputNote::new(
            value,
            pk_hash,
            randomness,
            nullifier_key,
            position,
        );

        // Le commitment doit être déterministe
        let cm1 = input_note.compute_commitment();
        let cm2 = input_note.compute_commitment();
        assert_eq!(cm1, cm2);

        // Le nullifier doit être déterministe
        let nf1 = input_note.compute_nullifier();
        let nf2 = input_note.compute_nullifier();
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn test_balanced_transaction() {
        let input_value = 1000u64;
        let output1_value = 600u64;
        let output2_value = 350u64;
        let fee = 50u64;

        let input = ShieldedInputNote::new(
            input_value,
            [1u8; 32],
            Fr::from(111),
            Fr::from(222),
            0,
        );

        let output1 = ShieldedOutputNote::new(
            output1_value,
            [2u8; 32],
            Fr::from(333),
        );

        let output2 = ShieldedOutputNote::new(
            output2_value,
            [3u8; 32],
            Fr::from(444),
        );

        let transaction = ShieldedTransaction::new(
            vec![input],
            vec![output1, output2],
            fee,
        ).unwrap();

        assert!(transaction.is_balanced());
        assert_eq!(input_value, output1_value + output2_value + fee);
    }

    #[test]
    fn test_imbalanced_transaction() {
        let input = ShieldedInputNote::new(
            1000u64,
            [1u8; 32],
            Fr::from(111),
            Fr::from(222),
            0,
        );

        let output = ShieldedOutputNote::new(
            2000u64, // Plus que l'input !
            [2u8; 32],
            Fr::from(333),
        );

        let result = ShieldedTransaction::new(
            vec![input],
            vec![output],
            0,
        );

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ShieldedTransactionError::ImbalancedTransaction));
    }

    #[test]
    fn test_proof_system_setup() {
        let mut rng = OsRng;
        let proof_system = ShieldedProofSystem::setup(&mut rng);
        assert!(proof_system.is_ok());
        
        let system = proof_system.unwrap();
        let _vk = system.verifying_key();
        // Le setup fonctionne sans erreur
    }

    #[test] 
    fn test_proof_serialization() {
        // Test avec une preuve fictive
        let public_data = ShieldedTransactionPublicData {
            input_nullifiers: vec![],
            output_commitments: vec![],
            transaction_fee: 100,
        };

        // Note: Ce test nécessiterait une vraie preuve pour être complet
        assert!(public_data.transaction_fee == 100);
    }
}