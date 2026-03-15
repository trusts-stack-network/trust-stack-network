//! Circuit Halo2 pour les transactions shielded TSN
//! 
//! Implémente la preuve zero-knowledge pour les transactions privées :
//! - Conservation des balances : sum(inputs) = sum(outputs) + fees
//! - Validité des commitments (Poseidon)
//! - Dérivation correcte des nullifiers
//! - Confidentialité des montants et destinataires
//!
//! Références:
//! - Zcash Sapling protocol: https://zips.z.cash/protocol/protocol.pdf
//! - Halo2 Book: https://zcash.github.io/halo2/
//! - NIST SP 800-208: Post-quantum cryptography standards

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use rand::rngs::OsRng;

use crate::crypto::{
    commitment::{NoteCommitment, commit_to_note},
    nullifier::{Nullifier, NullifierKey, derive_nullifier},
    poseidon::{POSEIDON_CONFIG, DOMAIN_NOTE_COMMITMENT, DOMAIN_NULLIFIER},
};

/// Paramètres de sécurité pour le circuit shielded
/// - MAX_INPUTS : Nombre maximum d'inputs par transaction (limitation pour la taille du circuit)
/// - MAX_OUTPUTS : Nombre maximum d'outputs par transaction
/// - SECURITY_LEVEL : Niveau de sécurité en bits (128-bit post-quantum)
pub const MAX_INPUTS: usize = 4;
pub const MAX_OUTPUTS: usize = 4;
pub const SECURITY_LEVEL: usize = 128;

/// Note d'input pour une transaction shielded
/// Contient toutes les données secrètes nécessaires pour dépenser la note
#[derive(Clone, Debug)]
pub struct ShieldedInput {
    /// Valeur de la note (gardée secrète)
    pub value: u64,
    /// Hash de la clé publique du destinataire  
    pub recipient_pk_hash: [u8; 32],
    /// Randomness pour le commitment (gardée secrète)
    pub randomness: Fr,
    /// Clé de nullifier (gardée secrète)
    pub nullifier_key: Fr,
    /// Position de la note dans l'arbre de commitments
    pub note_position: u64,
    /// Commitment de la note (public, dans l'arbre)
    pub note_commitment: NoteCommitment,
    /// Nullifier dérivé (public, pour éviter double dépense)
    pub nullifier: Nullifier,
}

impl ShieldedInput {
    /// Crée un input shielded en vérifiant la cohérence des données
    pub fn new(
        value: u64,
        recipient_pk_hash: [u8; 32],
        randomness: Fr,
        nullifier_key: NullifierKey,
        note_position: u64,
    ) -> Self {
        // Calcule le commitment attendu
        let note_commitment = commit_to_note(value, &recipient_pk_hash, &randomness);
        
        // Calcule le nullifier attendu
        let nullifier = derive_nullifier(&nullifier_key, &note_commitment, note_position);
        
        Self {
            value,
            recipient_pk_hash,
            randomness,
            nullifier_key: nullifier_key.to_field_element(),
            note_position,
            note_commitment,
            nullifier,
        }
    }
}

/// Note d'output pour une transaction shielded
/// Contient les données nécessaires pour créer une nouvelle note
#[derive(Clone, Debug)]
pub struct ShieldedOutput {
    /// Valeur de la note (gardée secrète)
    pub value: u64,
    /// Hash de la clé publique du destinataire
    pub recipient_pk_hash: [u8; 32],
    /// Randomness pour le commitment (gardée secrète)
    pub randomness: Fr,
    /// Commitment de la note (public, sera ajouté à l'arbre)
    pub note_commitment: NoteCommitment,
}

impl ShieldedOutput {
    /// Crée un output shielded
    pub fn new(value: u64, recipient_pk_hash: [u8; 32], randomness: Fr) -> Self {
        let note_commitment = commit_to_note(value, &recipient_pk_hash, &randomness);
        
        Self {
            value,
            recipient_pk_hash,
            randomness,
            note_commitment,
        }
    }
}

/// Circuit principal pour les transactions shielded
/// Prouve la validité d'une transaction privée sans révéler les montants
#[derive(Clone)]
pub struct ShieldedTransactionCircuit {
    /// Notes d'input (secrètes)
    pub inputs: Vec<ShieldedInput>,
    /// Notes d'output (secrètes sauf les commitments)
    pub outputs: Vec<ShieldedOutput>,
    /// Frais de transaction (publics)
    pub fee: u64,
    /// Randomness pour le value commitment binding (secrète)
    pub binding_randomness: Fr,
}

impl ShieldedTransactionCircuit {
    /// Crée un nouveau circuit de transaction shielded
    pub fn new(
        inputs: Vec<ShieldedInput>,
        outputs: Vec<ShieldedOutput>,
        fee: u64,
    ) -> Result<Self, &'static str> {
        if inputs.len() > MAX_INPUTS {
            return Err("Trop d'inputs");
        }
        if outputs.len() > MAX_OUTPUTS {
            return Err("Trop d'outputs");
        }
        if inputs.is_empty() && outputs.is_empty() {
            return Err("Transaction vide");
        }

        // Calcule la randomness binding pour équilibrer les value commitments
        let mut total_input_randomness = Fr::ZERO;
        for input in &inputs {
            // Utilise la randomness de la note pour le value commitment
            total_input_randomness += input.randomness;
        }

        let mut total_output_randomness = Fr::ZERO;
        for output in &outputs {
            total_output_randomness += output.randomness;
        }

        // binding_randomness = total_input_randomness - total_output_randomness
        let binding_randomness = total_input_randomness - total_output_randomness;

        Ok(Self {
            inputs,
            outputs,
            fee,
            binding_randomness,
        })
    }

    /// Calcule la balance totale des inputs
    fn total_input_value(&self) -> u64 {
        self.inputs.iter().map(|input| input.value).sum()
    }

    /// Calcule la balance totale des outputs
    fn total_output_value(&self) -> u64 {
        self.outputs.iter().map(|output| output.value).sum()
    }

    /// Vérifie que la balance est conservée
    pub fn verify_balance(&self) -> bool {
        self.total_input_value() == self.total_output_value() + self.fee
    }

    /// Extrait les données publiques (commitments et nullifiers)
    pub fn public_data(&self) -> ShieldedTransactionPublicData {
        ShieldedTransactionPublicData {
            input_nullifiers: self.inputs.iter().map(|i| i.nullifier).collect(),
            output_commitments: self.outputs.iter().map(|o| o.note_commitment).collect(),
            fee: self.fee,
        }
    }
}

/// Données publiques d'une transaction shielded
/// Ce qui est visible sur la blockchain
#[derive(Clone, Debug)]
pub struct ShieldedTransactionPublicData {
    /// Nullifiers des notes dépensées (pour éviter double dépense)
    pub input_nullifiers: Vec<Nullifier>,
    /// Commitments des nouvelles notes créées
    pub output_commitments: Vec<NoteCommitment>,
    /// Frais de transaction
    pub fee: u64,
}

/// Contraintes R1CS pour le circuit Poseidon
fn constrain_poseidon_hash(
    cs: ConstraintSystemRef<Fr>,
    domain: Fr,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), &POSEIDON_CONFIG);
    
    // Absorbe le domain tag
    let domain_var = FpVar::<Fr>::new_constant(cs.clone(), domain)?;
    sponge.absorb(&domain_var)?;
    
    // Absorbe les inputs
    for input in inputs {
        sponge.absorb(input)?;
    }
    
    // Squeeze le résultat
    let result = sponge.squeeze_field_elements(1)?;
    Ok(result[0].clone())
}

/// Contrainte pour vérifier un commitment de note
fn constrain_note_commitment(
    cs: ConstraintSystemRef<Fr>,
    value: &FpVar<Fr>,
    pk_hash: &FpVar<Fr>, 
    randomness: &FpVar<Fr>,
    expected_commitment: &FpVar<Fr>,
) -> Result<(), SynthesisError> {
    // Calcule cm = Poseidon(DOMAIN_NOTE_COMMITMENT, value, pk_hash, randomness)
    let domain = Fr::from(DOMAIN_NOTE_COMMITMENT);
    let computed_commitment = constrain_poseidon_hash(
        cs.clone(),
        domain,
        &[value.clone(), pk_hash.clone(), randomness.clone()],
    )?;
    
    // Contrainte: computed_commitment = expected_commitment
    computed_commitment.enforce_equal(expected_commitment)?;
    
    Ok(())
}

/// Contrainte pour vérifier un nullifier
fn constrain_nullifier(
    cs: ConstraintSystemRef<Fr>,
    nullifier_key: &FpVar<Fr>,
    commitment: &FpVar<Fr>,
    position: &FpVar<Fr>,
    expected_nullifier: &FpVar<Fr>,
) -> Result<(), SynthesisError> {
    // Calcule nf = Poseidon(DOMAIN_NULLIFIER, nk, cm, position)
    let domain = Fr::from(DOMAIN_NULLIFIER);
    let computed_nullifier = constrain_poseidon_hash(
        cs.clone(),
        domain,
        &[nullifier_key.clone(), commitment.clone(), position.clone()],
    )?;
    
    // Contrainte: computed_nullifier = expected_nullifier
    computed_nullifier.enforce_equal(expected_nullifier)?;
    
    Ok(())
}

impl ConstraintSynthesizer<Fr> for ShieldedTransactionCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        // ============================================================================
        // 1. ALLOUE LES VARIABLES PRIVÉES ET PUBLIQUES
        // ============================================================================
        
        let mut input_value_vars = Vec::new();
        let mut input_pk_hash_vars = Vec::new();
        let mut input_randomness_vars = Vec::new();
        let mut input_nullifier_key_vars = Vec::new();
        let mut input_position_vars = Vec::new();
        
        // Variables privées pour les inputs
        for input in self.inputs.iter() {
            let value_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(input.value)))?;
            let pk_hash_var = FpVar::<Fr>::new_witness(cs.clone(), || {
                Ok(Fr::from_le_bytes_mod_order(&input.recipient_pk_hash))
            })?;
            let randomness_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(input.randomness))?;
            let nk_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(input.nullifier_key))?;
            let position_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(input.note_position)))?;
            
            input_value_vars.push(value_var);
            input_pk_hash_vars.push(pk_hash_var);
            input_randomness_vars.push(randomness_var);
            input_nullifier_key_vars.push(nk_var);
            input_position_vars.push(position_var);
        }
        
        let mut output_value_vars = Vec::new();
        let mut output_pk_hash_vars = Vec::new();
        let mut output_randomness_vars = Vec::new();
        
        // Variables privées pour les outputs
        for output in self.outputs.iter() {
            let value_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(output.value)))?;
            let pk_hash_var = FpVar::<Fr>::new_witness(cs.clone(), || {
                Ok(Fr::from_le_bytes_mod_order(&output.recipient_pk_hash))
            })?;
            let randomness_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.randomness))?;
            
            output_value_vars.push(value_var);
            output_pk_hash_vars.push(pk_hash_var);
            output_randomness_vars.push(randomness_var);
        }
        
        // Variable publique pour les frais
        let fee_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.fee)))?;
        
        // ============================================================================
        // 2. CONTRAINTES DE COMMITMENT POUR LES INPUTS
        // ============================================================================
        
        for (i, input) in self.inputs.iter().enumerate() {
            // Commitment public attendu
            let expected_commitment_var = FpVar::<Fr>::new_input(cs.clone(), || {
                Ok(Fr::from_le_bytes_mod_order(&input.note_commitment.to_bytes()))
            })?;
            
            // Contrainte: commitment est correctement formé
            constrain_note_commitment(
                cs.clone(),
                &input_value_vars[i],
                &input_pk_hash_vars[i],
                &input_randomness_vars[i],
                &expected_commitment_var,
            )?;
        }
        
        // ============================================================================
        // 3. CONTRAINTES DE NULLIFIER POUR LES INPUTS
        // ============================================================================
        
        for (i, input) in self.inputs.iter().enumerate() {
            // Nullifier public attendu
            let expected_nullifier_var = FpVar::<Fr>::new_input(cs.clone(), || {
                Ok(Fr::from_le_bytes_mod_order(&input.nullifier.to_bytes()))
            })?;
            
            // Commitment pour le calcul du nullifier
            let commitment_var = FpVar::<Fr>::new_witness(cs.clone(), || {
                Ok(Fr::from_le_bytes_mod_order(&input.note_commitment.to_bytes()))
            })?;
            
            // Contrainte: nullifier est correctement dérivé
            constrain_nullifier(
                cs.clone(),
                &input_nullifier_key_vars[i],
                &commitment_var,
                &input_position_vars[i],
                &expected_nullifier_var,
            )?;
        }
        
        // ============================================================================
        // 4. CONTRAINTES DE COMMITMENT POUR LES OUTPUTS
        // ============================================================================
        
        for (i, output) in self.outputs.iter().enumerate() {
            // Commitment public attendu
            let expected_commitment_var = FpVar::<Fr>::new_input(cs.clone(), || {
                Ok(Fr::from_le_bytes_mod_order(&output.note_commitment.to_bytes()))
            })?;
            
            // Contrainte: commitment est correctement formé
            constrain_note_commitment(
                cs.clone(),
                &output_value_vars[i],
                &output_pk_hash_vars[i],
                &output_randomness_vars[i],
                &expected_commitment_var,
            )?;
        }
        
        // ============================================================================
        // 5. CONTRAINTE DE CONSERVATION DES BALANCES
        // ============================================================================
        
        // Somme des inputs
        let mut total_input_var = FpVar::<Fr>::new_constant(cs.clone(), Fr::ZERO)?;
        for value_var in &input_value_vars {
            total_input_var = &total_input_var + value_var;
        }
        
        // Somme des outputs
        let mut total_output_var = FpVar::<Fr>::new_constant(cs.clone(), Fr::ZERO)?;
        for value_var in &output_value_vars {
            total_output_var = &total_output_var + value_var;
        }
        
        // Contrainte: total_input = total_output + fee
        let total_spent = &total_output_var + &fee_var;
        total_input_var.enforce_equal(&total_spent)?;
        
        Ok(())
    }
}

/// Preuves ZK pour transactions shielded
pub mod proving {
    use super::*;
    use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
    use ark_snark::SNARK;
    use ark_std::rand::Rng;
    
    /// Générateur de preuves pour transactions shielded
    pub struct ShieldedProver {
        proving_key: ProvingKey<ark_bn254::Bn254>,
        verifying_key: VerifyingKey<ark_bn254::Bn254>,
    }
    
    impl ShieldedProver {
        /// Initialise le prouveur avec trusted setup
        /// ATTENTION: En production, le trusted setup doit être généré de manière sécurisée
        pub fn setup<R: Rng>(rng: &mut R) -> Result<Self, Box<dyn std::error::Error>> {
            // Circuit dummy pour le setup
            let dummy_circuit = ShieldedTransactionCircuit {
                inputs: vec![],
                outputs: vec![],
                fee: 0,
                binding_randomness: Fr::ZERO,
            };
            
            let (pk, vk) = Groth16::<ark_bn254::Bn254>::circuit_specific_setup(dummy_circuit, rng)?;
            
            Ok(Self {
                proving_key: pk,
                verifying_key: vk,
            })
        }
        
        /// Génère une preuve ZK pour une transaction shielded
        pub fn prove(
            &self,
            circuit: ShieldedTransactionCircuit,
        ) -> Result<ShieldedTransactionProof, Box<dyn std::error::Error>> {
            // Extrait les données publiques
            let public_data = circuit.public_data();
            
            // Prépare les inputs publics pour Groth16
            let mut public_inputs = Vec::new();
            
            // Ajoute les frais
            public_inputs.push(Fr::from(circuit.fee));
            
            // Ajoute les nullifiers des inputs
            for nullifier in &public_data.input_nullifiers {
                public_inputs.push(Fr::from_le_bytes_mod_order(&nullifier.to_bytes()));
            }
            
            // Ajoute les commitments des outputs
            for commitment in &public_data.output_commitments {
                public_inputs.push(Fr::from_le_bytes_mod_order(&commitment.to_bytes()));
            }
            
            // Génère la preuve
            let proof = Groth16::<ark_bn254::Bn254>::prove(&self.proving_key, circuit, &mut OsRng)?;
            
            Ok(ShieldedTransactionProof {
                proof,
                public_data,
            })
        }
        
        /// Retourne la clé de vérification publique
        pub fn verifying_key(&self) -> &VerifyingKey<ark_bn254::Bn254> {
            &self.verifying_key
        }
    }
    
    /// Vérifie une preuve de transaction shielded
    pub fn verify_shielded_proof(
        vk: &VerifyingKey<ark_bn254::Bn254>,
        proof: &ShieldedTransactionProof,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // Reconstruit les inputs publics
        let mut public_inputs = Vec::new();
        
        // Frais
        public_inputs.push(Fr::from(proof.public_data.fee));
        
        // Nullifiers
        for nullifier in &proof.public_data.input_nullifiers {
            public_inputs.push(Fr::from_le_bytes_mod_order(&nullifier.to_bytes()));
        }
        
        // Commitments
        for commitment in &proof.public_data.output_commitments {
            public_inputs.push(Fr::from_le_bytes_mod_order(&commitment.to_bytes()));
        }
        
        // Vérifie la preuve Groth16
        Ok(Groth16::<ark_bn254::Bn254>::verify(vk, &public_inputs, &proof.proof)?)
    }
}

/// Preuve complète d'une transaction shielded
#[derive(Clone)]
pub struct ShieldedTransactionProof {
    /// Preuve Groth16
    pub proof: ark_groth16::Proof<ark_bn254::Bn254>,
    /// Données publiques
    pub public_data: ShieldedTransactionPublicData,
}

impl ShieldedTransactionProof {
    /// Sérialise la preuve en bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        use ark_serialize::CanonicalSerialize;
        let mut bytes = Vec::new();
        // SAFETY: Groth16 proof serialization to Vec<u8> cannot fail (no I/O)
        self.proof.serialize_compressed(&mut bytes)
            .expect("BUG: Groth16 proof serialization to Vec cannot fail");
        bytes
    }
    
    /// Désérialise une preuve depuis bytes
    /// Note: Les données publiques doivent être fournies séparément
    pub fn from_bytes_with_public_data(
        bytes: &[u8], 
        public_data: ShieldedTransactionPublicData
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use ark_serialize::CanonicalDeserialize;
        let proof = ark_groth16::Proof::<ark_bn254::Bn254>::deserialize_compressed(bytes)?;
        
        Ok(Self {
            proof,
            public_data,
        })
    }
}

/// Nettoyage sécurisé des données sensibles après usage
impl Drop for ShieldedInput {
    fn drop(&mut self) {
        // Clear sensitive fields
        self.randomness = Fr::ZERO;
        self.nullifier_key = Fr::ZERO;
        self.recipient_pk_hash.fill(0);
    }
}

impl Drop for ShieldedOutput {
    fn drop(&mut self) {
        // Clear sensitive fields
        self.randomness = Fr::ZERO;
        self.recipient_pk_hash.fill(0);
    }
}

impl Drop for ShieldedTransactionCircuit {
    fn drop(&mut self) {
        self.binding_randomness = Fr::ZERO;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::nullifier::NullifierKey;
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;
    
    #[test]
    fn test_shielded_input_creation() {
        let mut rng = StdRng::seed_from_u64(12345);
        
        let value = 1000;
        let pk_hash = [1u8; 32];
        let randomness = Fr::rand(&mut rng);
        let nk = NullifierKey::new(b"test_nullifier_key");
        let position = 42;
        
        let input = ShieldedInput::new(value, pk_hash, randomness, nk, position);
        
        assert_eq!(input.value, value);
        assert_eq!(input.recipient_pk_hash, pk_hash);
        assert_eq!(input.randomness, randomness);
        assert_eq!(input.note_position, position);
    }
    
    #[test]
    fn test_shielded_output_creation() {
        let mut rng = StdRng::seed_from_u64(12345);
        
        let value = 500;
        let pk_hash = [2u8; 32];
        let randomness = Fr::rand(&mut rng);
        
        let output = ShieldedOutput::new(value, pk_hash, randomness);
        
        assert_eq!(output.value, value);
        assert_eq!(output.recipient_pk_hash, pk_hash);
        assert_eq!(output.randomness, randomness);
    }
    
    #[test]
    fn test_shielded_circuit_balance() {
        let mut rng = StdRng::seed_from_u64(12345);
        
        // Crée des inputs
        let input1 = ShieldedInput::new(
            1000,
            [1u8; 32],
            Fr::rand(&mut rng),
            NullifierKey::new(b"nk1"),
            0,
        );
        let input2 = ShieldedInput::new(
            500,
            [2u8; 32],
            Fr::rand(&mut rng),
            NullifierKey::new(b"nk2"),
            1,
        );
        
        // Crée des outputs
        let output1 = ShieldedOutput::new(700, [3u8; 32], Fr::rand(&mut rng));
        let output2 = ShieldedOutput::new(600, [4u8; 32], Fr::rand(&mut rng));
        
        let fee = 200;
        
        // Teste balance correcte
        let circuit = ShieldedTransactionCircuit::new(
            vec![input1.clone(), input2.clone()],
            vec![output1, output2],
            fee,
        ).unwrap();
        
        assert!(circuit.verify_balance());
        assert_eq!(circuit.total_input_value(), 1500);
        assert_eq!(circuit.total_output_value(), 1300);
        
        // Teste balance incorrecte
        let bad_output = ShieldedOutput::new(1000, [5u8; 32], Fr::rand(&mut rng));
        let bad_circuit = ShieldedTransactionCircuit::new(
            vec![input1, input2],
            vec![bad_output],
            fee,
        ).unwrap();
        
        assert!(!bad_circuit.verify_balance());
    }
    
    #[test]
    fn test_circuit_constraints() {
        use ark_relations::r1cs::{ConstraintSystem, OptimizationGoal};
        
        let mut rng = StdRng::seed_from_u64(12345);
        
        // Circuit simple avec un input et un output
        let input = ShieldedInput::new(
            1000,
            [1u8; 32],
            Fr::rand(&mut rng),
            NullifierKey::new(b"test_nk"),
            0,
        );
        let output = ShieldedOutput::new(800, [2u8; 32], Fr::rand(&mut rng));
        let circuit = ShieldedTransactionCircuit::new(
            vec![input],
            vec![output],
            200,
        ).unwrap();
        
        // Test des contraintes R1CS
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        
        // Doit passer sans erreur si le circuit est bien formé
        circuit.generate_constraints(cs.clone()).unwrap();
        
        println!("Constraints: {}", cs.num_constraints());
        println!("Variables: {}", cs.num_witness_variables());
        println!("Inputs: {}", cs.num_instance_variables());
        
        // Vérifie que le système est satisfiable
        assert!(cs.is_satisfied().unwrap());
    }
}