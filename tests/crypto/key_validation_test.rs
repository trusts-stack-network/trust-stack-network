use tsn_crypto::keys::{PublicKey, SecretKey};
use tsn_crypto::pq::dilithium::DilithiumKeypair;
use rand::rngs::OsRng;

/// Test la validation des clés post-quantiques
#[test]
fn test_pq_key_validation() {
    let mut rng = OsRng;
    
    // Génère une clé valide
    let (pk, sk) = DilithiumKeypair::generate(&mut rng).into_keys();
    
    // Doit passer la validation
    assert!(pk.validate().is_ok());
    
    // Test avec une clé sur la courbe incorrecte
    let mut invalid_pk_bytes = pk.to_bytes();
    invalid_pk_bytes[0] ^= 0xff; // Modifie le premier byte
    
    let invalid_pk = match PublicKey::from_bytes(&invalid_pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return, // Si la parsing échoue, c'est acceptable
    };
    
    // Doit échouer la validation
    assert!(invalid_pk.validate().is_err(), 
        "Clé publique invalide non détectée");
}

/// Test que les clés faibles sont rejetées
#[test]
fn test_weak_key_rejection() {
    let weak_keys = vec![
        [0u8; 32],  // Clé nulle
        [1u8; 32],  // Clé répétitive
    ];
    
    for weak_key in weak_keys {
        let result = PublicKey::from_bytes(&weak_key);
        assert!(result.is_err() || result.unwrap().validate().is_err(),
            "Clé faible acceptée: {:?}", weak_key);
    }
}