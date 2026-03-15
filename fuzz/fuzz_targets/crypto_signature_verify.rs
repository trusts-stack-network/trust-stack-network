#![no_main]
use libfuzzer_sys::fuzz_target;

// Taille des clés et signatures ML-DSA-65 (FIPS 204)
const PUBLIC_KEY_SIZE: usize = 1952;
const SIGNATURE_SIZE: usize = 3309;

fuzz_target!(|data: &[u8]| {
    // Besoin d'au moins: clé publique + signature + 1 byte de message
    let min_size = PUBLIC_KEY_SIZE + SIGNATURE_SIZE + 1;
    if data.len() < min_size {
        return;
    }
    
    // Séparation correcte des données:
    // - pk_bytes: les 1952 premiers bytes = clé publique
    // - sig_bytes: les 3309 bytes suivants = signature
    // - msg_bytes: le reste = message à vérifier
    let (pk_bytes, rest) = data.split_at(PUBLIC_KEY_SIZE);
    let (sig_bytes, msg_bytes) = rest.split_at(SIGNATURE_SIZE);
    
    // Vérification: on ne doit PAS utiliser les mêmes données pour message et signature
    // C'était la faille de sécurité dans l'implémentation précédente
    
    // Conversion de la clé publique (avec gestion d'erreur)
    let pk_result = tsn_crypto::signature::PublicKey::from_bytes(pk_bytes);
    
    if let Ok(pk) = pk_result {
        // Création de la signature depuis les bytes dédiés
        let sig = tsn_crypto::signature::Signature::from_bytes(sig_bytes.to_vec());
        
        // Vérification avec message et signature distincts
        let _ = pk.verify(msg_bytes, &sig);
    }
});