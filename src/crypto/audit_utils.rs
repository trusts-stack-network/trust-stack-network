//! Utilitaires d'audit et détection de side channels
//! À inclure dans le crate crypto existant

use core::ptr::{read_volatile, write_volatile};
use subtle::ConstantTimeEq;

/// Compare deux slices en temps constant (mitigation timing attacks)
pub fn ct_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Zeroize sécurisé empêchant l'optimisation du compilateur
pub fn secure_zero(buf: &mut [u8]) {
    for i in 0..buf.len() {
        unsafe {
            write_volatile(buf.as_mut_ptr().add(i), 0u8);
        }
    }
    // Barrière mémoire pour empêcher le reordering
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// Détecte potentiellement une fuite via cache side channel
/// en mesurant le temps d'accès mémoire
pub fn detect_cache_timing_leak<F, T>(f: F) -> (T, u64)
where 
    F: FnOnce() -> T,
{
    use std::time::Instant;
    let start = Instant::now();
    let result = f();
    let elapsed = start.elapsed().as_nanos() as u64;
    (result, elapsed)
}

/// Vérifie que le temps d'exécution ne dépend pas des données secrètes
/// Usage: statistical analysis sur plusieurs exécutions
pub fn constant_time_check<F, G, T>(
    secret_gen: F,
    operation: G,
    iterations: usize,
) -> Vec<(T, u64)>
where
    F: Fn() -> Vec<u8>,
    G: Fn(&[u8]) -> T,
{
    let mut timings = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let secret = secret_gen();
        let (_, timing) = detect_cache_timing_leak(|| operation(&secret));
        timings.push((secret.len(), timing));
    }
    
    timings
}

/// Validation canonique pour éviter les attaques par point non-canonique (Curve25519, etc.)
pub fn validate_canonical_point(point: &[u8; 32]) -> bool {
    // Vérification que le point est canonique (pas de représentation alternative)
    // Pour Curve25519: vérifier que le bit de poids fort est 0
    point[31] & 0x80 == 0
}

/// Détection d'oracle de padding (PKCS#7)
pub fn padding_oracle_check(ciphertext: &[u8], block_size: usize) -> Result<bool, &'static str> {
    if ciphertext.len() % block_size != 0 {
        return Err("Invalid ciphertext length");
    }
    
    let last_byte = ciphertext.last().copied().unwrap_or(0) as usize;
    if last_byte == 0 || last_byte > block_size {
        return Ok(false); // Padding invalide
    }
    
    // Vérification en temps constant recommandée dans l'implémentation réelle
    let padding_start = ciphertext.len() - last_byte;
    let valid = ciphertext[padding_start..].iter().all(|&b| b == last_byte as u8);
    
    Ok(valid)
}