//! Erreurs cryptographiques

#[derive(Debug)]
pub enum CryptoError {
    KeygenError,
    SignError,
    VerifyError,
}