// Module pour les erreurs liées aux primitives cryptographiques post-quantiques

#[derive(Debug)]
pub enum Error {
    CryptoError(String),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::CryptoError(msg) => write!(f, "Erreur cryptographique : {}", msg),
        }
    }
}