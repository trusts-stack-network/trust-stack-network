use axum::response::IntoResponse;
use axum::extract::Query;
use axum::http::StatusCode;
use std::error::Error;
use std::fmt;

// Types d'erreurs pour le protocole de sync
#[derive(Debug)]
enum RpcSyncError {
    InvalidMessage,
    InvalidBlockRange,
    BlockVerificationFailed,
    IoError(std::io::Error),
}

impl fmt::Display for RpcSyncError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RpcSyncError::InvalidMessage => write!(f, "Message invalide"),
            RpcSyncError::InvalidBlockRange => write!(f, "Plage de blocs invalide"),
            RpcSyncError::BlockVerificationFailed => write!(f, "Échec de la vérification du bloc"),
            RpcSyncError::IoError(e) => write!(f, "Erreur IO : {}", e),
        }
    }
}

impl Error for RpcSyncError {}

// Handler pour le protocole de sync
async fn sync_handler(
    Query(params): Query<SyncParams>,
) -> impl IntoResponse {
    // Requête de hauteur de chaîne
    let height = request_chain_height(&params.peer).await;

    // Téléchargement de blocs par plage
    let start = params.start;
    let end = params.end;
    let blocks = download_blocks(&params.peer, start, end).await;

    // Vérification et insertion des blocs
    verify_and_insert_blocks(blocks).await;

    (StatusCode::OK, "Sync réussie")
}

// Paramètres pour le protocole de sync
#[derive(serde::Deserialize)]
struct SyncParams {
    peer: String,
    start: u64,
    end: u64,
}