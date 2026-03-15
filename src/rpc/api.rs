use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

// Structure pour stocker les informations de l'API
struct Api {
    tx: mpsc::Sender<SocketAddr>,
}

impl Api {
    async fn new(tx: mpsc::Sender<SocketAddr>) -> Self {
        Api { tx }
    }

    async fn handle_request(&self, request: Json<Request>) -> impl IntoResponse {
        match request {
            Request::GetPeers => {
                let peers = self.get_peers().await;
                (StatusCode::OK, Json(peers))
            }
            Request::GetBlocks => {
                let blocks = self.get_blocks().await;
                (StatusCode::OK, Json(blocks))
            }
            _ => (StatusCode::NOT_FOUND, "Not Found"),
        }
    }

    async fn get_peers(&self) -> Vec<SocketAddr> {
        // Récupérer la liste des pairs connus
        let mut peers = Vec::new();
        // ...
        peers
    }

    async fn get_blocks(&self) -> Vec<Block> {
        // Récupérer la liste des blocs
        let mut blocks = Vec::new();
        // ...
        blocks
    }
}

// Structure pour stocker les informations de la requête
#[derive(Deserialize, Serialize)]
enum Request {
    GetPeers,
    GetBlocks,
}

// Structure pour stocker les informations du bloc
#[derive(Deserialize, Serialize)]
struct Block {
    // ...
}