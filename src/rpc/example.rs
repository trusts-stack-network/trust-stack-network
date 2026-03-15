use axum::Json;
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;

// Structure pour les requêtes RPC
#[derive(Serialize, Deserialize)]
struct RpcRequest {
    method: String,
    params: Vec<String>,
}

// Structure pour les réponses RPC
#[derive(Serialize, Deserialize)]
struct RpcResponse {
    result: String,
    error: Option<String>,
}

// Fonction principale pour gérer les requêtes RPC
async fn rpc_handler(
    Json(request): Json<RpcRequest>,
    tx: mpsc::Sender<RpcRequest>,
) -> Json<RpcResponse> {
    // Gestion des requêtes RPC
    tx.send(request).await.unwrap();
    Json(RpcResponse {
        result: "OK".to_string(),
        error: None,
    })
}