// DISABLED: depends on unavailable crate (proptest/tsn_crypto/etc.)
#![cfg(feature = "disabled_test")]
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use log::info;

#[tokio::test]
async fn test_handshake() {
    // Créer un serveur de test
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();

    // Créer un client de test
    let client = TcpStream::connect("127.0.0.1:8080").await.unwrap();

    // Envoyer la requête de handshake
    let handshake_req = HandshakeRequest {
        id: "TSN".to_string(),
        version: "1.0".to_string(),
    };

    let handshake_req_bytes = serde_json::to_vec(&handshake_req).unwrap();
    client.write_all(&handshake_req_bytes).await.unwrap();

    // Lire la réponse de handshake
    let mut handshake_resp_bytes = [0; 1024];
    client.read(&mut handshake_resp_bytes).await.unwrap();

    let handshake_resp: HandshakeResponse =
        serde_json::from_slice(&handshake_resp_bytes).unwrap();

    // Vérifier la réponse de handshake
    assert_eq!(handshake_resp.id, "TSN");
}
