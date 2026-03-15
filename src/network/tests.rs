use super::*;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use log::{info, warn};
use std::collections::HashSet;

// Tests pour le réseau P2P
#[tokio::test]
async fn test_discover_nodes() {
    let nodes = discover_nodes().await;
    assert!(!nodes.is_empty());
}

#[tokio::test]
async fn test_handshake() {
    let mut stream = TcpStream::connect("localhost:8080").await.unwrap();
    handshake(&mut stream).await.unwrap();
}

#[tokio::test]
async fn test_rate_limiter() {
    let mut rate_limiter = RateLimiter::new();
    assert!(rate_limiter.allow_request());
    assert!(rate_limiter.allow_request());
    // ...
    assert!(!rate_limiter.allow_request());
}

#[tokio::test]
async fn test_network() {
    let listener = TcpListener::bind("0.0.0.0:8081").await.unwrap();
    let mut nodes = discover_nodes().await;
    let mut rate_limiter = RateLimiter::new();

    loop {
        tokio::select! {
            stream = listener.accept() => {
                match stream {
                    Ok((mut stream, _)) => {
                        if rate_limiter.allow_request() {
                            tokio::spawn(async move {
                                handshake(&mut stream).await.unwrap();
                                // Traitement des requêtes
                            });
                        } else {
                            // Refus de la requête due à rate limiting
                            stream.shutdown().await.unwrap();
                        }
                    }
                    Err(e) => {
                        warn!("Erreur d'acceptation de requête: {}", e);
                    }
                }
            }
            _ = interval(Duration::from_secs(60)) => {
                // Mise à jour des seed nodes
                nodes = discover_nodes().await;
            }
        }
    }
}