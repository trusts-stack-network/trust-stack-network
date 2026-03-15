//! Module RPC JSON-RPC 2.0 pour TSN
//!  
//! Expose :
//! - HTTP : POST /rpc
//! - WebSocket : ws://host/ws
//! - Authentification par API keys avec permissions
//! - Rate limiting par clé

pub mod auth;
pub mod rate_limiter;
pub mod server;

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Contexte RPC partagé
#[derive(Clone)]
pub struct RpcContext {
    /// Gestionnaire de clés API
    pub auth_manager: Arc<tokio::sync::RwLock<auth::ApiKeyManager>>,
    /// Rate limiter
    pub rate_limiter: Arc<tokio::sync::RwLock<rate_limiter::RateLimiter>>,
}

impl RpcContext {
    /// Crée un nouveau contexte RPC
    pub fn new() -> Self {
        let mut auth_manager = auth::ApiKeyManager::new();
        
        // Créer des clés par défaut (à remplacer par une config en production)
        let _ = auth_manager.create_key("default-read", vec![auth::Permission::Read]);
        let _ = auth_manager.create_key("default-write", vec![auth::Permission::Read, auth::Permission::Write]);
        let _ = auth_manager.create_key("default-admin", vec![auth::Permission::Read, auth::Permission::Write, auth::Permission::Admin]);
        
        Self {
            auth_manager: Arc::new(tokio::sync::RwLock::new(auth_manager)),
            rate_limiter: Arc::new(tokio::sync::RwLock::new(crate_limiter::RateLimiter::new())),
        }
    }
}

impl Default for RpcContext {
    fn default() -> Self {
        Self::new()
    }
}