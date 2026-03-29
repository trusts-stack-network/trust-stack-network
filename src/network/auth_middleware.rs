//! Middleware d'authentification par API keys pour l'API REST TSN
//!
//! Supporte :
//! - API keys avec permissions (read, write, admin)
//! - Rate limiting par clé API
//! - Extraction depuis header X-API-Key ou query param ?api_key=

use axum::{
    body::Body,
    extract::{Query, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::rpc::auth::{ApiKey, ApiKeyManager, Permission};

/// Paramètres de requête pour l'authentification par query string
#[derive(Debug, Deserialize)]
pub struct AuthQuery {
    #[serde(rename = "api_key")]
    api_key: Option<String>,
}

/// État de l'authentification extrait de la requête
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Clé API utilisée (None si pas d'authentification)
    pub api_key: Option<ApiKey>,
    /// Permissions effectives
    pub permissions: Vec<Permission>,
    /// Est-ce une requête authentifiée ?
    pub is_authenticated: bool,
    /// Est-ce un admin ?
    pub is_admin: bool,
}

impl AuthContext {
    /// Crée un contexte anonyme (pas d'authentification)
    pub fn anonymous() -> Self {
        Self {
            api_key: None,
            permissions: vec![Permission::Read], // Les anonymes ont lecture seule
            is_authenticated: false,
            is_admin: false,
        }
    }

    /// Crée un contexte à partir d'une clé API valide
    pub fn from_api_key(key: ApiKey) -> Self {
        let is_admin = key.permissions.contains(&Permission::Admin);
        Self {
            permissions: key.permissions.clone(),
            api_key: Some(key),
            is_authenticated: true,
            is_admin,
        }
    }

    /// Vérifie si le contexte a une permission donnée
    pub fn has_permission(&self, perm: Permission) -> bool {
        self.permissions.contains(&perm) || self.is_admin
    }

    /// Vérifie si le contexte peut lire
    pub fn can_read(&self) -> bool {
        self.has_permission(Permission::Read)
    }

    /// Vérifie si le contexte peut écrire
    pub fn can_write(&self) -> bool {
        self.has_permission(Permission::Write)
    }

    /// Vérifie si le contexte est admin
    pub fn is_admin_only(&self) -> bool {
        self.has_permission(Permission::Admin)
    }
}

/// État partagé pour le middleware d'authentification
pub struct AuthMiddlewareState {
    /// Gestionnaire de clés API
    pub key_manager: Arc<RwLock<ApiKeyManager>>,
    /// Rate limiting par clé API: (key_id, bucket)
    pub rate_buckets: Arc<RwLock<HashMap<String, RateBucket>>>,
    /// Configuration du rate limiting
    pub rate_config: RateLimitConfig,
}

impl AuthMiddlewareState {
    /// Crée un nouvel état d'authentification
    pub fn new(key_manager: ApiKeyManager, rate_config: RateLimitConfig) -> Self {
        Self {
            key_manager: Arc::new(RwLock::new(key_manager)),
            rate_buckets: Arc::new(RwLock::new(HashMap::new())),
            rate_config,
        }
    }

    /// Crée un état avec des clés par défaut (pour les tests)
    pub fn with_default_keys() -> Self {
        let mut manager = ApiKeyManager::new();
        
        // Clé read-only par défaut
        let _ = manager.create_key("default-read", vec![Permission::Read]);
        
        // Clé write par défaut (à changer en production)
        let _ = manager.create_key("default-write", vec![Permission::Read, Permission::Write]);
        
        // Clé admin par défaut (à changer absolument en production)
        let _ = manager.create_key("default-admin", vec![Permission::Read, Permission::Write, Permission::Admin]);

        Self::new(manager, RateLimitConfig::default())
    }
}

/// Configuration du rate limiting
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Requêtes par seconde pour les clés anonymes
    pub anon_rps: u64,
    /// Burst pour les clés anonymes
    pub anon_burst: u32,
    /// Requêtes par seconde pour les clés authentifiées
    pub auth_rps: u64,
    /// Burst pour les clés authentifiées
    pub auth_burst: u32,
    /// Requêtes par seconde pour les admins
    pub admin_rps: u64,
    /// Burst pour les admins
    pub admin_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            anon_rps: 10,
            anon_burst: 20,
            auth_rps: 100,
            auth_burst: 200,
            admin_rps: 1000,
            admin_burst: 2000,
        }
    }
}

/// Bucket de rate limiting pour une clé
#[derive(Debug)]
struct RateBucket {
    tokens: f64,
    last_update: Instant,
    capacity: f64,
    refill_rate: f64,
}

impl RateBucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: Instant::now(),
            capacity,
            refill_rate,
        }
    }

    fn try_consume(&mut self, tokens: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        // Refill tokens
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);

        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }
}

/// Réponse d'erreur d'authentification
#[derive(Serialize)]
struct AuthErrorResponse {
    error: String,
    code: u16,
}

/// Erreurs d'authentification
#[derive(Debug)]
pub enum AuthError {
    MissingApiKey,
    InvalidApiKey,
    ExpiredApiKey,
    RevokedApiKey,
    RateLimited,
    InsufficientPermissions(Permission),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingApiKey => (StatusCode::UNAUTHORIZED, "Missing API key"),
            AuthError::InvalidApiKey => (StatusCode::UNAUTHORIZED, "Invalid API key"),
            AuthError::ExpiredApiKey => (StatusCode::UNAUTHORIZED, "Expired API key"),
            AuthError::RevokedApiKey => (StatusCode::UNAUTHORIZED, "Revoked API key"),
            AuthError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"),
            AuthError::InsufficientPermissions(perm) => {
                (StatusCode::FORBIDDEN, &format!("Insufficient permissions: {:?} required", perm))
            }
        };

        let body = Json(AuthErrorResponse {
            error: message.to_string(),
            code: status.as_u16(),
        });

        (status, body).into_response()
    }
}

/// Extrait la clé API de la requête (header ou query param)
fn extract_api_key(req: &Request) -> Option<String> {
    // 1. Essayer le header X-API-Key
    if let Some(header) = req.headers().get("X-API-Key") {
        if let Ok(key) = header.to_str() {
            return Some(key.to_string());
        }
    }

    // 2. Essayer le header Authorization: Bearer <key>
    if let Some(header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth) = header.to_str() {
            if auth.starts_with("Bearer ") {
                return Some(auth[7..].to_string());
            }
        }
    }

    None
}

/// Middleware d'authentification principal
pub async fn auth_middleware(
    State(state): State<Arc<AuthMiddlewareState>>,
    req: Request,
    next: Next,
) -> Result<Response, AuthError> {
    // Extraire la clé API
    let api_key_str = extract_api_key(&req);

    // Construire le contexte d'authentification
    let auth_context = if let Some(key_str) = api_key_str {
        let manager = state.key_manager.read().await;
        
        match manager.validate_key(&key_str) {
            Some(key) => {
                debug!("API key validated: {}", key.id);
                AuthContext::from_api_key(key)
            }
            None => {
                warn!("Invalid API key attempt");
                return Err(AuthError::InvalidApiKey);
            }
        }
    } else {
        // Pas de clé API = accès anonyme
        AuthContext::anonymous()
    };

    // Vérifier le rate limiting
    let rate_limit_key = auth_context
        .api_key
        .as_ref()
        .map(|k| k.id.clone())
        .unwrap_or_else(|| "anonymous".to_string());

    let (rps, burst) = if auth_context.is_admin {
        (state.rate_config.admin_rps, state.rate_config.admin_burst)
    } else if auth_context.is_authenticated {
        (state.rate_config.auth_rps, state.rate_config.auth_burst)
    } else {
        (state.rate_config.anon_rps, state.rate_config.anon_burst)
    };

    {
        let mut buckets = state.rate_buckets.write().await;
        let bucket = buckets
            .entry(rate_limit_key)
            .or_insert_with(|| RateBucket::new(burst as f64, rps as f64));

        if !bucket.try_consume(1.0) {
            warn!("Rate limit exceeded for key");
            return Err(AuthError::RateLimited);
        }
    }

    // Ajouter le contexte d'authentification aux extensions de la requête
    let mut req = req;
    req.extensions_mut().insert(auth_context);

    Ok(next.run(req).await)
}

/// Middleware qui requiert une permission spécifique
pub async fn require_permission(
    req: Request,
    next: Next,
    permission: Permission,
) -> Result<Response, AuthError> {
    let auth_context = req
        .extensions()
        .get::<AuthContext>()
        .cloned()
        .unwrap_or_else(AuthContext::anonymous);

    if !auth_context.has_permission(permission) {
        return Err(AuthError::InsufficientPermissions(permission));
    }

    Ok(next.run(req).await)
}

/// Middleware qui requiert l'authentification
pub async fn require_auth(
    req: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let auth_context = req
        .extensions()
        .get::<AuthContext>()
        .cloned()
        .unwrap_or_else(AuthContext::anonymous);

    if !auth_context.is_authenticated {
        return Err(AuthError::MissingApiKey);
    }

    Ok(next.run(req).await)
}

/// Middleware qui requiert les droits admin
pub async fn require_admin(
    req: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let auth_context = req
        .extensions()
        .get::<AuthContext>()
        .cloned()
        .unwrap_or_else(AuthContext::anonymous);

    if !auth_context.is_admin {
        return Err(AuthError::InsufficientPermissions(Permission::Admin));
    }

    Ok(next.run(req).await)
}

/// Extension trait pour extraire le contexte d'authentification
pub trait AuthExt {
    fn auth_context(&self) -> AuthContext;
}

impl AuthExt for Request {
    fn auth_context(&self) -> AuthContext {
        self.extensions()
            .get::<AuthContext>()
            .cloned()
            .unwrap_or_else(AuthContext::anonymous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_bucket() {
        let mut bucket = RateBucket::new(10.0, 5.0);
        
        // Should allow 10 requests immediately
        for _ in 0..10 {
            assert!(bucket.try_consume(1.0));
        }
        
        // 11th should fail
        assert!(!bucket.try_consume(1.0));
    }

    #[test]
    fn test_auth_context_permissions() {
        let ctx = AuthContext::anonymous();
        assert!(ctx.can_read());
        assert!(!ctx.can_write());
        assert!(!ctx.is_admin_only());
    }
}