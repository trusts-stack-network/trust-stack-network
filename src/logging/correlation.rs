//! Correlation IDs for distributed tracing across modules
//!
//! This module provides utilities for tracking operations across multiple
//! modules and async boundaries. Correlation IDs allow tracing a single
//! operation (e.g., transaction processing) through all the components
//! it touches.
//!
//! # Usage
//!
//! ```rust
//! use tsn::logging::{CorrelationId, correlation_scope};
//!
//! async fn process_request() {
//!     let corr_id = CorrelationId::new();
//!     let _guard = correlation_scope(corr_id.clone());
//!     
//!     // All logs within this scope will include the correlation ID
//!     tracing::info!(correlation_id = %corr_id, "Processing request");
//! }
//! ```

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use tracing::{span, Instrument, Span};
use uuid::Uuid;

thread_local! {
    /// Thread-local storage for the current correlation ID
    static CURRENT_CORRELATION_ID: std::cell::RefCell<Option<CorrelationId>> = std::cell::RefCell::new(None);
}

/// A unique identifier for tracing operations across modules
///
/// Correlation IDs are used to track a single logical operation
/// as it flows through multiple components of the system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CorrelationId(Arc<str>);

impl CorrelationId {
    /// Create a new random correlation ID
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string().into())
    }

    /// Create a correlation ID from a string
    ///
    /// # Arguments
    /// * `id` - The correlation ID string
    pub fn from_string(id: impl Into<String>) -> Self {
        Self(id.into().into())
    }

    /// Get the correlation ID as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Generate a short correlation ID (first 8 characters)
    ///
    /// Useful for display purposes where space is limited.
    pub fn short(&self) -> &str {
        &self.0[..self.0.len().min(8)]
    }

    /// Check if this is a valid correlation ID (non-empty)
    pub fn is_valid(&self) -> bool {
        !self.0.is_empty()
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for CorrelationId {
    fn from(s: &str) -> Self {
        Self::from_string(s)
    }
}

impl From<String> for CorrelationId {
    fn from(s: String) -> Self {
        Self::from_string(s)
    }
}

/// Get the current correlation ID from thread-local storage
///
/// Returns `None` if no correlation ID has been set for this thread.
pub fn current_correlation_id() -> Option<CorrelationId> {
    CURRENT_CORRELATION_ID.with(|id| id.borrow().clone())
}

/// Set the correlation ID for the current thread
///
/// # Returns
/// The previous correlation ID, if any
pub fn set_correlation_id(id: CorrelationId) -> Option<CorrelationId> {
    CURRENT_CORRELATION_ID.with(|current| {
        let mut guard = current.borrow_mut();
        let prev = guard.take();
        *guard = Some(id);
        prev
    })
}

/// Clear the correlation ID for the current thread
///
/// # Returns
/// The previous correlation ID, if any
pub fn clear_correlation_id() -> Option<CorrelationId> {
    CURRENT_CORRELATION_ID.with(|id| id.borrow_mut().take())
}

/// A guard that restores the previous correlation ID when dropped
pub struct CorrelationGuard {
    prev: Option<CorrelationId>,
}

impl Drop for CorrelationGuard {
    fn drop(&mut self) {
        CURRENT_CORRELATION_ID.with(|id| {
            *id.borrow_mut() = self.prev.take();
        });
    }
}

/// Set a correlation ID for the current scope
///
/// When the returned guard is dropped, the previous correlation ID
/// (if any) is restored.
///
/// # Example
///
/// ```rust
/// use tsn::logging::{CorrelationId, correlation_scope};
///
/// fn process() {
///     let _guard = correlation_scope(CorrelationId::new());
///     // correlation ID is active here
/// }
/// // previous correlation ID restored here
/// ```
pub fn correlation_scope(id: CorrelationId) -> CorrelationGuard {
    let prev = set_correlation_id(id);
    CorrelationGuard { prev }
}

/// Extension trait for futures to add correlation ID tracking
pub trait CorrelationFuture: Future + Sized {
    /// Instrument this future with a correlation ID
    ///
    /// The correlation ID will be set when the future is polled
    /// and restored when it yields.
    fn with_correlation(self, id: CorrelationId) -> CorrelatedFuture<Self>;
}

pin_project! {
    /// A future that carries a correlation ID
    pub struct CorrelatedFuture<F> {
        #[pin]
        inner: F,
        correlation_id: CorrelationId,
    }
}

impl<F: Future> Future for CorrelatedFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let _guard = correlation_scope(this.correlation_id.clone());
        this.inner.poll(cx)
    }
}

impl<F: Future + Sized> CorrelationFuture for F {
    fn with_correlation(self, id: CorrelationId) -> CorrelatedFuture<Self> {
        CorrelatedFuture {
            inner: self,
            correlation_id: id,
        }
    }
}

/// Create a tracing span with correlation ID information
///
/// This creates a span that automatically includes the current
/// correlation ID as a field.
///
/// # Arguments
/// * `level` - The span level (e.g., `tracing::Level::INFO`)
/// * `name` - The span name
/// * `fields` - Additional fields to include
///
/// # Example
///
/// ```rust
/// use tsn::logging::correlation_span;
/// use tracing::Level;
///
/// let span = correlation_span(Level::INFO, "process_block", "height" = 42u64);
/// let _enter = span.enter();
/// ```
#[macro_export]
macro_rules! correlation_span {
    ($level:expr, $name:expr $(, $key:tt = $value:expr)* $(,)?) => {
        {
            let corr_id = $crate::logging::correlation::current_correlation_id();
            tracing::span!(
                $level,
                $name,
                correlation_id = corr_id.as_ref().map(|id| id.as_str()).unwrap_or("none"),
                $($key = $value),*
            )
        }
    };
}

/// Create an info-level span with correlation ID
#[macro_export]
macro_rules! info_correlation_span {
    ($name:expr $(, $key:tt = $value:expr)* $(,)?) => {
        $crate::correlation_span!(tracing::Level::INFO, $name $(, $key = $value)*)
    };
}

/// Create a debug-level span with correlation ID
#[macro_export]
macro_rules! debug_correlation_span {
    ($name:expr $(, $key:tt = $value:expr)* $(,)?) => {
        $crate::correlation_span!(tracing::Level::DEBUG, $name $(, $key = $value)*)
    };
}

/// Create an error-level span with correlation ID
#[macro_export]
macro_rules! error_correlation_span {
    ($name:expr $(, $key:tt = $value:expr)* $(,)?) => {
        $crate::correlation_span!(tracing::Level::ERROR, $name $(, $key = $value)*)
    };
}

/// Instrument a function with correlation ID tracking
///
/// This attribute macro can be used to automatically extract or
/// generate correlation IDs for function calls.
///
/// Note: This is a simplified version. In production, you might
/// want to use a full procedural macro.
pub fn instrument_with_correlation<F, R>(f: F, id: Option<CorrelationId>) -> R
where
    F: FnOnce() -> R,
{
    let id = id.unwrap_or_else(CorrelationId::new);
    let _guard = correlation_scope(id);
    f()
}

/// Extract correlation ID from HTTP headers
///
/// Looks for common correlation ID header names:
/// - X-Correlation-ID
/// - X-Request-ID
/// - X-Trace-ID
#[cfg(feature = "http")]
pub fn extract_from_headers(headers: &axum::http::HeaderMap) -> Option<CorrelationId> {
    const HEADER_NAMES: &[&str] = &[
        "x-correlation-id",
        "x-request-id",
        "x-trace-id",
        "x-request-correlation-id",
    ];

    for name in HEADER_NAMES {
        if let Some(value) = headers.get(*name) {
            if let Ok(s) = value.to_str() {
                return Some(CorrelationId::from_string(s));
            }
        }
    }

    None
}

/// Add correlation ID to HTTP response headers
#[cfg(feature = "http")]
pub fn inject_into_headers(
    id: &CorrelationId,
    headers: &mut axum::http::HeaderMap,
) -> Result<(), axum::http::header::InvalidHeaderValue> {
    use axum::http::HeaderValue;

    let value = HeaderValue::from_str(id.as_str())?;
    headers.insert("x-correlation-id", value);
    Ok(())
}

/// A middleware that extracts/injects correlation IDs for HTTP requests
#[cfg(feature = "http")]
pub mod middleware {
    use super::*;
    use axum::{
        extract::Request,
        middleware::Next,
        response::Response,
    };

    /// Axum middleware for correlation ID handling
    ///
    /// Extracts the correlation ID from incoming requests and adds it
    /// to outgoing responses. Generates a new ID if none is present.
    pub async fn correlation_middleware(
        request: Request,
        next: Next,
    ) -> Response {
        // Extract or generate correlation ID
        let corr_id = extract_from_headers(request.headers())
            .unwrap_or_else(CorrelationId::new);

        // Create a span with the correlation ID
        let span = span!(
            tracing::Level::DEBUG,
            "http_request",
            correlation_id = %corr_id,
            method = %request.method(),
            uri = %request.uri(),
        );

        // Process the request within the correlation scope
        let response = next
            .run(request)
            .instrument(span)
            .with_correlation(corr_id.clone())
            .await;

        // Add correlation ID to response
        let mut response = response;
        if let Err(e) = inject_into_headers(&corr_id, response.headers_mut()) {
            tracing::warn!(error = %e, "Failed to inject correlation ID into response");
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_id_generation() {
        let id1 = CorrelationId::new();
        let id2 = CorrelationId::new();

        assert_ne!(id1, id2);
        assert!(!id1.as_str().is_empty());
        assert_eq!(id1.as_str().len(), 36); // UUID v4 length
    }

    #[test]
    fn test_correlation_id_from_string() {
        let id = CorrelationId::from_string("test-id-123");
        assert_eq!(id.as_str(), "test-id-123");
    }

    #[test]
    fn test_correlation_id_short() {
        let id = CorrelationId::from_string("abcdef12-3456-7890-abcd-ef1234567890");
        assert_eq!(id.short(), "abcdef12");
    }

    #[test]
    fn test_correlation_scope() {
        assert!(current_correlation_id().is_none());

        {
            let _guard = correlation_scope(CorrelationId::from_string("test-123"));
            assert_eq!(
                current_correlation_id().map(|id| id.as_str().to_string()),
                Some("test-123".to_string())
            );
        }

        assert!(current_correlation_id().is_none());
    }

    #[test]
    fn test_correlation_scope_nested() {
        let _outer = correlation_scope(CorrelationId::from_string("outer"));

        {
            let _inner = correlation_scope(CorrelationId::from_string("inner"));
            assert_eq!(
                current_correlation_id().map(|id| id.as_str().to_string()),
                Some("inner".to_string())
            );
        }

        assert_eq!(
            current_correlation_id().map(|id| id.as_str().to_string()),
            Some("outer".to_string())
        );
    }

    #[test]
    fn test_correlation_id_display() {
        let id = CorrelationId::from_string("test-id");
        assert_eq!(format!("{}", id), "test-id");
    }

    #[test]
    fn test_correlation_id_serialization() {
        let id = CorrelationId::from_string("test-serialization");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"test-serialization\"");

        let decoded: CorrelationId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }
}
