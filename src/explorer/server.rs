use axum::{
    response::Redirect,
    routing::get,
    Router,
};

/// Create the explorer router (redirects to React app at /explorer).
pub fn create_explorer_router() -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::permanent("/explorer") }))
}
