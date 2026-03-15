//! Periodic version checker for TSN nodes.
//!
//! Queries seed nodes for their `/version.json` endpoint every 6 hours
//! and warns if the local node is outdated.

use serde::Deserialize;
use std::time::Duration;
use tracing::{info, warn};

use crate::config::SEED_NODES;

/// Version info returned by seed nodes.
#[derive(Debug, Deserialize)]
struct RemoteVersionInfo {
    version: String,
    minimum_version: String,
    #[allow(dead_code)]
    protocol_version: u16,
}

/// Interval between version checks (6 hours).
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Local node version from Cargo.toml.
const LOCAL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Parse a semver string into (major, minor, patch) for comparison.
fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

/// Returns true if `a` is older than `b` (a < b).
fn version_less_than(a: &str, b: &str) -> bool {
    match (parse_semver(a), parse_semver(b)) {
        (Some(va), Some(vb)) => va < vb,
        _ => false,
    }
}

/// Check a single seed node for version info.
async fn check_seed_version(client: &reqwest::Client, seed_url: &str) -> Option<RemoteVersionInfo> {
    let url = format!("{}/version.json", seed_url);
    match client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) => match resp.json::<RemoteVersionInfo>().await {
            Ok(info) => Some(info),
            Err(e) => {
                warn!("Failed to parse version from {}: {}", seed_url, e);
                None
            }
        },
        Err(e) => {
            warn!("Failed to query version from {}: {}", seed_url, e);
            None
        }
    }
}

/// Run a single version check against all seed nodes.
async fn do_version_check() {
    let client = reqwest::Client::new();
    let mut latest_version: Option<String> = None;
    let mut latest_minimum: Option<String> = None;

    for seed in SEED_NODES {
        if let Some(info) = check_seed_version(&client, seed).await {
            // Track the highest version seen
            match &latest_version {
                Some(current) if !version_less_than(current, &info.version) => {}
                _ => {
                    latest_version = Some(info.version);
                    latest_minimum = Some(info.minimum_version);
                }
            }
        }
    }

    if let (Some(latest), Some(minimum)) = (latest_version, latest_minimum) {
        if version_less_than(LOCAL_VERSION, &minimum) {
            warn!(
                "TSN node outdated! Please upgrade to v{}. Download at tsnchain.com",
                latest
            );
        } else if version_less_than(LOCAL_VERSION, &latest) {
            info!("New TSN version available: v{}", latest);
        }
    }
}

/// Start the periodic version check loop.
///
/// Runs an initial check on startup, then every 6 hours.
pub async fn version_check_loop() {
    info!(
        "Version checker started (local: v{}, checking every {}h)",
        LOCAL_VERSION,
        CHECK_INTERVAL.as_secs() / 3600
    );

    // Initial check
    do_version_check().await;

    // Periodic checks
    let mut interval = tokio::time::interval(CHECK_INTERVAL);
    interval.tick().await; // Skip immediate first tick (already checked above)
    loop {
        interval.tick().await;
        do_version_check().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_semver() {
        assert_eq!(parse_semver("0.3.0"), Some((0, 3, 0)));
        assert_eq!(parse_semver("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_semver("invalid"), None);
    }

    #[test]
    fn test_version_less_than() {
        assert!(version_less_than("0.2.0", "0.3.0"));
        assert!(version_less_than("0.3.0", "0.3.1"));
        assert!(version_less_than("0.3.0", "1.0.0"));
        assert!(!version_less_than("0.3.0", "0.3.0"));
        assert!(!version_less_than("0.4.0", "0.3.0"));
    }
}
