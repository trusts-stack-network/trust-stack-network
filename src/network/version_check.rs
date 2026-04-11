//! Periodic version checker for TSN nodes.
//!
//! Queries seed nodes for their `/version.json` endpoint and **blocks mining**
//! if the local node is below the network's `minimum_version`.
//! Nodes that are outdated will stop mining and refuse to produce blocks
//! until they are upgraded. This prevents forks caused by incompatible versions.

use serde::Deserialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{info, warn, error};

use crate::config::SEED_NODES;

/// Version info returned by seed nodes.
#[derive(Debug, Deserialize)]
struct RemoteVersionInfo {
    version: String,
    minimum_version: String,
    #[allow(dead_code)]
    protocol_version: u16,
}

/// Interval between version checks (30 minutes — faster detection of required upgrades).
const CHECK_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Local node version from Cargo.toml.
pub const LOCAL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Minimum version this node requires from peers.
/// Updated at each release to match the network.
/// Nodes below this version are rejected during sync and disconnected via P2P.
pub const MINIMUM_VERSION: &str = "2.1.0";

/// Global flag: true = node is allowed to mine and sync. false = node is outdated.
static NODE_VERSION_OK: AtomicBool = AtomicBool::new(true);

/// Check if this node is allowed to mine (version is not outdated).
pub fn is_version_ok() -> bool {
    NODE_VERSION_OK.load(Ordering::Relaxed)
}

/// Parse a semver string into (major, minor, patch) for comparison.
/// Handles versions with role suffix like "1.3.5/miner" → strips everything after '/'.
pub fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    // Strip role suffix (e.g. "1.3.5/miner" → "1.3.5")
    let ver = v.split('/').next().unwrap_or(v);
    let parts: Vec<&str> = ver.split('.').collect();
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
pub fn version_less_than(a: &str, b: &str) -> bool {
    match (parse_semver(a), parse_semver(b)) {
        (Some(va), Some(vb)) => va < vb,
        _ => false,
    }
}

/// Returns true if version `v` meets the minimum version requirement.
pub fn version_meets_minimum(v: &str) -> bool {
    !version_less_than(v, MINIMUM_VERSION)
}

/// Check a single seed node for version info.
async fn check_seed_version(client: &reqwest::Client, seed_url: &str) -> Option<RemoteVersionInfo> {
    use crate::network::peer_id;
    let url = format!("{}/version.json", seed_url);
    let label = peer_id(seed_url);
    match client
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => match resp.json::<RemoteVersionInfo>().await {
            Ok(info) => Some(info),
            Err(e) => {
                warn!("Failed to parse version from {}", label);
                None
            }
        },
        Err(_) => {
            warn!("Failed to query version from {} (timeout or unreachable)", label);
            None
        }
    }
}

/// Run a single version check against all seed nodes.
/// Updates the global NODE_VERSION_OK flag.
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
            // CRITICAL: Node is below minimum — block mining
            NODE_VERSION_OK.store(false, Ordering::SeqCst);
            error!(
                "=== NODE OUTDATED === Version {} is below minimum required {}. \
                 Mining DISABLED. Please upgrade to v{} immediately! \
                 Download at https://tsnchain.com/",
                LOCAL_VERSION, minimum, latest
            );
        } else {
            // Node is OK — (re-)enable mining if it was previously disabled
            let was_blocked = !NODE_VERSION_OK.swap(true, Ordering::SeqCst);
            if was_blocked {
                info!("Node version {} meets minimum {} — mining RE-ENABLED", LOCAL_VERSION, minimum);
            }
            if version_less_than(LOCAL_VERSION, &latest) {
                info!("New TSN version available: v{} (current: v{})", latest, LOCAL_VERSION);
            }
        }
    }
}

/// Start the periodic version check loop.
///
/// Runs an initial check on startup, then every 30 minutes.
/// If the node is outdated, mining is automatically disabled via `is_version_ok()`.
pub async fn version_check_loop() {
    info!(
        "Version checker started (local: v{}, minimum: v{}, interval: {}min)",
        LOCAL_VERSION,
        MINIMUM_VERSION,
        CHECK_INTERVAL.as_secs() / 60
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

    #[test]
    fn test_version_meets_minimum() {
        assert!(version_meets_minimum(MINIMUM_VERSION));
        assert!(version_meets_minimum("2.1.0"));
        assert!(version_meets_minimum("2.1.1"));
        assert!(version_meets_minimum("2.2.0"));
        assert!(version_meets_minimum("3.0.0"));
        assert!(!version_meets_minimum("2.0.9"));
        assert!(!version_meets_minimum("2.0.8"));
        assert!(!version_meets_minimum("2.0.0"));
        assert!(!version_meets_minimum("1.9.0"));
        assert!(!version_meets_minimum("0.6.0"));
    }

    #[test]
    fn test_is_version_ok_default() {
        // By default, node is allowed to mine
        assert!(is_version_ok());
    }
}
