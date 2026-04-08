//! Automatic node update system for TSN.
//!
//! Handles automatic detection, download, verification, and installation of new
//! TSN node releases. Supports multi-source download (GitHub + fallback) and
//! SHA256 integrity verification with Ed25519 signature verification (Phase 2).
//!
//! ## Update flow
//!
//! 1. **Detection**: Polls GitHub Releases API and/or fallback manifest on tsnchain.com.
//!    Additionally, peers may signal newer versions via the P2P Identify protocol.
//! 2. **Download**: Fetches the platform-appropriate binary from the best available source.
//! 3. **Verification**: Validates SHA256 checksum; Ed25519 signature in Phase 2.
//! 4. **Installation**: Extracts archive, backs up current binary, replaces in-place.
//! 5. **Restart**: Exits cleanly for systemd restart or re-execs with the same arguments.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::time::Duration;
use tracing::{info, warn, error};

use crate::config::SEED_NODES;
use crate::network::version_check::{LOCAL_VERSION, version_less_than};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Ed25519 public key used to verify release signatures (Phase 2).
/// Generated offline and embedded at compile time.
pub const RELEASE_SIGNING_PUBKEY: [u8; 32] = [
    0xf0, 0xbb, 0x3b, 0x2b, 0x6f, 0xf6, 0xd8, 0x4b,
    0x8f, 0x63, 0x56, 0xac, 0x4a, 0xff, 0x29, 0x2b,
    0xf7, 0x49, 0x9f, 0xcf, 0x5d, 0x4a, 0x09, 0x94,
    0x2e, 0xf2, 0xfb, 0x8f, 0x58, 0xc9, 0x95, 0x6a,
];

/// GitHub Releases API endpoint for the latest release.
const GITHUB_RELEASE_URL: &str =
    "https://api.github.com/repos/trusts-stack-network/trust-stack-network/releases/latest";

/// Fallback release manifest hosted on our own infrastructure (HTTPS).
const FALLBACK_RELEASE_URL: &str = "https://tsnchain.com/releases/latest.json";

/// Interval between automatic update checks.
const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// HTTP User-Agent header sent with all requests.
fn user_agent() -> String {
    format!("TSN-Node/{}", LOCAL_VERSION)
}

// ---------------------------------------------------------------------------
// P2P version signaling
// ---------------------------------------------------------------------------

/// Latest version reported by any connected peer.
static LATEST_PEER_VERSION: Mutex<Option<String>> = Mutex::new(None);

/// Called by the P2P layer when a peer announces its version via Identify.
/// Only stores the version if it is newer than our LOCAL version.
pub fn notify_peer_version(version: &str) {
    // Ignore peers running an older or equal version
    if !version_less_than(LOCAL_VERSION, version) {
        return;
    }
    let mut guard = LATEST_PEER_VERSION.lock().unwrap_or_else(|e| e.into_inner());
    let should_update = match &*guard {
        Some(current) => version_less_than(current, version),
        None => true,
    };
    if should_update {
        info!(peer_version = %version, local = %LOCAL_VERSION, "Peer announced newer version");
        *guard = Some(version.to_string());
    }
}

/// Returns the latest version seen from peers, if any.
pub fn get_latest_peer_version() -> Option<String> {
    LATEST_PEER_VERSION
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A GitHub release object (subset of fields we care about).
#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
    #[allow(dead_code)]
    body: String,
}

/// A single asset attached to a GitHub release.
#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    #[allow(dead_code)]
    size: u64,
}

/// Self-hosted release manifest (served by tsnchain.com).
#[derive(Debug, Deserialize)]
struct ReleaseManifest {
    version: String,
    assets: HashMap<String, AssetInfo>,
    /// Hex-encoded Ed25519 signature over the SHA256 digest of the manifest body
    /// (excluding this field). Reserved for Phase 2; may be empty.
    #[serde(default)]
    signature: String,
}

/// Per-platform asset metadata inside a [`ReleaseManifest`].
#[derive(Debug, Clone, Deserialize)]
struct AssetInfo {
    url: String,
    sha256: String,
    #[allow(dead_code)]
    size: u64,
}

/// Resolved update information ready for download.
#[derive(Debug, Clone)]
struct ResolvedUpdate {
    version: String,
    download_url: String,
    expected_sha256: Option<String>,
}

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

/// Returns the expected release asset filename for the given version and current
/// platform/architecture combination.
pub fn get_platform_asset_name(version: &str) -> String {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64" // default fallback
    };

    let ext = if cfg!(target_os = "windows") {
        "zip"
    } else {
        "tar.gz"
    };

    format!("tsn-{}-{}-{}.{}", version, os, arch, ext)
}

// ---------------------------------------------------------------------------
// Update check
// ---------------------------------------------------------------------------

/// Queries remote sources for the latest available version.
///
/// Returns `Some((new_version, download_url, optional_sha256))` when a version
/// newer than [`LOCAL_VERSION`] is available. Falls back from GitHub to the
/// self-hosted manifest automatically.
async fn check_for_update(
    client: &reqwest::Client,
) -> Option<ResolvedUpdate> {
    // 1. Try GitHub first
    if let Some(resolved) = check_github(client).await {
        return Some(resolved);
    }

    // 2. Fallback to self-hosted manifest
    if let Some(resolved) = check_fallback(client).await {
        return Some(resolved);
    }

    // 3. Check if any peer announced a newer version (informational only —
    //    we still need a download URL, so just log a warning).
    if let Some(peer_ver) = get_latest_peer_version() {
        if version_less_than(LOCAL_VERSION, &peer_ver) {
            warn!(
                "Peer reported newer version v{} but no download source found. \
                 Please upgrade manually at https://tsnchain.com/",
                peer_ver
            );
        }
    }

    None
}

/// Check the GitHub Releases API for a newer version.
///
/// Also fetches the companion `.sha256` file from the same GitHub release
/// so we can verify the download without depending on the fallback manifest.
async fn check_github(client: &reqwest::Client) -> Option<ResolvedUpdate> {
    let resp = client
        .get(GITHUB_RELEASE_URL)
        .header("User-Agent", user_agent())
        .header("Accept", "application/vnd.github+json")
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        warn!(status = %resp.status(), "GitHub API returned non-200");
        return None;
    }

    let release: GithubRelease = resp.json().await.ok()?;
    let version = release.tag_name.trim_start_matches('v').to_string();

    if !version_less_than(LOCAL_VERSION, &version) {
        return None;
    }

    let asset_name = get_platform_asset_name(&version);
    let asset = release.assets.iter().find(|a| a.name == asset_name)?;

    // Fetch SHA256 from the companion .sha256 file in the same GitHub release
    let sha256_asset_name = format!("{}.sha256", asset_name);
    let expected_sha256 = if let Some(sha256_asset) = release.assets.iter().find(|a| a.name == sha256_asset_name) {
        match client
            .get(&sha256_asset.browser_download_url)
            .header("User-Agent", user_agent())
            .timeout(Duration::from_secs(15))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(text) = resp.text().await {
                    // Format: "sha256hash  filename" — extract just the hash
                    let hash = text.split_whitespace().next().unwrap_or("").trim().to_string();
                    if hash.len() == 64 {
                        info!(sha256 = %hash, "Got SHA256 from GitHub companion file");
                        Some(hash)
                    } else {
                        warn!("GitHub .sha256 file has unexpected format: {}", text.trim());
                        None
                    }
                } else {
                    None
                }
            }
            _ => {
                warn!("Failed to fetch GitHub .sha256 companion file");
                None
            }
        }
    } else {
        None
    };

    info!(
        current = %LOCAL_VERSION,
        available = %version,
        asset = %asset_name,
        has_sha256 = expected_sha256.is_some(),
        "New release found on GitHub"
    );

    Some(ResolvedUpdate {
        version,
        download_url: asset.browser_download_url.clone(),
        expected_sha256,
    })
}

/// Check the self-hosted release manifest for a newer version.
async fn check_fallback(client: &reqwest::Client) -> Option<ResolvedUpdate> {
    let resp = client
        .get(FALLBACK_RELEASE_URL)
        .header("User-Agent", user_agent())
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        warn!(status = %resp.status(), "Fallback manifest returned non-200");
        return None;
    }

    let manifest: ReleaseManifest = resp.json().await.ok()?;

    if !version_less_than(LOCAL_VERSION, &manifest.version) {
        return None;
    }

    let asset_name = get_platform_asset_name(&manifest.version);
    let asset_info = manifest.assets.get(&asset_name)?;

    info!(
        current = %LOCAL_VERSION,
        available = %manifest.version,
        asset = %asset_name,
        "New release found on fallback manifest"
    );

    Some(ResolvedUpdate {
        version: manifest.version,
        download_url: asset_info.url.clone(),
        expected_sha256: Some(asset_info.sha256.clone()),
    })
}

/// Fetch the SHA256 for a given version/asset from the fallback manifest.
/// Used to verify a GitHub-sourced download against our own manifest.
async fn fetch_expected_sha256(
    client: &reqwest::Client,
    version: &str,
) -> Option<String> {
    let resp = client
        .get(FALLBACK_RELEASE_URL)
        .header("User-Agent", user_agent())
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .ok()?;

    let manifest: ReleaseManifest = resp.json().await.ok()?;
    if manifest.version.trim_start_matches('v') != version.trim_start_matches('v') {
        return None;
    }

    let asset_name = get_platform_asset_name(version);
    manifest.assets.get(&asset_name).map(|a| a.sha256.clone())
}

/// Fetch the Ed25519 signature hex string for a given version from the fallback manifest.
async fn fetch_signature_hex(
    client: &reqwest::Client,
    version: &str,
) -> Option<String> {
    let resp = client
        .get(FALLBACK_RELEASE_URL)
        .header("User-Agent", user_agent())
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .ok()?;

    let manifest: ReleaseManifest = resp.json().await.ok()?;
    if manifest.version.trim_start_matches('v') != version.trim_start_matches('v') {
        return None;
    }

    if manifest.signature.is_empty() {
        None
    } else {
        Some(manifest.signature)
    }
}

// ---------------------------------------------------------------------------
// Download & verification
// ---------------------------------------------------------------------------

/// Downloads the update binary and verifies its SHA256 checksum.
///
/// Returns the raw bytes on success.
async fn download_update(
    client: &reqwest::Client,
    url: &str,
    expected_sha256: &str,
) -> Result<Vec<u8>, String> {
    info!(url = %url, "Downloading update...");

    let resp = client
        .get(url)
        .header("User-Agent", user_agent())
        .timeout(Duration::from_secs(300)) // 5 min max for large binaries
        .send()
        .await
        .map_err(|e| format!("Download request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Download returned HTTP {}", resp.status()));
    }

    let total_size = resp.content_length().unwrap_or(0);
    if total_size > 0 {
        info!(size_mb = total_size / (1024 * 1024), "Download size");
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("Failed to read download body: {}", e))?;

    info!(bytes = bytes.len(), "Download complete, verifying checksum...");

    // Compute SHA256
    let computed = compute_sha256(&bytes);
    let computed_hex = hex::encode(&computed);

    if computed_hex != expected_sha256.to_lowercase() {
        return Err(format!(
            "SHA256 mismatch: expected {}, got {}",
            expected_sha256, computed_hex
        ));
    }

    info!("SHA256 checksum verified successfully");
    Ok(bytes.to_vec())
}

/// Compute the SHA256 digest of a byte slice.
fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Verify an Ed25519 signature over a SHA256 hash.
///
/// **Phase 2**: Full Ed25519 verification using `ed25519-dalek`.
///
/// The release pipeline signs `SHA256(binary)` with the private key
/// corresponding to [`RELEASE_SIGNING_PUBKEY`]. This function reconstructs
/// the public key and verifies the signature over the 32-byte hash.
///
/// For backwards compatibility during rollout, an empty signature triggers a
/// warning but returns `true`. This will become mandatory in v1.3.6.
pub fn verify_signature(binary_sha256: &[u8; 32], signature_hex: &str) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if signature_hex.is_empty() {
        warn!(
            "No Ed25519 signature provided — skipping verification \
             (backwards compat, will be mandatory in v1.3.6)"
        );
        return true;
    }

    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) if b.len() == 64 => b,
        Ok(b) => {
            error!(len = b.len(), "Invalid signature length (expected 64 bytes)");
            return false;
        }
        Err(e) => {
            error!(error = %e, "Failed to decode signature hex");
            return false;
        }
    };

    // Parse the hardcoded public key
    let pubkey = match VerifyingKey::from_bytes(&RELEASE_SIGNING_PUBKEY) {
        Ok(k) => k,
        Err(e) => {
            error!(error = %e, "Failed to parse release signing public key");
            return false;
        }
    };

    // Parse the 64-byte signature
    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            error!("Signature byte conversion failed");
            return false;
        }
    };
    let signature = Signature::from_bytes(&sig_array);

    // Verify signature over the 32-byte SHA256 hash
    match pubkey.verify(binary_sha256, &signature) {
        Ok(()) => {
            info!("Ed25519 release signature verified successfully");
            true
        }
        Err(e) => {
            error!(error = %e, "Ed25519 signature verification FAILED — rejecting update");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

/// Extracts the downloaded archive and replaces the current binary.
///
/// Steps:
/// 1. Determine current executable path.
/// 2. Extract archive to a temporary directory.
/// 3. Locate the `tsn` binary inside the extracted files.
/// 4. Back up the current binary to `<name>.backup`.
/// 5. Overwrite the current binary.
/// 6. Set executable permissions (Unix only).
async fn apply_update(binary_data: &[u8]) -> Result<PathBuf, String> {
    let current_exe = {
        let exe = std::env::current_exe()
            .map_err(|e| format!("Cannot determine current executable: {}", e))?;
        // If current_exe doesn't point to a tsn binary (e.g. launched via nohup/bash),
        // fall back to well-known path /opt/tsn/bin/tsn
        if !exe.file_name().map(|n| n.to_str().unwrap_or("").starts_with("tsn")).unwrap_or(false) {
            let fallback = PathBuf::from("/opt/tsn/bin/tsn");
            if fallback.exists() {
                info!("current_exe ({}) is not tsn binary, using fallback: {}", exe.display(), fallback.display());
                fallback
            } else {
                exe
            }
        } else {
            exe
        }
    };

    let current_dir = current_exe
        .parent()
        .ok_or("Cannot determine executable directory")?;

    // Create temp extraction directory next to the binary
    let tmp_dir = current_dir.join(".tsn_update_tmp");
    if tmp_dir.exists() {
        std::fs::remove_dir_all(&tmp_dir)
            .map_err(|e| format!("Cannot clean old temp dir: {}", e))?;
    }
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| format!("Cannot create temp dir: {}", e))?;

    // Extract tar.gz (or zip on Windows)
    extract_archive(binary_data, &tmp_dir)?;

    // Find the tsn binary in the extracted files
    let new_binary = find_binary_in_dir(&tmp_dir)?;

    // Back up current binary
    let backup_path = current_exe.with_extension("backup");
    if backup_path.exists() {
        std::fs::remove_file(&backup_path)
            .map_err(|e| format!("Cannot remove old backup: {}", e))?;
    }
    std::fs::rename(&current_exe, &backup_path)
        .map_err(|e| format!("Cannot back up current binary: {}", e))?;
    info!(backup = %backup_path.display(), "Current binary backed up");

    // Move new binary into place
    std::fs::copy(&new_binary, &current_exe)
        .map_err(|e| format!("Cannot install new binary: {}", e))?;

    // Set executable permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&current_exe, perms)
            .map_err(|e| format!("Cannot set executable permissions: {}", e))?;
    }

    // Clean up temp directory
    let _ = std::fs::remove_dir_all(&tmp_dir);

    info!(path = %current_exe.display(), "New binary installed successfully");
    Ok(current_exe)
}

/// Extracts a `.tar.gz` archive into `dest_dir`.
fn extract_archive(data: &[u8], dest_dir: &Path) -> Result<(), String> {
    use flate2::read::GzDecoder;

    let decoder = GzDecoder::new(std::io::Cursor::new(data));
    let mut archive = tar::Archive::new(decoder);

    archive
        .unpack(dest_dir)
        .map_err(|e| format!("Archive extraction failed: {}", e))?;

    Ok(())
}

/// Searches `dir` (recursively, one level) for a binary named `tsn` (or `tsn.exe`).
fn find_binary_in_dir(dir: &Path) -> Result<PathBuf, String> {
    let binary_name = if cfg!(target_os = "windows") {
        "tsn.exe"
    } else {
        "tsn"
    };

    // Check directly in dir
    let direct = dir.join(binary_name);
    if direct.exists() {
        return Ok(direct);
    }

    // Check one level of subdirectories (archives often wrap in a folder)
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("Cannot read temp dir: {}", e))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let candidate = path.join(binary_name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    Err(format!(
        "Binary '{}' not found in extracted archive at {}",
        binary_name,
        dir.display()
    ))
}

// ---------------------------------------------------------------------------
// Restart
// ---------------------------------------------------------------------------

/// Restarts the node after a successful update.
///
/// - If running under systemd, exits cleanly (code 0) so the service manager
///   restarts us with the new binary.
/// - Otherwise, re-execs the new binary with the same command-line arguments.
///
/// `installed_path`: the path where the NEW binary was installed by `apply_update`.
/// We use this instead of `current_exe()` because after rename+copy,
/// `/proc/self/exe` still points to the OLD binary (renamed to .backup).
fn restart_node(installed_path: Option<PathBuf>) -> ! {
    let args: Vec<String> = std::env::args().collect();
    info!(args = ?args, "Restarting node with updated binary...");

    // Check if running under systemd
    if std::env::var("INVOCATION_ID").is_ok() || std::env::var("NOTIFY_SOCKET").is_ok() {
        info!("Running under systemd — exiting cleanly for automatic restart");
        std::process::exit(0);
    }

    // Determine which binary to exec:
    // 1. Use the installed path from apply_update (correct after rename)
    // 2. Fallback to args[0] resolved (the command the user typed)
    // 3. Last resort: current_exe() (may point to .backup after rename)
    let exe = installed_path
        .or_else(|| {
            let arg0 = PathBuf::from(&args[0]);
            std::fs::canonicalize(&arg0).ok()
        })
        .unwrap_or_else(|| std::env::current_exe().expect("Cannot determine executable path"));

    info!(exe = %exe.display(), "Re-exec target binary");

    // Re-exec with same arguments
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&exe)
            .args(&args[1..])
            .exec();
        // exec() only returns on error
        error!(error = %err, "Failed to re-exec binary");
        std::process::exit(1);
    }

    #[cfg(not(unix))]
    {
        match std::process::Command::new(&exe).args(&args[1..]).spawn() {
            Ok(_) => std::process::exit(0),
            Err(e) => {
                error!(error = %e, "Failed to spawn new process");
                std::process::exit(1);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Background auto-update loop
// ---------------------------------------------------------------------------

/// Background loop that periodically checks for and applies updates.
///
/// Spawned once at node startup. Runs forever until the process exits.
pub async fn auto_update_loop() {
    info!(
        version = %LOCAL_VERSION,
        interval_secs = UPDATE_CHECK_INTERVAL.as_secs(),
        "Auto-update loop started"
    );

    let client = reqwest::Client::builder()
        .user_agent(user_agent())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    // Small initial delay so the node finishes booting before we check
    tokio::time::sleep(Duration::from_secs(30)).await;

    let mut interval = tokio::time::interval(UPDATE_CHECK_INTERVAL);

    loop {
        interval.tick().await;

        match check_for_update(&client).await {
            Some(update) => {
                info!(
                    from = %LOCAL_VERSION,
                    to = %update.version,
                    url = %update.download_url,
                    "Update available — starting download"
                );

                // Resolve SHA256: use the one from the manifest, or fetch it
                let sha256 = match update.expected_sha256 {
                    Some(ref s) => Some(s.clone()),
                    None => fetch_expected_sha256(&client, &update.version).await,
                };

                let sha256 = match sha256 {
                    Some(s) => s,
                    None => {
                        error!(
                            "Cannot verify update: no SHA256 available for v{}. Skipping.",
                            update.version
                        );
                        continue;
                    }
                };

                match download_update(&client, &update.download_url, &sha256).await {
                    Ok(data) => {
                        // Ed25519 signature verification (Phase 2)
                        let binary_hash = compute_sha256(&data);

                        // Fetch signature from fallback manifest
                        let sig_hex = fetch_signature_hex(&client, &update.version).await;
                        let sig_ref = sig_hex.as_deref().unwrap_or("");

                        if sig_ref.is_empty() {
                            warn!(
                                version = %update.version,
                                "No Ed25519 signature found in manifest — signature check SKIPPED"
                            );
                        } else {
                            info!(
                                version = %update.version,
                                "Ed25519 signature found in manifest — verifying..."
                            );
                        }

                        if !verify_signature(&binary_hash, sig_ref) {
                            error!(
                                "Ed25519 signature verification FAILED for v{}. Aborting update.",
                                update.version
                            );
                            continue;
                        }

                        if !sig_ref.is_empty() {
                            info!("Ed25519 signature VERIFIED for v{}", update.version);
                        }

                        info!(bytes = data.len(), "Download verified, applying update...");
                        match apply_update(&data).await {
                            Ok(installed_path) => {
                                info!("Update to v{} applied successfully, restarting...", update.version);
                                restart_node(Some(installed_path));
                            }
                            Err(e) => error!(error = %e, "Failed to apply update"),
                        }
                    }
                    Err(e) => error!(error = %e, "Failed to download update"),
                }
            }
            None => {
                info!("Node is up to date (v{})", LOCAL_VERSION);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Manual update command (`tsn update`)
// ---------------------------------------------------------------------------

/// Manual update command for `tsn update`.
///
/// Checks for updates, downloads, verifies, applies, and restarts — printing
/// status to stdout with clear progress messages.
pub async fn cmd_update() -> Result<(), String> {
    println!("TSN Auto-Updater");
    println!("================");
    println!("Current version: v{}", LOCAL_VERSION);
    println!();

    let client = reqwest::Client::builder()
        .user_agent(user_agent())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    println!("Checking for updates...");

    let update = check_for_update(&client)
        .await
        .ok_or_else(|| "Already up to date.".to_string())?;

    println!("New version available: v{}", update.version);
    println!("Download URL: {}", update.download_url);
    println!();

    // Resolve SHA256
    let sha256 = match update.expected_sha256 {
        Some(ref s) => s.clone(),
        None => {
            println!("Fetching checksum from release manifest...");
            fetch_expected_sha256(&client, &update.version)
                .await
                .ok_or("No SHA256 checksum available. Cannot verify download safely.")?
        }
    };

    println!("Expected SHA256: {}", sha256);
    println!("Downloading...");

    let data = download_update(&client, &update.download_url, &sha256).await?;

    println!(
        "Downloaded {} bytes, checksum verified.",
        data.len()
    );
    println!("Applying update...");

    let installed_path = apply_update(&data).await?;

    println!("Update installed to: {}", installed_path.display());
    println!("Restarting node...");

    restart_node(Some(installed_path));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_platform_asset_name_format() {
        let name = get_platform_asset_name("1.2.0");
        assert!(name.starts_with("tsn-1.2.0-"));
        assert!(
            name.ends_with(".tar.gz") || name.ends_with(".zip"),
            "Unexpected extension in '{}'",
            name
        );
        // Should contain a valid OS
        assert!(
            name.contains("linux") || name.contains("macos") || name.contains("windows"),
            "No OS in '{}'",
            name
        );
        // Should contain a valid arch
        assert!(
            name.contains("x86_64") || name.contains("aarch64"),
            "No arch in '{}'",
            name
        );
    }

    #[test]
    fn test_compute_sha256() {
        let hash = compute_sha256(b"hello world");
        let hex_str = hex::encode(&hash);
        assert_eq!(
            hex_str,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_verify_signature_empty() {
        let hash = compute_sha256(b"test");
        // Empty signature → Phase 1 passthrough
        assert!(verify_signature(&hash, ""));
    }

    #[test]
    fn test_verify_signature_bad_hex() {
        let hash = compute_sha256(b"test");
        assert!(!verify_signature(&hash, "not_hex_at_all!!!"));
    }

    #[test]
    fn test_verify_signature_wrong_length() {
        let hash = compute_sha256(b"test");
        // Valid hex but wrong length (not 64 bytes)
        assert!(!verify_signature(&hash, "abcdef"));
    }

    #[test]
    fn test_verify_signature_invalid_sig() {
        let hash = compute_sha256(b"test data");
        // Valid hex, correct length (64 bytes = 128 hex chars), but wrong signature
        let fake_sig = "a".repeat(128);
        assert!(!verify_signature(&hash, &fake_sig));
    }

    #[test]
    fn test_peer_version_signaling() {
        // Reset state
        {
            let mut guard = LATEST_PEER_VERSION.lock().unwrap();
            *guard = None;
        }

        assert!(get_latest_peer_version().is_none());

        // Only versions strictly newer than LOCAL_VERSION are stored
        notify_peer_version("2.0.1");
        assert_eq!(get_latest_peer_version(), Some("2.0.1".to_string()));

        // Higher version replaces
        notify_peer_version("2.1.0");
        assert_eq!(get_latest_peer_version(), Some("2.1.0".to_string()));

        // Lower version does NOT replace
        notify_peer_version("2.0.5");
        assert_eq!(get_latest_peer_version(), Some("2.1.0".to_string()));
    }

    #[test]
    fn test_release_signing_pubkey_constant() {
        let hex_str = hex::encode(&RELEASE_SIGNING_PUBKEY);
        assert_eq!(
            hex_str,
            "f0bb3b2b6ff6d84b8f6356ac4aff292bf7499fcf5d4a09942ef2fb8f58c9956a"
        );
    }

    #[test]
    fn test_user_agent_format() {
        let ua = user_agent();
        assert!(ua.starts_with("TSN-Node/"));
        assert!(ua.contains(LOCAL_VERSION));
    }

    #[tokio::test]
    async fn test_check_for_update_no_network() {
        // With no network available, should gracefully return None
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        let result = check_for_update(&client).await;
        assert!(result.is_none());
    }
}
