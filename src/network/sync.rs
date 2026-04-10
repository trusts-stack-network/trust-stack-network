use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::time::{interval, Duration};
use tracing::{info, warn, debug};
use hex;

use crate::core::ShieldedBlock;
use crate::consensus::LWMA_WINDOW;

use crate::network::api::AppState;
use crate::network::peer_id;

/// Remove IP addresses and URLs from error messages for privacy.
fn sanitize_error(e: &dyn std::fmt::Display) -> String {
    let msg = e.to_string();
    if let Some(idx) = msg.find("url (") {
        format!("{}connection failed", &msg[..idx])
    } else if let Some(idx) = msg.find("http://") {
        format!("{}<hidden>", &msg[..idx])
    } else if let Some(idx) = msg.find("https://") {
        format!("{}<hidden>", &msg[..idx])
    } else {
        msg
    }
}

/// Ban a peer for the given duration.
fn ban_peer(state: &Arc<AppState>, peer_url: &str, duration_secs: u64) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(duration_secs);
    let mut bans = state.banned_peers.write().unwrap();
    bans.insert(peer_url.to_string(), until);
    warn!("Banned peer {} for {}s", peer_id(peer_url), duration_secs);
}

/// Sync the local chain from a peer node.
/// v2.0: Headers-first sync — fetches compact headers to detect forks BEFORE downloading blocks.
/// Inspired by Quantus (Substrate) and Dilithion (Bitcoin) sync protocols.
pub async fn sync_from_peer(state: Arc<AppState>, peer_url: &str) -> Result<u64, SyncError> {
    // Skip hashed peer IDs — not contactable URLs
    if !super::is_contactable_peer(peer_url) {
        return Ok(0);
    }

    let client = state.http_client.clone();

    // ── Step 1: Ban check ──
    {
        let bans = state.banned_peers.read().unwrap();
        if let Some(until) = bans.get(peer_url) {
            if std::time::Instant::now() < *until {
                debug!("Skipping banned peer {}", peer_id(peer_url));
                return Ok(0);
            }
        }
    }

    // ── Step 2: Version check ──
    {
        let version_url = format!("{}/version.json", peer_url);
        if let Ok(resp) = client.get(&version_url).timeout(Duration::from_secs(5)).send().await {
            if let Ok(info) = resp.json::<serde_json::Value>().await {
                if let Some(peer_version) = info["version"].as_str() {
                    if !crate::network::version_check::version_meets_minimum(peer_version) {
                        warn!(
                            "Rejecting sync from {} — outdated version {} (minimum: {})",
                            peer_id(peer_url), peer_version,
                            crate::network::version_check::MINIMUM_VERSION
                        );
                        return Err(SyncError::HttpError(format!(
                            "Peer version {} below minimum {}",
                            peer_version, crate::network::version_check::MINIMUM_VERSION
                        )));
                    }
                }
            }
        }
    }

    // ── Step 3: Get peer chain info ──
    let info_url = format!("{}/chain/info", peer_url);
    let response = client.get(&info_url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(SyncError::HttpError(format!("HTTP {}: {}", status, body)));
    }
    let peer_info: PeerChainInfo = response.json().await?;

    let (local_height, local_hash, local_genesis) = {
        let chain = state.blockchain.read()
            .map_err(|e| SyncError::LockPoisoned(format!("read lock: {}", e)))?;
        let genesis = chain.info().genesis_hash;
        (chain.height(), hex::encode(chain.latest_hash()), genesis)
    };

    // ── Step 4: Genesis compatibility check (strict) ──
    // Fetch the peer's actual genesis block hash via HTTP to prevent syncing
    // from an incompatible chain. This catches old-network peers that the
    // protocol magic (P2P only) and version check cannot block on REST API.
    let expected_genesis = crate::config::EXPECTED_GENESIS_HASH;
    if !expected_genesis.is_empty() {
        let genesis_url = format!("{}/block/height/0", peer_url);
        match client.get(&genesis_url).timeout(std::time::Duration::from_secs(5)).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(block) = resp.json::<PeerBlockInfo>().await {
                    if block.hash != expected_genesis {
                        warn!(
                            "Rejecting peer {} — genesis mismatch (peer: {}…, expected: {}…)",
                            peer_id(peer_url),
                            &block.hash[..16.min(block.hash.len())],
                            &expected_genesis[..16]
                        );
                        return Ok(0);
                    }
                }
            }
            _ => {
                // If we can't fetch genesis, fall back to chain/info check
                let placeholder = "0".repeat(64);
                let peer_has_real_genesis = !peer_info.genesis_hash.is_empty() && peer_info.genesis_hash != placeholder;
                let local_has_real_genesis = !local_genesis.is_empty() && local_genesis != placeholder;
                if peer_has_real_genesis && local_has_real_genesis && peer_info.genesis_hash != local_genesis {
                    warn!(
                        "Rejecting peer {} — incompatible genesis (peer: {}…, local: {}…)",
                        peer_id(peer_url),
                        &peer_info.genesis_hash[..16.min(peer_info.genesis_hash.len())],
                        &local_genesis[..16.min(local_genesis.len())]
                    );
                    return Ok(0);
                }
            }
        }
    }

    // ── Step 5: Determine sync mode ──
    // Use both height AND cumulative_work to decide if peer is ahead.
    // v1.6.0 removed work comparison ("unreliable after fast-sync") but that
    // caused flip-flop between miners at same height. The fix: use work as
    // tiebreaker, with a 5% tolerance for fast-sync estimation differences.
    let local_work = {
        let chain = state.blockchain.read()
            .map_err(|e| SyncError::LockPoisoned(format!("read lock: {}", e)))?;
        chain.cumulative_work()
    };
    let peer_work = peer_info.cumulative_work;

    let peer_ahead = peer_info.height > local_height
        || (peer_info.height == local_height && peer_work > local_work);
    let mut is_fork = peer_info.height == local_height
        && peer_info.latest_hash != local_hash;

    // At same height with different hash: only sync if peer has more work.
    // This prevents flip-flop where both miners keep switching to each other's chain.
    if is_fork && peer_work > 0 && local_work > 0 {
        if peer_work <= local_work {
            debug!(
                "SYNC_DEBUG: FORK_IGNORED peer={} peer_work={} <= local_work={} at height={}",
                peer_id(peer_url), peer_work, local_work, local_height
            );
            return Ok(0);
        }
    }
    if is_fork {
        warn!(
            "SYNC_DEBUG: === FORK_SEQUENCE START peer={} local_h={} local_hash={} peer_h={} peer_hash={} local_work={} peer_work={} ===",
            peer_id(peer_url), local_height, &local_hash[..16],
            peer_info.height, &peer_info.latest_hash[..16.min(peer_info.latest_hash.len())],
            local_work, peer_work
        );
    }

    // v1.8.0: Even if peer is behind, check for fork if peer is close enough.
    // Without this, a peer on a different chain but lower height is silently ignored,
    // and the fork diverges forever. Check headers to detect chain split.
    if !peer_ahead && !is_fork && peer_info.height > 0 {
        let height_diff = local_height.saturating_sub(peer_info.height);
        if height_diff <= 100 {
            // Peer is slightly behind — check if we share the same block at peer's height
            let chain = state.blockchain.read()
                .map_err(|e| SyncError::LockPoisoned(format!("read lock: {}", e)))?;
            let local_hash_at_peer_height = chain.get_block_by_height(peer_info.height)
                .map(|b| hex::encode(b.hash()));
            drop(chain);

            if let Some(local_h) = local_hash_at_peer_height {
                if local_h != peer_info.latest_hash && peer_work > 0 {
                    // Different hash at same height = FORK detected!
                    // We MUST resolve this fork even if we have more work locally,
                    // because our chain may not be the one the rest of the network follows.
                    // The fork resolution (find ancestor + rollback + reorg) will decide
                    // which chain wins based on cumulative work from the common ancestor.
                    warn!(
                        "SYNC_DEBUG: FORK_BEHIND_DETECTED peer={} peer_h={} peer_hash={} local_hash_at_peer_h={} peer_work={} local_work={}",
                        peer_id(peer_url), peer_info.height,
                        &peer_info.latest_hash[..16.min(peer_info.latest_hash.len())],
                        &local_h[..16], peer_work, local_work
                    );
                    is_fork = true;
                } else {
                    // Same hash at peer's height — no fork, peer just hasn't caught up
                    return Ok(0);
                }
            } else {
                return Ok(0);
            }
        } else {
            debug!("Peer {} too far behind ({} blocks), skipping", peer_id(peer_url), height_diff);
            return Ok(0);
        }
    } else if !peer_ahead && !is_fork {
        return Ok(0);
    }

    // ── Step 6: Headers-first fork detection ──
    // Instead of checking one block at local height, fetch headers to detect divergence
    if peer_ahead && !is_fork {
        match detect_fork_via_headers(&state, &client, peer_url, local_height).await {
            ForkDetection::NoFork => {
                // Peer extends our chain — proceed to block download
                info!("Syncing from peer {} (peer h={}, local h={})", peer_id(peer_url), peer_info.height, local_height);
            }
            ForkDetection::ForkDetected { ancestor_height } => {
                is_fork = true;
                info!(
                    "Headers-first: fork detected with {} at height {} (ancestor: {})",
                    peer_id(peer_url), peer_info.height, ancestor_height
                );
            }
            ForkDetection::Incompatible => {
                warn!(
                    "SYNC_DEBUG: INCOMPATIBLE peer={} local_h={} — no common ancestor in headers window, falling back to full search (Step 8)",
                    peer_id(peer_url), local_height
                );
                // Fast-path headers window too narrow — don't ban, let Step 8
                // (find_common_ancestor_headers) do a full search up to MAX_REORG_DEPTH.
                // The ban only happens if Step 8 also fails.
                is_fork = true;
            }
        }
    }

    // ── Step 7: Snapshot sync (fresh node) ──
    if local_height == 0 && peer_info.height > 0 {
        info!("Local height is 0, attempting snapshot sync from {}", peer_id(peer_url));
        match attempt_snapshot_sync(&state, &client, peer_url).await {
            Ok(height) if height > 0 => {
                info!("Snapshot sync complete: jumped to height {} from {}", height, peer_id(peer_url));
                return Ok(height);
            }
            _ => {
                warn!("Snapshot sync failed from {} — falling back to block-by-block", peer_id(peer_url));
            }
        }
    }

    // ── Step 8: Fork resolution via headers-first ancestor search ──
    let sync_from_height = if is_fork {
        let _reorg_guard = state.reorg_lock.write().await;

        // Check fast_sync_base BEFORE searching, to detect fallback ancestors
        let fast_sync_base = {
            let chain = state.blockchain.read()
                .map_err(|e| SyncError::LockPoisoned(format!("read lock: {}", e)))?;
            chain.fast_sync_base_height()
        };

        match find_common_ancestor_headers(&state, &client, peer_url, local_height, peer_info.height).await {
            Ok(ancestor) => {
                // BUG FIX: If ancestor == fast_sync_base, this is a FALLBACK, not a real
                // common ancestor. Rolling back to fast_sync_base and re-downloading from
                // a peer on a different fork creates a thrashing loop:
                //   rollback → download fails → remine → peer announces → rollback → ...
                // Instead, add a sync cooldown for this peer and skip.
                if fast_sync_base > 0 && ancestor <= fast_sync_base {
                    // PATCH A: ancestor at or below fast_sync_base is ALWAYS a fallback,
                    // never a real common ancestor. Rolling back to it is destructive
                    // (thrashing loop). Skip this peer entirely — no ban, no rollback.
                    // PATCH B: No ban/cooldown. With 10+ peers, banning each one for 120s
                    // causes total isolation (all peers banned → miner forks alone).
                    warn!(
                        "SYNC_DEBUG: ANCESTOR_IS_FALLBACK ancestor={} <= fast_sync_base={}, local_h={}, peer_h={} — skipping peer {} (no rollback, no ban)",
                        ancestor, fast_sync_base, local_height, peer_info.height, peer_id(peer_url)
                    );
                    return Ok(0);
                }

                warn!("SYNC_DEBUG: ANCESTOR_FOUND height={} peer={}", ancestor, peer_id(peer_url));
                info!("Common ancestor found at height {} via headers", ancestor);

                // Cancel mining during reorg (this is a REAL rollback — cancel is justified)
                state.last_reorg_height.store(ancestor, std::sync::atomic::Ordering::Relaxed);
                state.reorg_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                    warn!("MINING_CANCEL=true reason=step8_rollback ancestor={} peer={}", ancestor, peer_id(peer_url));
                    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                }

                // Rollback to ancestor
                let mut chain = state.blockchain.write()
                    .map_err(|e| SyncError::LockPoisoned(format!("write lock: {}", e)))?;
                if let Err(e) = chain.rollback_to_height(ancestor) {
                    warn!("Rollback to height {} failed: {}", ancestor, e);
                    return Err(SyncError::HttpError(format!("Rollback failed: {}", e)));
                }
                info!("Rolled back to common ancestor at height {}", ancestor);

                // CRITICAL FIX: After rollback, process orphan pool.
                // Peer blocks received via P2P relay are stored as orphans.
                // After rollback, they may now chain onto our new tip.
                // Without this, sync would re-download them via HTTP, find them
                // as "duplicates" (already in orphan pool), and fail to add them.
                if let Err(e) = chain.process_orphans() {
                    warn!("process_orphans after rollback failed: {}", e);
                }
                let post_orphan_height = chain.height();
                if post_orphan_height > ancestor {
                    info!(
                        "Orphan processing after rollback: {} → {} ({} blocks recovered)",
                        ancestor, post_orphan_height, post_orphan_height - ancestor
                    );
                }
                warn!(
                    "SYNC_DEBUG: POST_ROLLBACK sync_from={} ancestor={} post_orphan={}",
                    post_orphan_height, ancestor, post_orphan_height
                );
                // Use post-orphan height as sync start point.
                // Without this, we re-download blocks already added by process_orphans
                // → "none accepted" → ban peer → network deadlock.
                post_orphan_height
            }
            Err(_) => {
                // No ancestor found — check peer checkpoints before drastic action
                if verify_peer_checkpoints(&client, peer_url).await {
                    // PATCH D: Suppress reset during post-fast-sync warm-up window.
                    // Null-hash placeholders cause false "no ancestor" → reset is an artefact.
                    let delta = local_height.saturating_sub(fast_sync_base);
                    if fast_sync_base > 0 && delta < LWMA_WINDOW * 3 {
                        warn!(
                            "SNAPSHOT_RESYNC_SUPPRESSED_POST_FASTSYNC path=step8_err fast_sync_base={} local_height={} delta={} peer={} reason=null_hash_placeholders_in_warmup",
                            fast_sync_base, local_height, delta, peer_id(peer_url)
                        );
                        return Ok(0);
                    }
                    info!("Peer {} passes checkpoints — snapshot resync", peer_id(peer_url));
                    if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                        cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    let mut chain = state.blockchain.write()
                        .map_err(|e| SyncError::LockPoisoned(format!("write lock: {}", e)))?;
                    chain.reset_for_snapshot_resync();
                    return Ok(0);
                } else {
                    // FIX: Reduced from 1800s ban to 120s cooldown.
                    // On a private network, checkpoint failure can happen due to
                    // fast-sync placeholders, not malicious peers.
                    warn!("No ancestor + checkpoint fail — cooldown 120s for peer {} (not banning)", peer_id(peer_url));
                    ban_peer(&state, peer_url, 120);
                    return Ok(0);
                }
            }
        }
    } else {
        local_height
    };

    // ── Step 9: Block download (only for validated height range) ──
    let mut synced = 0u64;
    let mut current_sync_height = sync_from_height;
    let mut consecutive_empty_batches = 0u32;
    let mut recovery_attempted = false; // Prevent infinite recovery loops

    loop {
        let blocks_url = format!("{}/blocks/since/{}", peer_url, current_sync_height);
        let response = client.get(&blocks_url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(SyncError::HttpError(format!("HTTP {}: {}", status, body)));
        }

        let blocks: Vec<ShieldedBlock> = response.json().await?;
        let batch_size = blocks.len();

        if batch_size == 0 {
            break;
        }

        let mut batch_added = 0u64;

        warn!(
            "SYNC_DEBUG: SYNC_BATCH_START from_height={} batch_size={} peer={}",
            current_sync_height, batch_size, peer_id(peer_url)
        );

        for (idx, block) in blocks.into_iter().enumerate() {
            let block_hash_hex = hex::encode(&block.hash()[..8]);
            let block_h = block.coinbase.height;
            let mut chain = state.blockchain.write()
                .map_err(|e| SyncError::LockPoisoned(format!("write lock: {}", e)))?;
            debug!(
                "SYNC_DEBUG: BLOCK_ATTEMPT idx={}/{} block={} height={} prev={}",
                idx + 1, batch_size, block_hash_hex, block_h,
                hex::encode(&block.header.prev_hash[..8])
            );
            match chain.try_add_block(block) {
                Ok(true) => {
                    batch_added += 1;
                    synced += 1;
                    current_sync_height = chain.height();
                    debug!(
                        "SYNC_DEBUG: BLOCK_RESULT idx={}/{} result=ACCEPTED new_height={}",
                        idx + 1, batch_size, current_sync_height
                    );
                }
                Ok(false) => {
                    debug!(
                        "SYNC_DEBUG: BLOCK_RESULT idx={}/{} result=REJECTED(Ok(false))",
                        idx + 1, batch_size
                    );
                }
                Err(e) => {
                    warn!("Failed to add block during sync: {}", e);
                    break;
                }
            }
        }

        warn!(
            "SYNC_DEBUG: SYNC_BATCH_END added={}/{} synced_total={}",
            batch_added, batch_size, synced
        );

        if synced > 0 && synced % 50 == 0 {
            info!("Synced {} blocks from {} (height: {})", synced, peer_id(peer_url), current_sync_height);
        }

        // ── CRITICAL FIX: blocks don't chain → headers-based recovery ──
        // This is the core fix that prevents infinite sync loops.
        // If we got blocks but NONE were added, the chains have diverged.
        // Use headers to find the real ancestor instead of looping forever.
        if batch_size > 0 && batch_added == 0 {
            consecutive_empty_batches += 1;
            warn!(
                "Got {} blocks from {} but none accepted (attempt {}/3) — chains diverged",
                batch_size, peer_id(peer_url), consecutive_empty_batches
            );

            if consecutive_empty_batches >= 3 {
                // Three strikes — this peer's chain is incompatible with ours
                if recovery_attempted {
                    // BUG FIX: Don't ban the peer — the fork may be legitimate.
                    // Previously, this ban was applied to ALL peers because
                    // recovery_attempted was a single bool per sync session.
                    // Under load (10+ miners), this caused a cascade that banned
                    // every peer within seconds, killing the entire network.
                    // Instead, just stop syncing with this peer for now.
                    warn!("Recovery already attempted with {} — stopping sync (no ban)", peer_id(peer_url));
                    break;
                }
                recovery_attempted = true;
                warn!("3 consecutive empty batches from {} — attempting header-based recovery", peer_id(peer_url));

                // Acquire reorg_lock BEFORE searching for ancestor to prevent race conditions
                let _recovery_reorg_guard = state.reorg_lock.write().await;
                if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                    warn!("MINING_CANCEL=true reason=recovery_rollback peer={}", peer_id(peer_url));
                    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                }

                match find_common_ancestor_headers(&state, &client, peer_url, current_sync_height, peer_info.height).await {
                    Ok(ancestor) => {
                        info!("Header recovery found ancestor at {} — rolling back", ancestor);
                        state.last_reorg_height.store(ancestor, std::sync::atomic::Ordering::Relaxed);
                        state.reorg_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                        let mut chain = state.blockchain.write()
                            .map_err(|e| SyncError::LockPoisoned(format!("write lock: {}", e)))?;
                        if let Err(e) = chain.rollback_to_height(ancestor) {
                            warn!("Header recovery rollback failed: {}", e);
                            break;
                        }
                        // Process orphans after rollback — same fix as Step 8
                        if let Err(e) = chain.process_orphans() {
                            warn!("process_orphans after recovery rollback failed: {}", e);
                        }
                        let recovered_height = chain.height();
                        if recovered_height > ancestor {
                            info!(
                                "Recovery orphan processing: {} → {} ({} blocks)",
                                ancestor, recovered_height, recovered_height - ancestor
                            );
                        }
                        current_sync_height = chain.height();
                        consecutive_empty_batches = 0;
                        continue; // Retry from correct ancestor
                    }
                    Err(_) => {
                        // Last resort: snapshot resync if peer passes checkpoints
                        if verify_peer_checkpoints(&client, peer_url).await {
                            // PATCH D: Suppress reset during post-fast-sync warm-up window.
                            let recovery_fsb = {
                                let c = state.blockchain.read()
                                    .map_err(|e| SyncError::LockPoisoned(format!("read lock: {}", e)))?;
                                (c.fast_sync_base_height(), c.height())
                            };
                            let (fsb, cur_h) = recovery_fsb;
                            let delta = cur_h.saturating_sub(fsb);
                            if fsb > 0 && delta < LWMA_WINDOW * 3 {
                                warn!(
                                    "SNAPSHOT_RESYNC_SUPPRESSED_POST_FASTSYNC path=recovery_err fast_sync_base={} local_height={} delta={} peer={} reason=null_hash_placeholders_in_warmup",
                                    fsb, cur_h, delta, peer_id(peer_url)
                                );
                                break;
                            }
                            if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                                cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                            let mut chain = state.blockchain.write()
                                .map_err(|e| SyncError::LockPoisoned(format!("write lock: {}", e)))?;
                            chain.reset_for_snapshot_resync();
                            return Ok(0);
                        } else {
                            // FIX: Reduced from 1800s ban to 120s cooldown
                            warn!("Recovery checkpoint fail — cooldown 120s for peer {} (not banning)", peer_id(peer_url));
                            ban_peer(&state, peer_url, 120);
                        }
                        break;
                    }
                }
            }
            // Don't break on first empty batch — might be a temporary issue
            continue;
        } else {
            consecutive_empty_batches = 0;
        }

        if batch_size < 50 {
            break;
        }
    }

    // ── Step 10: Post-sync checkpoint validation ──
    if synced > 0 {
        // Check checkpoints with read lock, collect violation info, then drop lock
        let checkpoint_violation = {
            let chain = state.blockchain.read()
                .map_err(|e| SyncError::LockPoisoned(format!("read lock: {}", e)))?;
            let mut violation = None;
            for &(cp_height, cp_hash) in crate::config::HARDCODED_CHECKPOINTS {
                if cp_height <= chain.height() {
                    if let Some(actual_hash) = chain.get_hash_at_height(cp_height) {
                        let actual_hex = hex::encode(actual_hash);
                        if actual_hex != "0".repeat(64) && actual_hex != cp_hash {
                            warn!(
                                "BANNING {} — synced chain violates checkpoint at height {} (expected {}, got {})",
                                peer_id(peer_url), cp_height, &cp_hash[..16], &actual_hex[..16]
                            );
                            violation = Some(cp_height);
                            break;
                        }
                    }
                }
            }

            if violation.is_none() {
                if is_fork {
                    info!("Fork resolved: synced {} blocks from {} (new height: {})", synced, peer_id(peer_url), chain.height());
                } else {
                    info!("Synced {} blocks from {}", synced, peer_id(peer_url));
                }
            }
            violation
        }; // chain read lock dropped here

        if let Some(cp_height) = checkpoint_violation {
            ban_peer(&state, peer_url, 3600);
            let rollback_to = cp_height.saturating_sub(1);
            let _reorg_guard = state.reorg_lock.write().await;
            if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
                cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            let mut chain_w = state.blockchain.write()
                .map_err(|e| SyncError::LockPoisoned(format!("write lock: {}", e)))?;
            let _ = chain_w.rollback_to_height(rollback_to);
            return Err(SyncError::InvalidResponse(
                format!("Peer chain violates checkpoint at height {}", cp_height)
            ));
        }

        // FIX 7: Do NOT cancel mining here at end of sync.
        // The cancel during actual rollback (Step 8, lines ~260/419) is sufficient.
        // This preemptive cancel was firing on every P2P-triggered sync that detected
        // a fork — even when no rollback occurred. With blocks arriving every ~8s from
        // forked peers, mining was cancelled faster than it could find a block,
        // permanently stalling the miner.
        if is_fork {
            warn!(
                "SYNC_DEBUG: sync_complete is_fork=true synced={} — NOT cancelling mining (cancel only during rollback)",
                synced
            );
        }
    }
    Ok(synced)
}

// ============ Headers-First Fork Detection ============

/// Result of headers-first fork detection.
#[derive(Debug)]
enum ForkDetection {
    /// Peer extends our chain — no fork.
    NoFork,
    /// Fork detected — ancestor_height is where chains diverged.
    ForkDetected { ancestor_height: u64 },
    /// Chains are completely incompatible (no common ancestor in range).
    Incompatible,
}

/// Detect fork by fetching compact headers from the peer and comparing with local chain.
/// Much faster than fetching full blocks — each header is ~200 bytes.
async fn detect_fork_via_headers(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    peer_url: &str,
    local_height: u64,
) -> ForkDetection {
    // Fetch peer's headers around our local height to check chain compatibility
    // Use a wide window (50 blocks back, 100 headers) to catch deep forks.
    // Previously saturating_sub(5) + limit=10 missed any fork deeper than 5 blocks.
    let start = local_height.saturating_sub(50);
    let headers_url = format!("{}/headers/since/{}?limit=100", peer_url, start);

    let resp = match client.get(&headers_url).timeout(Duration::from_secs(5)).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => {
            // Peer doesn't support /headers/since — fall back to old single-block check
            return detect_fork_legacy(state, client, peer_url, local_height).await;
        }
    };

    let peer_headers: Vec<CompactHeaderResponse> = match resp.json().await {
        Ok(h) => h,
        Err(_) => return detect_fork_legacy(state, client, peer_url, local_height).await,
    };

    if peer_headers.is_empty() {
        return ForkDetection::NoFork;
    }

    let chain = match state.blockchain.read() {
        Ok(c) => c,
        Err(_) => return ForkDetection::NoFork,
    };

    // Check each header — find the HIGHEST height where hashes match (ancestor)
    // and the LOWEST height where they mismatch (divergence point).
    // Use max/min to handle unsorted headers correctly.
    let mut best_match: Option<u64> = None;
    let mut earliest_mismatch: Option<u64> = None;

    for header in &peer_headers {
        if header.height > local_height { continue; }
        if let Some(local_hash) = chain.get_hash_at_height(header.height) {
            let local_hex = hex::encode(local_hash);
            if local_hex == "0".repeat(64) { continue; } // placeholder
            if header.hash == local_hex {
                best_match = Some(best_match.map_or(header.height, |prev: u64| prev.max(header.height)));
            } else {
                earliest_mismatch = Some(earliest_mismatch.map_or(header.height, |prev: u64| prev.min(header.height)));
            }
        }
    }

    let result = match (best_match, earliest_mismatch) {
        (Some(ancestor), Some(_)) => ForkDetection::ForkDetected { ancestor_height: ancestor },
        (None, Some(mismatch)) => {
            // BUG FIX: After fast-sync, we have no real block hashes below fast_sync_base.
            // The window may contain ONLY divergent blocks if the fork started right after
            // fast-sync. Instead of declaring Incompatible (which triggers ban cascades),
            // treat this as a fork with ancestor = fast_sync_base or start of window.
            // Step 8 (find_common_ancestor_headers) will do the precise search.
            let fast_sync_base = {
                let chain = match state.blockchain.read() {
                    Ok(c) => c,
                    Err(_) => return ForkDetection::Incompatible,
                };
                chain.fast_sync_base_height()
            };
            if fast_sync_base > 0 && start <= fast_sync_base {
                // We're in the fast-sync blind zone — can't conclude incompatible.
                // Use earliest mismatch as a hint, ancestor is at or below it.
                let estimated_ancestor = mismatch.saturating_sub(1).max(fast_sync_base);
                warn!(
                    "SYNC_DEBUG: fast-sync blind zone — promoting Incompatible to ForkDetected(ancestor={}), fast_sync_base={}, mismatch={}",
                    estimated_ancestor, fast_sync_base, mismatch
                );
                ForkDetection::ForkDetected { ancestor_height: estimated_ancestor }
            } else {
                ForkDetection::Incompatible
            }
        }
        _ => ForkDetection::NoFork, // All headers match — no fork
    };
    warn!(
        "SYNC_DEBUG: detect_fork_via_headers peer={} start={} got={} headers best_match={:?} earliest_mismatch={:?} result={:?}",
        peer_id(peer_url), start, peer_headers.len(), best_match, earliest_mismatch, result
    );
    result
}

/// Legacy fork detection: check single block at local height (for peers without /headers/since).
async fn detect_fork_legacy(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    peer_url: &str,
    local_height: u64,
) -> ForkDetection {
    let local_hash = {
        let chain = match state.blockchain.read() {
            Ok(c) => c,
            Err(_) => return ForkDetection::NoFork,
        };
        hex::encode(chain.latest_hash())
    };

    let check_url = format!("{}/block/height/{}", peer_url, local_height);
    if let Ok(resp) = client.get(&check_url).timeout(Duration::from_secs(5)).send().await {
        if resp.status().is_success() {
            if let Ok(peer_block) = resp.json::<PeerBlockInfo>().await {
                if peer_block.hash != local_hash {
                    return ForkDetection::ForkDetected { ancestor_height: local_height.saturating_sub(1) };
                }
            }
        }
    }
    ForkDetection::NoFork
}

// ============ Headers-First Common Ancestor Search ============

/// Find common ancestor using compact headers (new protocol).
/// Falls back to legacy block-by-block method for old peers.
async fn find_common_ancestor_headers(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    peer_url: &str,
    local_height: u64,
    _peer_height: u64,
) -> Result<u64, SyncError> {
    let search_start = local_height.saturating_sub(crate::config::MAX_REORG_DEPTH);

    // Try headers-first protocol
    let headers_url = format!("{}/headers/since/{}?limit=500", peer_url, search_start);
    let resp = client.get(&headers_url).timeout(Duration::from_secs(10)).send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let peer_headers: Vec<CompactHeaderResponse> = r.json().await
                .map_err(|e| SyncError::InvalidResponse(format!("headers parse: {}", e)))?;

            if peer_headers.is_empty() {
                return Err(SyncError::InvalidResponse("Peer returned 0 headers".into()));
            }

            let chain = state.blockchain.read()
                .map_err(|e| SyncError::LockPoisoned(format!("read lock: {}", e)))?;

            let fast_sync_base = chain.fast_sync_base_height();

            // Walk backwards through peer headers to find matching hash
            for header in peer_headers.iter().rev() {
                if header.height > local_height { continue; }
                // BUG FIX: Don't skip headers below fast_sync_base unconditionally.
                // After fast-sync, blocks below fast_sync_base have no stored data,
                // but get_hash_at_height may still return the snapshot's genesis hash.
                // The "0".repeat(64) check below already filters null hashes safely.
                // Skipping entirely prevented finding ANY ancestor when the fork
                // started right above fast_sync_base (e.g. fast_sync=244, fork=246).

                if let Some(local_hash) = chain.get_hash_at_height(header.height) {
                    let local_hex = hex::encode(local_hash);
                    if local_hex != "0".repeat(64) && header.hash == local_hex {
                        info!("Found common ancestor at height {} via headers-first", header.height);
                        return Ok(header.height);
                    }
                }
            }

            // No match in headers range — if we're in fast-sync zone, return the base
            // as a safe fallback instead of failing entirely
            if fast_sync_base > 0 && fast_sync_base >= search_start {
                warn!(
                    "No common ancestor in {} headers from {} — falling back to fast_sync_base={} as safe ancestor",
                    peer_headers.len(), peer_id(peer_url), fast_sync_base
                );
                return Ok(fast_sync_base);
            }

            warn!("No common ancestor in {} headers from {}", peer_headers.len(), peer_id(peer_url));
            Err(SyncError::InvalidResponse("No common ancestor in header range".into()))
        }
        _ => {
            // Peer doesn't support /headers/since — fall back to legacy
            info!("Peer {} doesn't support headers protocol — using legacy ancestor search", peer_id(peer_url));
            find_common_ancestor_legacy(state, client, peer_url, local_height).await
        }
    }
}

/// Legacy common ancestor search: fetch one full block per height (slow, for old peers).
async fn find_common_ancestor_legacy(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    peer_url: &str,
    start_height: u64,
) -> Result<u64, SyncError> {
    let check_depth = 100u64.min(start_height);
    let fast_sync_base = {
        let chain = state.blockchain.read()
            .map_err(|e| SyncError::LockPoisoned(format!("read lock: {}", e)))?;
        chain.fast_sync_base_height()
    };

    for offset in 0..check_depth {
        let height = start_height - offset;
        // BUG FIX: Same as headers-first — don't skip below fast_sync_base.
        // The null-hash checks below already handle missing block data safely.

        let local_hash = {
            let chain = state.blockchain.read()
                .map_err(|e| SyncError::LockPoisoned(format!("read lock: {}", e)))?;
            match chain.get_block_by_height(height) {
                Some(b) => {
                    let h = hex::encode(b.hash());
                    if h == "0".repeat(64) { None } else { Some(h) }
                }
                None => {
                    chain.get_hash_at_height(height).and_then(|h| {
                        let hex_str = hex::encode(h);
                        if hex_str == "0".repeat(64) { None } else { Some(hex_str) }
                    })
                }
            }
        };

        if let Some(local_hash) = local_hash {
            let block_url = format!("{}/block/height/{}", peer_url, height);
            if let Ok(resp) = client.get(&block_url).send().await {
                if resp.status().is_success() {
                    if let Ok(peer_block) = resp.json::<PeerBlockInfo>().await {
                        if peer_block.hash == local_hash {
                            info!("Found common ancestor at height {} (legacy)", height);
                            return Ok(height);
                        }
                    }
                }
            }
        }
    }

    // No ancestor — check if peer has valid checkpoints before giving up
    warn!("No common ancestor in last {} blocks with peer {}", check_depth, peer_id(peer_url));

    let peer_valid = verify_peer_checkpoints(client, peer_url).await;
    if peer_valid {
        // PATCH D: Suppress reset during post-fast-sync warm-up window.
        let (fsb, cur_h) = {
            let c = state.blockchain.read()
                .map_err(|e| SyncError::LockPoisoned(format!("read lock: {}", e)))?;
            (c.fast_sync_base_height(), c.height())
        };
        let delta = cur_h.saturating_sub(fsb);
        if fsb > 0 && delta < LWMA_WINDOW * 3 {
            warn!(
                "SNAPSHOT_RESYNC_SUPPRESSED_POST_FASTSYNC path=legacy_ancestor fast_sync_base={} local_height={} delta={} peer={} reason=null_hash_placeholders_in_warmup",
                fsb, cur_h, delta, peer_id(peer_url)
            );
            return Ok(fsb);
        }
        info!("Peer {} passes checkpoints — triggering snapshot resync", peer_id(peer_url));
        // Cancel mining before chain reset
        if let Some(cancel) = state.mining_cancel.read().unwrap().as_ref() {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let mut chain = state.blockchain.write()
            .map_err(|e| SyncError::LockPoisoned(format!("write lock: {}", e)))?;
        chain.reset_for_snapshot_resync();
        return Ok(0);
    }

    Err(SyncError::InvalidResponse(format!(
        "No common ancestor found in last {} blocks — incompatible chain", check_depth
    )))
}

// ============ Snapshot Sync ============

/// Attempt to download and import a state snapshot from a peer.
async fn attempt_snapshot_sync(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    peer_url: &str,
) -> Result<u64, SyncError> {
    let info_url = format!("{}/snapshot/info", peer_url);
    let resp = client.get(&info_url).timeout(Duration::from_secs(10)).send().await
        .map_err(|e| SyncError::HttpError(format!("snapshot info: {}", e)))?;

    let info: serde_json::Value = resp.json().await
        .map_err(|e| SyncError::InvalidResponse(format!("snapshot info parse: {}", e)))?;

    if info["available"].as_bool() != Some(true) {
        return Err(SyncError::InvalidResponse("Snapshot not available".into()));
    }

    let snap_height = info["height"].as_u64().unwrap_or(0);
    if snap_height == 0 {
        return Err(SyncError::InvalidResponse("Snapshot height is 0".into()));
    }

    let snap_hash_str = info["block_hash"].as_str().unwrap_or("");

    // v1.7.0: Read exact cumulative_work from snapshot info (decimal string).
    // If absent (old peer), refuse snapshot for non-seed peers.
    let snap_work_str = info["cumulative_work"].as_str().unwrap_or("0");
    let snap_work: u128 = snap_work_str.parse().unwrap_or(0);

    if snap_work == 0 {
        let is_seed = crate::config::SEED_NODES.iter().any(|s| peer_url.starts_with(s));
        if is_seed {
            warn!(
                "Snapshot from seed {} has no cumulative_work — accepting in degraded mode (private network)",
                peer_id(peer_url)
            );
        } else {
            warn!(
                "Rejecting snapshot from {} — no cumulative_work provided (require v1.7.0+)",
                peer_id(peer_url)
            );
            return Err(SyncError::InvalidResponse(
                "Snapshot missing cumulative_work — peer must be v1.7.0+".into()
            ));
        }
    }

    let dl_url = format!("{}/snapshot/download", peer_url);
    let resp = client.get(&dl_url).timeout(Duration::from_secs(30)).send().await
        .map_err(|e| SyncError::HttpError(format!("snapshot download: {}", e)))?;

    let compressed = resp.bytes().await
        .map_err(|e| SyncError::HttpError(format!("snapshot bytes: {}", e)))?;

    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut json_data = Vec::new();
    decoder.read_to_end(&mut json_data)
        .map_err(|e| SyncError::InvalidResponse(format!("snapshot decompress: {}", e)))?;

    let snapshot: crate::core::StateSnapshotPQ = serde_json::from_slice(&json_data)
        .map_err(|e| SyncError::InvalidResponse(format!("snapshot parse: {}", e)))?;

    let mut block_hash = [0u8; 32];
    if let Ok(bytes) = hex::decode(snap_hash_str) {
        if bytes.len() == 32 { block_hash.copy_from_slice(&bytes); }
    }

    // Get peer's difficulty info (for LWMA post-snapshot)
    let ci_url = format!("{}/chain/info", peer_url);
    let (diff, next_diff) = if let Ok(r) = client.get(&ci_url).send().await {
        let i = r.json::<serde_json::Value>().await.ok();
        let d = i.as_ref().and_then(|v| v["difficulty"].as_u64()).unwrap_or(1000);
        let nd = i.as_ref().and_then(|v| v["next_difficulty"].as_u64()).unwrap_or(d);
        (d, nd)
    } else {
        (1000, 1000)
    };

    let mut chain = state.blockchain.write()
        .map_err(|e| SyncError::LockPoisoned(format!("write lock: {}", e)))?;
    chain.import_snapshot_at_height(snapshot, snap_height, block_hash, diff, next_diff, snap_work);

    Ok(snap_height)
}

// ============ Checkpoint Verification ============

/// Verify that a peer's chain matches our hardcoded checkpoints.
/// When no checkpoints exist, returns true only for seed nodes (trusted bootstrap).
async fn verify_peer_checkpoints(client: &reqwest::Client, peer_url: &str) -> bool {
    if crate::config::HARDCODED_CHECKPOINTS.is_empty() {
        // No checkpoints — only trust seed nodes for bootstrap
        let is_seed = crate::config::SEED_NODES.iter().any(|s| peer_url.starts_with(s));
        if !is_seed {
            debug!("No checkpoints + non-seed peer {} — untrusted", peer_id(peer_url));
        }
        return is_seed;
    }
    for &(cp_height, cp_hash) in crate::config::HARDCODED_CHECKPOINTS {
        let url = format!("{}/block/height/{}", peer_url, cp_height);
        match client.get(&url).timeout(Duration::from_secs(5)).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(block) = resp.json::<PeerBlockInfo>().await {
                    if block.hash != cp_hash {
                        warn!(
                            "Peer {} FAILS checkpoint at height {}: expected {}, got {}",
                            peer_id(peer_url), cp_height, &cp_hash[..16], &block.hash[..16]
                        );
                        return false;
                    }
                }
            }
            _ => continue, // Peer doesn't have this block — skip
        }
    }
    true
}

// ============ Block Broadcast ============

/// Broadcast a newly mined block to all peers (concurrent, with timeout).
pub async fn broadcast_block(block: &ShieldedBlock, peers: &[String], client: &reqwest::Client) -> Vec<Result<(), SyncError>> {
    let mut handles = Vec::new();
    for peer in peers {
        if !super::is_contactable_peer(peer) { continue; }
        let url = format!("{}/blocks", peer);
        let client = client.clone();
        let block = block.clone();
        let peer_label = peer_id(peer);
        handles.push(tokio::spawn(async move {
            let result = client
                .post(&url)
                .header("X-TSN-Version", env!("CARGO_PKG_VERSION"))
                .timeout(std::time::Duration::from_secs(3))
                .json(&block)
                .send()
                .await
                .map(|_| ())
                .map_err(SyncError::from);

            if let Err(ref e) = result {
                debug!("Failed to broadcast to {}: {}", peer_label, sanitize_error(e));
            }
            result
        }));
    }
    let mut results = Vec::new();
    for h in handles {
        match h.await {
            Ok(r) => results.push(r),
            Err(_) => results.push(Err(SyncError::HttpError("broadcast task join error".to_string()))),
        }
    }
    results
}

// ============ Sync Loop ============

/// Consecutive failure counter (reduces log spam).
static SYNC_FAIL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Background task that periodically syncs with peers.
pub async fn sync_loop(state: Arc<AppState>, seed_peers: Vec<String>, sync_interval_secs: u64) {
    if seed_peers.is_empty() {
        return;
    }

    let mut interval = interval(Duration::from_secs(sync_interval_secs));
    let mut peer_failures: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

    loop {
        interval.tick().await;

        // Cleanup expired bans
        {
            let now = std::time::Instant::now();
            let mut bans = state.banned_peers.write().unwrap();
            bans.retain(|url, until| {
                if now >= *until {
                    info!("Ban expired for peer {}", peer_id(url));
                    false
                } else {
                    true
                }
            });
        }

        let peers = state.peers.read().unwrap().clone();

        for peer in &peers {
            // Skip hashed peer IDs (not contactable URLs)
            if !super::is_contactable_peer(peer) {
                continue;
            }
            // v1.8.0: Skip peers with too many consecutive failures (temporary cooldown).
            // After 20 failures, skip this peer for this cycle. Counter resets on success.
            // This prevents the sync loop from wasting time on dead peers while
            // other live peers with forked chains go undetected.
            let fail_count = peer_failures.get(peer).copied().unwrap_or(0);
            if fail_count >= 20 {
                // Only attempt dead peers every 10th cycle to detect recovery
                let cycle = SYNC_FAIL_COUNT.load(Ordering::Relaxed);
                if cycle % 10 != 0 {
                    continue;
                }
            }

            loop {
                match sync_from_peer(state.clone(), peer).await {
                    Ok(n) if n > 0 => {
                        SYNC_FAIL_COUNT.store(0, Ordering::Relaxed);
                        peer_failures.remove(peer);
                        info!("Synced {} blocks from {}", n, peer_id(peer));
                        continue; // Peer may have more
                    }
                    Ok(_) => {
                        peer_failures.remove(peer);
                        break;
                    }
                    Err(e) => {
                        let count = SYNC_FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                        let peer_count = peer_failures.entry(peer.clone()).or_insert(0);
                        *peer_count += 1;

                        if *peer_count == 1 {
                            warn!("Sync from {} failed: {}", peer_id(peer), sanitize_error(&e));
                        } else if *peer_count % 10 == 0 {
                            warn!("Sync from {} failed ({} consecutive): {}", peer_id(peer), *peer_count, sanitize_error(&e));
                        }

                        // Ghost peer cleanup
                        if *peer_count >= 10 && !seed_peers.contains(peer) {
                            info!("Removing ghost peer {} after {} failures", peer_id(peer), peer_count);
                            let mut peers_write = state.peers.write().unwrap();
                            peers_write.retain(|p| p != peer);
                            peer_failures.remove(peer);
                        }
                        break;
                    }
                }
            }
        }
    }
}

// ============ Types ============

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct PeerChainInfo {
    height: u64,
    latest_hash: String,
    difficulty: u64,
    commitment_count: u64,
    #[serde(default)]
    genesis_hash: String,
    #[serde(default)]
    cumulative_work: u128,
    #[serde(default)]
    finalized_height: u64,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct PeerBlockInfo {
    hash: String,
    height: u64,
    prev_hash: String,
}

/// Compact header response from /headers/since endpoint.
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct CompactHeaderResponse {
    height: u64,
    hash: String,
    prev_hash: String,
    difficulty: u64,
    timestamp: u64,
    cumulative_work: u128,
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("HTTP error: {0}")]
    HttpError(String),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),
}

/// v1.4.0: Verify a peer's claimed cumulative_work by sampling blocks.
pub async fn verify_peer_work_sample(
    client: &reqwest::Client,
    peer_url: &str,
    peer_height: u64,
    peer_claimed_work: u128,
) -> bool {
    const SAMPLE_COUNT: u64 = 5;
    if peer_height < SAMPLE_COUNT || peer_claimed_work == 0 {
        return true;
    }

    let mut sampled_work: u128 = 0;
    let mut sampled_count: u64 = 0;
    let step = peer_height / SAMPLE_COUNT;
    for i in 0..SAMPLE_COUNT {
        let h = (i + 1) * step;
        let url = format!("{}/block/height/{}", peer_url, h);
        if let Ok(resp) = client.get(&url).timeout(Duration::from_secs(5)).send().await {
            if let Ok(block_info) = resp.json::<serde_json::Value>().await {
                if let Some(diff) = block_info["difficulty"].as_u64() {
                    sampled_work += diff as u128;
                    sampled_count += 1;
                }
            }
        }
    }

    if sampled_count == 0 {
        warn!("verify_peer_work_sample: couldn't fetch any blocks from {}", peer_id(peer_url));
        return false;
    }

    let avg_difficulty = sampled_work / sampled_count as u128;
    let estimated_work = avg_difficulty * peer_height as u128;
    let ratio = if estimated_work > 0 {
        peer_claimed_work as f64 / estimated_work as f64
    } else {
        0.0
    };

    if ratio < 0.5 || ratio > 2.0 {
        warn!(
            "Peer {} claimed work {} but estimate is {} (ratio {:.2}) — suspicious",
            peer_id(peer_url), peer_claimed_work, estimated_work, ratio
        );
        return false;
    }

    debug!(
        "Peer {} work OK: claimed={}, estimated={}, ratio={:.2}",
        peer_id(peer_url), peer_claimed_work, estimated_work, ratio
    );
    true
}

/// Sync configuration
#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub max_concurrent_requests: usize,
    pub timeout: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 10,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Block sync manager
pub struct BlockSync {
    _config: SyncConfig,
}

impl BlockSync {
    pub fn new(config: SyncConfig) -> Self {
        Self { _config: config }
    }

    pub async fn sync(
        &self,
        _peer: &str,
        _from_height: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

/// Multi-peer snapshot verification
#[derive(Debug)]
pub struct SnapshotVerification {
    pub responding_peers: usize,
    pub agreeing_peers: usize,
    pub majority_hash: Option<String>,
}

pub async fn verify_snapshot_multi_peer(
    peer_urls: &[String],
    expected_state_root: &str,
) -> Result<SnapshotVerification, SyncError> {
    const MIN_PEERS: usize = 3;

    if peer_urls.len() < MIN_PEERS {
        return Err(SyncError::InvalidResponse(format!(
            "Need {} peers for verification, got {}",
            MIN_PEERS, peer_urls.len()
        )));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(SyncError::Request)?;

    let mut handles = Vec::new();
    for peer_url in peer_urls {
        let client = client.clone();
        let url = format!("{}/snapshot/info", peer_url);
        let peer = peer_url.clone();
        handles.push(tokio::spawn(async move {
            let result = client.get(&url).send().await;
            (peer, result)
        }));
    }

    let mut responses: Vec<(String, PeerSnapshotInfo)> = Vec::new();
    for handle in handles {
        if let Ok((peer, result)) = handle.await {
            match result {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<PeerSnapshotInfo>().await {
                        Ok(info) => responses.push((peer, info)),
                        Err(e) => warn!("Peer {} invalid response: {}", peer_id(&peer), sanitize_error(&e)),
                    }
                }
                Ok(resp) => warn!("Peer {} HTTP {}", peer_id(&peer), resp.status()),
                Err(e) => warn!("Peer {} unreachable: {}", peer_id(&peer), sanitize_error(&e)),
            }
        }
    }

    let responding_peers = responses.len();
    if responding_peers < MIN_PEERS {
        return Err(SyncError::InvalidResponse(format!(
            "Only {} peers responded, need {}", responding_peers, MIN_PEERS
        )));
    }

    let mut votes: std::collections::HashMap<(String, u64), Vec<String>> =
        std::collections::HashMap::new();
    for (peer, info) in &responses {
        votes.entry((info.block_hash.clone(), info.height)).or_default().push(peer.clone());
    }

    let (majority_key, majority_peers) = votes
        .iter()
        .max_by_key(|(_, peers)| peers.len())
        .map(|(k, p)| (k.clone(), p.clone()))
        .unwrap();

    let agreeing_peers = majority_peers.len();
    let majority_hash = majority_key.0.clone();
    let is_majority = agreeing_peers * 2 > responding_peers;

    for (peer, info) in &responses {
        if info.block_hash != majority_hash || info.height != majority_key.1 {
            warn!(
                "Peer {} disagrees: hash={}, height={} (majority: {}, {})",
                peer_id(peer), info.block_hash, info.height, majority_hash, majority_key.1
            );
        }
    }

    let _majority_root_matches = responses
        .iter()
        .any(|(_, info)| info.state_root == expected_state_root && info.block_hash == majority_hash);

    if !is_majority {
        return Err(SyncError::InvalidResponse(format!(
            "No majority: {}/{} agree", agreeing_peers, responding_peers
        )));
    }

    info!(
        "Snapshot verification OK: {}/{} agree (hash={}, height={})",
        agreeing_peers, responding_peers, majority_hash, majority_key.1
    );

    Ok(SnapshotVerification {
        responding_peers,
        agreeing_peers,
        majority_hash: Some(majority_hash),
    })
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct PeerSnapshotInfo {
    block_hash: String,
    height: u64,
    state_root: String,
}
