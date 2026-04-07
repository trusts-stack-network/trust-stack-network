use clap::{Parser, Subcommand, ValueEnum};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use tsn::config::{self, GENESIS_DIFFICULTY};
use tsn::consensus::{MiningPool, SimdMode};
use tsn::core::{ShieldedBlock, ShieldedBlockchain};
use tsn::network::{create_router, Mempool, peer_id};
use tsn::node::NodeRole;
use tsn::wallet::ShieldedWallet;

#[derive(Parser)]
#[command(name = "tsn", version)]
#[command(about = "TSN - Trust Stack Network: A privacy-preserving post-quantum cryptocurrency", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    // ---- Top-level flags (for default node mode) ----

    /// Number of mining threads (default: 1)
    #[arg(short, long, global = false)]
    threads: Option<usize>,

    /// Wallet file (default: auto-detect wallet.json next to binary)
    #[arg(short, long, global = false)]
    wallet: Option<String>,

    /// Port to listen on (default: 9333)
    #[arg(short, long, global = false)]
    port: Option<u16>,

    /// Additional peer nodes
    #[arg(long, global = false)]
    peer: Vec<String>,

    /// Data directory (default: ./data)
    #[arg(short, long, global = false)]
    data_dir: Option<String>,

    /// Public URL to announce to peers
    #[arg(long, global = false)]
    public_url: Option<String>,

    /// Disable connecting to seed nodes
    #[arg(long, global = false)]
    no_seeds: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SimdArg {
    Neon,
}

impl From<SimdArg> for SimdMode {
    fn from(value: SimdArg) -> Self {
        match value {
            SimdArg::Neon => SimdMode::Neon,
        }
    }
}

fn require_simd_support(simd: Option<SimdMode>) -> Option<SimdMode> {
    if let Some(mode) = simd {
        if !mode.is_supported() {
            eprintln!("SIMD mode {:?} requires ARMv8 NEON+SHA2 support.", mode);
            std::process::exit(1);
        }
    }
    simd
}

/// Expected SHA256 checksums for verification keys (for integrity verification)
const SPEND_VKEY_SHA256: &str = "a1ff15d0968e066b6d8285993580f57065d67fb7ce5625ed7966fd13a8952e27";
const OUTPUT_VKEY_SHA256: &str = "c97a5eb20c85009a2abd2f85b1bece88c054e913a24423e1973e0629537ff038";

/// Find verification keys, checking committed keys first, then build directory.
/// Also verifies checksums for committed keys to ensure integrity.
fn find_verification_keys() -> anyhow::Result<(String, String)> {
    use sha2::{Sha256, Digest};
    use std::path::{Path, PathBuf};

    // Build list of directories to search (CWD, next to binary, parent of binary)
    let mut search_dirs: Vec<PathBuf> = vec![PathBuf::from(".")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            search_dirs.push(parent.to_path_buf());
            // Also check parent of parent (for target/release/tsn → project root)
            if let Some(grandparent) = parent.parent() {
                search_dirs.push(grandparent.to_path_buf());
                if let Some(ggp) = grandparent.parent() {
                    search_dirs.push(ggp.to_path_buf());
                }
            }
        }
    }

    for base in &search_dirs {
        let committed_spend = base.join("circuits/keys/spend_vkey.json");
        let committed_output = base.join("circuits/keys/output_vkey.json");
        if committed_spend.exists() && committed_output.exists() {
            // Read and normalize line endings (strip \r) so checksums match
            // regardless of platform (Windows CRLF vs Unix LF)
            let spend_data: Vec<u8> = std::fs::read(&committed_spend)?
                .into_iter().filter(|&b| b != b'\r').collect();
            let output_data: Vec<u8> = std::fs::read(&committed_output)?
                .into_iter().filter(|&b| b != b'\r').collect();
            let spend_hash = hex::encode(Sha256::digest(&spend_data));
            let output_hash = hex::encode(Sha256::digest(&output_data));
            if spend_hash != SPEND_VKEY_SHA256 {
                return Err(anyhow::anyhow!(
                    "Spend verification key checksum mismatch!\n  Expected: {}\n  Got: {}",
                    SPEND_VKEY_SHA256, spend_hash
                ));
            }
            if output_hash != OUTPUT_VKEY_SHA256 {
                return Err(anyhow::anyhow!(
                    "Output verification key checksum mismatch!\n  Expected: {}\n  Got: {}",
                    OUTPUT_VKEY_SHA256, output_hash
                ));
            }
            println!("  Using committed verification keys (checksums verified)");
            return Ok((committed_spend.to_string_lossy().to_string(), committed_output.to_string_lossy().to_string()));
        }
    }

    for base in &search_dirs {
        let build_spend = base.join("circuits/build/spend_vkey.json");
        let build_output = base.join("circuits/build/output_vkey.json");
        if build_spend.exists() && build_output.exists() {
            println!("  Using local build verification keys (development mode)");
            return Ok((build_spend.to_string_lossy().to_string(), build_output.to_string_lossy().to_string()));
        }
    }

    // Legacy: check relative paths (backward compat)
    let committed_spend = "circuits/keys/spend_vkey.json";
    let committed_output = "circuits/keys/output_vkey.json";
    let build_spend = "circuits/build/spend_vkey.json";
    let build_output = "circuits/build/output_vkey.json";

    if Path::new(committed_spend).exists() && Path::new(committed_output).exists() {
        // Verify checksums for committed keys (normalize CRLF for cross-platform)
        let spend_data: Vec<u8> = std::fs::read(committed_spend)?
            .into_iter().filter(|&b| b != b'\r').collect();
        let output_data: Vec<u8> = std::fs::read(committed_output)?
            .into_iter().filter(|&b| b != b'\r').collect();

        let spend_hash = hex::encode(Sha256::digest(&spend_data));
        let output_hash = hex::encode(Sha256::digest(&output_data));

        if spend_hash != SPEND_VKEY_SHA256 {
            return Err(anyhow::anyhow!(
                "Spend verification key checksum mismatch!\n  Expected: {}\n  Got: {}\n  File may be corrupted or tampered with.",
                SPEND_VKEY_SHA256, spend_hash
            ));
        }
        if output_hash != OUTPUT_VKEY_SHA256 {
            return Err(anyhow::anyhow!(
                "Output verification key checksum mismatch!\n  Expected: {}\n  Got: {}\n  File may be corrupted or tampered with.",
                OUTPUT_VKEY_SHA256, output_hash
            ));
        }

        println!("  Using committed verification keys (checksums verified)");
        return Ok((committed_spend.to_string(), committed_output.to_string()));
    }

    // Fall back to build directory (local development)
    if Path::new(build_spend).exists() && Path::new(build_output).exists() {
        println!("  Using local build verification keys (development mode)");
        return Ok((build_spend.to_string(), build_output.to_string()));
    }

    Err(anyhow::anyhow!(
        "Verification keys not found.\n\
         For production: Ensure circuits/keys/ directory is present (from git).\n\
         For development: Run 'npm run compile:all && npm run setup:spend && npm run setup:output' in circuits/"
    ))
}

#[derive(Clone, Copy)]
enum MiningMode {
    Mine,
    Benchmark,
}

#[derive(serde::Deserialize)]
struct PeerChainInfo {
    height: u64,
    latest_hash: String,
}

async fn fetch_peer_chain_info(
    client: &reqwest::Client,
    peer_url: &str,
) -> Option<PeerChainInfo> {
    let info_url = format!("{}/chain/info", peer_url);
    let response = client.get(&info_url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<PeerChainInfo>().await.ok()
}

async fn wait_for_initial_sync(
    state: Arc<tsn::network::AppState>,
    max_wait_secs: u64,
) -> anyhow::Result<()> {
    use std::time::{Duration, Instant};
    use tokio::time::sleep;

    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(max_wait_secs);

    loop {
        let peers = { state.peers.read().unwrap().clone() };
        let (local_height, local_hash) = {
            let chain = state.blockchain.read().unwrap();
            (chain.height(), hex::encode(chain.latest_hash()))
        };

        // Allow solo mining when no peers are available (single-node deployment)
        if peers.is_empty() {
            println!("No peers configured. Starting solo mining at height {}...", local_height);
            return Ok(());
        }

        let mut best_peer: Option<(String, PeerChainInfo)> = None;
        for peer in &peers {
            if let Some(info) = fetch_peer_chain_info(&client, peer).await {
                let take = match &best_peer {
                    None => true,
                    Some((_, best_info)) => info.height > best_info.height,
                };
                if take {
                    best_peer = Some((peer.clone(), info));
                }
            }
        }

        if let Some((peer_url, info)) = best_peer {
            // Accept if we're within 5 blocks AND our tip hash matches the peer's chain
            let gap = if info.height > local_height { info.height - local_height } else { local_height - info.height };
            if gap <= 5 {
                // Verify we're on the same chain, not a fork
                let on_same_chain = if info.height == local_height {
                    info.latest_hash == local_hash
                } else {
                    // Check peer's block at our height
                    let check_url = format!("{}/block/height/{}", peer_url, local_height);
                    match client.get(&check_url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            match resp.json::<serde_json::Value>().await {
                                Ok(block) => block["hash"].as_str() == Some(&local_hash),
                                Err(_) => true, // assume OK if can't parse
                            }
                        }
                        _ => true, // assume OK if can't reach
                    }
                };
                if on_same_chain {
                    println!(
                        "Local chain synced with network at height {}.",
                        local_height
                    );
                    return Ok(());
                } else {
                    println!(
                        "Fork detected at height {}. Force re-sync from network (wiping local chain)...",
                        local_height
                    );
                    // v1.4.1: Do NOT wipe chain. Just attempt normal sync — the peer
                    // may have a heavier chain and sync_from_peer will handle fork resolution.
                    // Wiping was the cause of catastrophic chain loss.
                    let _ = tsn::network::sync_from_peer(state.clone(), &peer_url).await;
                }
            } else {
                println!(
                    "Waiting for sync... local height={}, peer height={} (gap: {})",
                    local_height, info.height, gap
                );
                let _ = tsn::network::sync_from_peer(state.clone(), &peer_url).await;
            }
        } else {
            println!("Waiting for sync... no peer info available yet.");
        }

        if Instant::now() >= deadline {
            // Don't fail — just start mining anyway if we have any blocks
            let height = state.blockchain.read().unwrap().height();
            if height > 0 {
                println!("Sync timeout but chain at height {}. Starting mining.", height);
                return Ok(());
            }
            return Err(anyhow::anyhow!(
                "Timed out waiting for sync; local tip does not match any peer."
            ));
        }

        sleep(Duration::from_secs(5)).await;
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive wallet menu
    Wallet {
        /// Wallet file (default: auto-detect)
        #[arg(short, long)]
        wallet: Option<String>,
        /// Node URL (default: auto-detect)
        #[arg(short, long)]
        node: Option<String>,
    },
    /// Generate a new shielded wallet
    NewWallet {
        /// Output file for the wallet (default: wallet.json)
        #[arg(short, long, default_value = "wallet.json")]
        output: String,
    },
    /// Show wallet balance (scans blockchain for owned notes)
    Balance {
        /// Wallet file (default: auto-detect)
        #[arg(short, long)]
        wallet: Option<String>,
        /// Node URL to query (default: auto-detect from port)
        #[arg(short, long)]
        node: Option<String>,
    },
    /// Run a miner node (shortcut for: node --role miner)
    Miner {
        /// Number of mining threads
        #[arg(short, long)]
        threads: Option<usize>,
        /// Port (default: auto-detect free port from 9333)
        #[arg(short, long)]
        port: Option<u16>,
        /// Wallet file (default: auto-detect or auto-create)
        #[arg(short, long)]
        wallet: Option<String>,
        /// Data directory (default: ./data-miner)
        #[arg(short, long)]
        data_dir: Option<String>,
        /// Additional peer nodes
        #[arg(long)]
        peer: Vec<String>,
        /// Public URL to announce to peers
        #[arg(long)]
        public_url: Option<String>,
        /// Disable connecting to seed nodes
        #[arg(long)]
        no_seeds: bool,
    },
    /// Run a relay node (shortcut for: node --role relay)
    Relay {
        /// Port (default: auto-detect free port from 9333)
        #[arg(short, long)]
        port: Option<u16>,
        /// Wallet file (for receiving relay rewards)
        #[arg(short, long)]
        wallet: Option<String>,
        /// Data directory (default: ./data-relay)
        #[arg(short, long)]
        data_dir: Option<String>,
        /// Additional peer nodes
        #[arg(long)]
        peer: Vec<String>,
        /// Public URL to announce to peers
        #[arg(long)]
        public_url: Option<String>,
        /// Disable connecting to seed nodes
        #[arg(long)]
        no_seeds: bool,
    },
    /// Run a light client node (shortcut for: node --role light)
    Light {
        /// Port (default: auto-detect free port from 9333)
        #[arg(short, long)]
        port: Option<u16>,
        /// Wallet file (for balance checking and sending transactions)
        #[arg(short, long)]
        wallet: Option<String>,
        /// Data directory (default: ./data-light)
        #[arg(short, long)]
        data_dir: Option<String>,
        /// Additional peer nodes
        #[arg(long)]
        peer: Vec<String>,
        /// Disable connecting to seed nodes
        #[arg(long)]
        no_seeds: bool,
    },
    /// Show transaction history from the explorer
    History {
        /// Node URL to query (default: auto-detect)
        #[arg(short, long)]
        node: Option<String>,
        /// Number of recent transactions to show (default: 20)
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },
    /// Send TSN to an address
    Send {
        /// Recipient address (pk_hash hex, 64 chars)
        #[arg(long)]
        to: String,
        /// Amount to send in TSN
        #[arg(long)]
        amount: f64,
        /// Transaction fee in TSN (default: 0.001)
        #[arg(long, default_value = "0.001")]
        fee: f64,
        /// Wallet file (default: auto-detect)
        #[arg(short, long)]
        wallet: Option<String>,
        /// Node URL to submit transaction (default: auto-detect)
        #[arg(short, long)]
        node: Option<String>,
    },
    /// Start mining blocks
    Mine {
        /// Wallet file (mining rewards go to this wallet)
        #[arg(short, long, default_value = "wallet.json")]
        wallet: String,
        /// Number of blocks to mine (0 = unlimited)
        #[arg(short, long, default_value = "0")]
        blocks: u64,
        /// Mining difficulty (leading zero bits)
        #[arg(short, long, default_value = "16")]
        difficulty: u64,
        /// Number of mining threads to use
        #[arg(short, long, default_value = "1")]
        jobs: usize,
        /// SIMD mode (optional). Currently supports: neon
        #[arg(short, long, value_enum)]
        simd: Option<SimdArg>,
    },
    /// Run a mining benchmark (mines N blocks and prints avg hashrate)
    Benchmark {
        /// Wallet file (mining rewards go to this wallet)
        #[arg(short, long, default_value = "wallet.json")]
        wallet: String,
        /// Number of blocks to mine
        #[arg(short, long, default_value = "20")]
        blocks: u64,
        /// Mining difficulty (leading zero bits)
        #[arg(short, long, default_value = "20")]
        difficulty: u64,
        /// Number of mining threads to use
        #[arg(short, long, default_value = "1")]
        jobs: usize,
        /// SIMD mode (optional). Currently supports: neon
        #[arg(short, long, value_enum)]
        simd: Option<SimdArg>,
    },
    /// Run a full node
    Node {
        /// Node role: miner, relay, light (default: miner)
        #[arg(long, default_value = "miner")]
        role: String,
        /// Port to listen on (or set TSN_PORT env var)
        #[arg(short, long)]
        port: Option<u16>,
        /// Peer nodes to connect to (in addition to seed nodes)
        #[arg(long)]
        peer: Vec<String>,
        /// Data directory (or set TSN_DATA_DIR env var)
        #[arg(short, long)]
        data_dir: Option<String>,
        /// Wallet file for mining (enables mining if provided)
        #[arg(long)]
        mine: Option<String>,
        /// Number of mining threads to use
        #[arg(short, long, default_value = "1")]
        jobs: usize,
        /// SIMD mode (optional). Currently supports: neon
        #[arg(short, long, value_enum)]
        simd: Option<SimdArg>,
        /// Public URL to announce to peers (e.g. https://example.com)
        #[arg(long)]
        public_url: Option<String>,
        /// Disable connecting to seed nodes
        #[arg(long)]
        no_seeds: bool,
        /// Disable assume-valid and verify all ZK proofs from genesis
        #[arg(long)]
        full_verify: bool,
        /// Allow mining without peer sync verification (for solo/testing)
        #[arg(long)]
        force_mine: bool,
        /// Wallet file for faucet (enables faucet if provided)
        #[arg(long)]
        faucet_wallet: Option<String>,
        /// Override daily faucet limit in TSN (default: 50)
        #[arg(long)]
        faucet_daily_limit: Option<u64>,
    },
    /// Check for updates and install the latest version
    Update,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Suppress logs for simple commands (balance, new-wallet)
    let is_quiet_cmd = matches!(cli.command, Some(Commands::Wallet { .. }) | Some(Commands::Balance { .. }) | Some(Commands::NewWallet { .. }) | Some(Commands::Send { .. }) | Some(Commands::History { .. }) | Some(Commands::Update));
    let log_level = if is_quiet_cmd {
        "error".to_string()
    } else {
        "info,yamux=error,libp2p_swarm=warn".to_string()
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_level.into()),
        )
        .init();

    match cli.command {
        Some(Commands::Wallet { wallet, node }) => {
            let wallet = wallet.or_else(auto_detect_wallet).unwrap_or_else(|| "wallet.json".to_string());
            let node = node.unwrap_or_else(|| {
                for port in [9333u16, 9334, 9335, 8333] {
                    if let Ok(stream) = std::net::TcpStream::connect_timeout(
                        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                        std::time::Duration::from_millis(200),
                    ) {
                        drop(stream);
                        return format!("http://127.0.0.1:{}", port);
                    }
                }
                format!("http://127.0.0.1:{}", config::get_port())
            });
            cmd_wallet_menu(&wallet, &node).await?;
        }
        Some(Commands::NewWallet { output }) => {
            cmd_new_wallet(&output)?;
        }
        Some(Commands::Balance { wallet, node }) => {
            let wallet = wallet.or_else(auto_detect_wallet).unwrap_or_else(|| "wallet.json".to_string());
            let node = node.unwrap_or_else(|| {
                // Try common ports to find running node (use 127.0.0.1, not localhost which may resolve to IPv6)
                for port in [9333u16, 9334, 9335, 8333] {
                    if let Ok(stream) = std::net::TcpStream::connect_timeout(
                        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                        std::time::Duration::from_millis(200),
                    ) {
                        drop(stream);
                        return format!("http://127.0.0.1:{}", port);
                    }
                }
                format!("http://127.0.0.1:{}", config::get_port())
            });
            cmd_balance(&wallet, &node).await?;
        }
        Some(Commands::History { node, limit }) => {
            let wallet_path = auto_detect_wallet().unwrap_or_else(|| "wallet.json".to_string());
            let node = node.unwrap_or_else(|| {
                for port in [9333u16, 9334, 9335, 8333] {
                    if let Ok(stream) = std::net::TcpStream::connect_timeout(
                        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                        std::time::Duration::from_millis(200),
                    ) {
                        drop(stream);
                        return format!("http://127.0.0.1:{}", port);
                    }
                }
                format!("http://127.0.0.1:{}", config::get_port())
            });
            cmd_history(&wallet_path, &node, limit).await?;
        }
        Some(Commands::Send { to, amount, fee, wallet, node }) => {
            let wallet = wallet.or_else(auto_detect_wallet).unwrap_or_else(|| "wallet.json".to_string());
            let node = node.unwrap_or_else(|| {
                for port in [9333u16, 9334, 9335, 8333] {
                    if let Ok(stream) = std::net::TcpStream::connect_timeout(
                        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                        std::time::Duration::from_millis(200),
                    ) {
                        drop(stream);
                        return format!("http://127.0.0.1:{}", port);
                    }
                }
                format!("http://127.0.0.1:{}", config::get_port())
            });
            cmd_send(&wallet, &node, &to, amount, fee).await?;
        }
        Some(Commands::Update) => {
            tsn::network::auto_update::cmd_update().await.map_err(|e| anyhow::anyhow!(e))?;
        }
        Some(Commands::Miner { threads, port, wallet, data_dir, peer, public_url, no_seeds }) => {
            let data_dir = data_dir.unwrap_or_else(|| "data-miner".to_string());
            let port = port.unwrap_or_else(|| find_free_port(config::get_port()));
            let wallet_path = wallet.unwrap_or_else(|| auto_wallet_for_mining(&data_dir));
            let jobs = threads.unwrap_or(1);
            let mut peers = if no_seeds { Vec::new() } else { config::get_seed_nodes() };
            peers.extend(peer);
            dedup_peers(&mut peers);
            cmd_node(port, peers, &data_dir, Some(wallet_path), jobs, None, public_url, false, None, None, true, NodeRole::Miner).await?;
        }
        Some(Commands::Relay { port, wallet, data_dir, peer, public_url, no_seeds }) => {
            let data_dir = data_dir.unwrap_or_else(|| "data-relay".to_string());
            let port = port.unwrap_or_else(|| find_free_port(config::get_port()));
            let wallet_path = wallet.or_else(auto_detect_wallet);
            let mut peers = if no_seeds { Vec::new() } else { config::get_seed_nodes() };
            peers.extend(peer);
            dedup_peers(&mut peers);
            cmd_node(port, peers, &data_dir, wallet_path, 1, None, public_url, false, None, None, true, NodeRole::Relay).await?;
        }
        Some(Commands::Light { port, wallet, data_dir, peer, no_seeds }) => {
            let data_dir = data_dir.unwrap_or_else(|| "data-light".to_string());
            let port = port.unwrap_or_else(|| find_free_port(config::get_port()));
            let wallet_path = wallet.or_else(auto_detect_wallet);
            let mut peers = if no_seeds { Vec::new() } else { config::get_seed_nodes() };
            peers.extend(peer);
            dedup_peers(&mut peers);
            cmd_node(port, peers, &data_dir, wallet_path, 1, None, None, false, None, None, true, NodeRole::LightClient).await?;
        }
        Some(Commands::Mine {
            wallet,
            blocks,
            difficulty,
            jobs,
            simd,
        }) => {
            cmd_mine(
                &wallet,
                blocks,
                difficulty,
                jobs,
                simd.map(Into::into),
                MiningMode::Mine,
            )?;
        }
        Some(Commands::Benchmark {
            wallet,
            blocks,
            difficulty,
            jobs,
            simd,
        }) => {
            cmd_mine(
                &wallet,
                blocks,
                difficulty,
                jobs,
                simd.map(Into::into),
                MiningMode::Benchmark,
            )?;
        }
        Some(Commands::Node {
            role,
            port,
            peer,
            data_dir,
            mine,
            jobs,
            simd,
            public_url,
            no_seeds,
            full_verify,
            force_mine,
            faucet_wallet,
            faucet_daily_limit,
        }) => {
            // Legacy `node` subcommand — still supported
            let node_role = NodeRole::from_str(&role).unwrap_or_else(|| {
                eprintln!("Unknown node role '{}'. Valid roles: miner, relay, light", role);
                std::process::exit(1);
            });
            let port = port.unwrap_or_else(config::get_port);
            let data_dir = data_dir.unwrap_or_else(config::get_data_dir);
            if full_verify {
                std::env::set_var("TSN_FULL_VERIFY", "1");
            }
            let mut peers = if no_seeds { Vec::new() } else { config::get_seed_nodes() };
            peers.extend(peer);
            dedup_peers(&mut peers);

            cmd_node(
                port, peers, &data_dir,
                mine, jobs, simd.map(Into::into), public_url,
                force_mine, faucet_wallet, faucet_daily_limit,
                true, // fast_sync always on
                node_role,
            ).await?;
        }
        None => {
            // ---- DEFAULT MODE: auto-detect everything and run as miner ----
            let node_role = auto_detect_role();
            let data_dir = cli.data_dir.unwrap_or_else(|| {
                match node_role {
                    NodeRole::Miner => "data-miner".to_string(),
                    NodeRole::Relay => "data-relay".to_string(),
                    NodeRole::LightClient => "data-light".to_string(),
                }
            });
            let port = cli.port.unwrap_or_else(|| find_free_port(config::get_port()));
            let jobs = cli.threads.unwrap_or(1);

            // Auto-detect or auto-create wallet (same behavior as `tsn miner`)
            let wallet = cli.wallet.or_else(auto_detect_wallet);
            let wallet = match wallet {
                Some(w) => Some(w),
                None if matches!(node_role, NodeRole::Miner) => {
                    // Auto-create wallet for mining, just like `tsn miner` does
                    Some(auto_wallet_for_mining(&data_dir))
                }
                None => None,
            };

            let mut peers = if cli.no_seeds { Vec::new() } else { config::get_seed_nodes() };
            peers.extend(cli.peer);
            dedup_peers(&mut peers);

            cmd_node(
                port, peers, &data_dir,
                wallet, jobs, None, cli.public_url,
                false, None, None,
                true, // fast_sync always on
                node_role,
            ).await?;
        }
    }

    Ok(())
}

/// Find a free port starting from `start`.
/// Tries start, start+1, start+2, ... up to start+100.
fn find_free_port(start: u16) -> u16 {
    for port in start..start.saturating_add(100) {
        if std::net::TcpListener::bind(("0.0.0.0", port)).is_ok() {
            return port;
        }
    }
    start // fallback
}

/// Auto-detect or auto-create wallet for mining.
/// 1. Check wallet.json next to binary / in cwd
/// 2. Check data_dir/wallet.json
/// 3. Create a new wallet in data_dir/wallet.json
/// BIP39-like word list (2048 words, simplified — first 256 common English words)
const SEED_WORDS: &[&str] = &[
    "abandon","ability","able","about","above","absent","absorb","abstract",
    "absurd","abuse","access","accident","account","accuse","achieve","acid",
    "acoustic","acquire","across","act","action","actor","actress","actual",
    "adapt","add","addict","address","adjust","admit","adult","advance",
    "advice","aerobic","affair","afford","afraid","again","age","agent",
    "agree","ahead","aim","air","airport","aisle","alarm","album",
    "alcohol","alert","alien","all","alley","allow","almost","alone",
    "alpha","already","also","alter","always","amateur","amazing","among",
    "amount","amused","analyst","anchor","ancient","anger","angle","angry",
    "animal","ankle","announce","annual","another","answer","antenna","antique",
    "anxiety","any","apart","apology","appear","apple","approve","april",
    "arch","arctic","area","arena","argue","arm","armed","armor",
    "army","around","arrange","arrest","arrive","arrow","art","artefact",
    "artist","artwork","ask","aspect","assault","asset","assist","assume",
    "asthma","athlete","atom","attack","attend","attitude","attract","auction",
    "audit","august","aunt","author","auto","autumn","average","avocado",
    "avoid","awake","aware","awesome","awful","awkward","axis","baby",
    "bachelor","bacon","badge","bag","balance","balcony","ball","bamboo",
    "banana","banner","bar","barely","bargain","barrel","base","basic",
    "basket","battle","beach","bean","beauty","because","become","beef",
    "before","begin","behave","behind","believe","below","belt","bench",
    "benefit","best","betray","better","between","beyond","bicycle","bid",
    "bike","bind","biology","bird","birth","bitter","black","blade",
    "blame","blanket","blast","bleak","bless","blind","blood","blossom",
    "blow","blue","blur","blush","board","boat","body","boil",
    "bomb","bone","bonus","book","boost","border","boring","borrow",
    "boss","bottom","bounce","box","boy","bracket","brain","brand",
    "brass","brave","bread","breeze","brick","bridge","brief","bright",
    "bring","brisk","broccoli","broken","bronze","broom","brother","brown",
    "brush","bubble","buddy","budget","buffalo","build","bulb","bulk",
    "bullet","bundle","bunny","burden","burger","burst","bus","business",
];

fn generate_seed_phrase() -> String {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut entropy = [0u8; 32]; // 256 bits
    rng.fill_bytes(&mut entropy);

    // Convert 256 bits of entropy to 24 words (each word = ~10.7 bits)
    let mut words = Vec::with_capacity(24);
    for i in 0..24 {
        let byte_idx = i * 32 / 24;
        let combined = if byte_idx + 1 < 32 {
            ((entropy[byte_idx] as u16) << 8) | (entropy[byte_idx + 1] as u16)
        } else {
            (entropy[byte_idx] as u16) << 8
        };
        let word_idx = (combined as usize + i * 7) % SEED_WORDS.len();
        words.push(SEED_WORDS[word_idx]);
    }
    words.join(" ")
}

fn auto_wallet_for_mining(data_dir: &str) -> String {
    // Check common locations first
    if let Some(w) = auto_detect_wallet() {
        println!("Wallet found: {}", w);
        return w;
    }
    // Check in data dir
    let data_wallet = std::path::PathBuf::from(data_dir).join("wallet.json");
    if data_wallet.exists() {
        let p = data_wallet.to_string_lossy().to_string();
        println!("Wallet found: {}", p);
        return p;
    }

    // Auto-create with seed phrase
    let yellow = "\x1b[1;33m";
    let green = "\x1b[1;32m";
    let red = "\x1b[1;31m";
    let reset = "\x1b[0m";

    println!();
    println!("{}========================================{}", yellow, reset);
    println!("{}  NEW WALLET CREATION{}", yellow, reset);
    println!("{}========================================{}", yellow, reset);
    println!();

    let seed_phrase = generate_seed_phrase();

    println!("  Your recovery seed phrase (24 words):");
    println!();
    println!("  {}{}{}",green, seed_phrase, reset);
    println!();
    println!("  {}WARNING: Write these words down and store them safely!{}", red, reset);
    println!("  {}Without this phrase, your coins are LOST FOREVER.{}", red, reset);
    println!("  This is the ONLY time this phrase will be shown.");
    println!();

    // Wait for user confirmation
    print!("  Have you saved your seed phrase? Type YES to continue: ");
    use std::io::Write;
    std::io::stdout().flush().ok();

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();

    if input.trim().to_uppercase() != "YES" {
        println!();
        println!("  Aborted. Please run again and save your seed phrase.");
        std::process::exit(0);
    }

    println!();
    std::fs::create_dir_all(data_dir).ok();
    let wallet = ShieldedWallet::generate();
    let path = data_wallet.to_string_lossy().to_string();
    wallet.save(&path).expect("Failed to create wallet");
    println!("  Wallet created: {}", path);
    println!("  Address: {}", hex::encode(wallet.pk_hash()));
    println!();
    path
}

/// Auto-detect node role from parent directory name
fn auto_detect_role() -> NodeRole {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let dir_name = parent.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_lowercase();
            if dir_name.contains("relay") { return NodeRole::from_str("relay").unwrap(); }
            if dir_name.contains("light") { return NodeRole::from_str("light").unwrap(); }
        }
    }
    // Also check current working directory
    if let Ok(cwd) = std::env::current_dir() {
        let dir_name = cwd.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        if dir_name.contains("relay") { return NodeRole::from_str("relay").unwrap(); }
        if dir_name.contains("light") { return NodeRole::from_str("light").unwrap(); }
    }
    // Default: miner
    NodeRole::from_str("miner").unwrap()
}

/// Auto-detect wallet.json next to binary or in current dir
fn auto_detect_wallet() -> Option<String> {
    // Check next to binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let wallet_path = parent.join("wallet.json");
            if wallet_path.exists() {
                return Some(wallet_path.to_string_lossy().to_string());
            }
            // Check data* subdirectories next to binary
            if let Ok(entries) = std::fs::read_dir(parent) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with("data") && entry.path().is_dir() {
                        let w = entry.path().join("wallet.json");
                        if w.exists() {
                            return Some(w.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
    }
    // Check current directory
    let cwd_wallet = std::path::Path::new("wallet.json");
    if cwd_wallet.exists() {
        return Some("wallet.json".to_string());
    }
    // Check data* subdirectories in current directory
    if let Ok(entries) = std::fs::read_dir(".") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("data") && entry.path().is_dir() {
                let w = entry.path().join("wallet.json");
                if w.exists() {
                    return Some(w.to_string_lossy().to_string());
                }
            }
        }
    }
    None
}

/// Deduplicate peer URLs
fn dedup_peers(peers: &mut Vec<String>) {
    for p in peers.iter_mut() {
        while p.ends_with('/') { p.pop(); }
    }
    let mut seen = std::collections::HashSet::new();
    peers.retain(|p| seen.insert(p.clone()));
}

fn cmd_new_wallet(output: &str) -> anyhow::Result<()> {
    println!("Generating new TSN shielded wallet...");
    let wallet = ShieldedWallet::generate();

    wallet.save(output)?;

    println!("Wallet saved to: {}", output);
    println!("Address: {}", hex::encode(wallet.pk_hash()));
    println!("\nThis wallet uses:");
    println!("  - CRYSTALS-Dilithium post-quantum signatures");
    println!("  - zk-SNARKs for private transactions");
    println!("\nYour balance is private and can only be viewed with this wallet file.");
    Ok(())
}

async fn cmd_wallet_menu(wallet_path: &str, node_url: &str) -> anyhow::Result<()> {
    use std::io::{self, Write};

    let green = "\x1b[1;32m";
    let cyan = "\x1b[1;36m";
    let yellow = "\x1b[1;33m";
    let reset = "\x1b[0m";

    loop {
        // Load wallet for display
        let wallet = ShieldedWallet::load(wallet_path);
        let pk_hash_hex = wallet.as_ref()
            .map(|w| hex::encode(w.pk_hash()))
            .unwrap_or_else(|_| "???".to_string());

        println!();
        println!("  {}╔══════════════════════════════════════════════════════════════════════╗{}", cyan, reset);
        println!("  {}║  TSN Wallet v1.3.0║{}", cyan, reset);
        println!("  {}╚══════════════════════════════════════════════════════════════════════╝{}", cyan, reset);
        println!("  Your address (share this to receive TSN):");
        println!("  {}{}{}", green, pk_hash_hex, reset);
        println!();
        println!("  {}1{} — Balance", yellow, reset);
        println!("  {}2{} — Transaction history", yellow, reset);
        println!("  {}3{} — Send TSN", yellow, reset);
        println!("  {}4{} — Rescan wallet", yellow, reset);
        println!("  {}0{} — Quit", yellow, reset);
        println!();
        print!("  Choice: ");
        io::stdout().flush().ok();

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let choice = input.trim();

        match choice {
            "1" => {
                cmd_balance(wallet_path, node_url).await?;
            }
            "2" => {
                cmd_history(wallet_path, node_url, 20).await?;
            }
            "3" => {
                print!("  Recipient address: ");
                io::stdout().flush().ok();
                let mut to = String::new();
                io::stdin().read_line(&mut to)?;
                let to = to.trim();
                if to.len() != 64 {
                    println!("  {}Invalid address (must be 64 hex chars){}", "\x1b[1;31m", reset);
                    continue;
                }

                print!("  Amount (TSN): ");
                io::stdout().flush().ok();
                let mut amt = String::new();
                io::stdin().read_line(&mut amt)?;
                let amount: f64 = match amt.trim().parse() {
                    Ok(a) if a > 0.0 => a,
                    _ => {
                        println!("  {}Invalid amount{}", "\x1b[1;31m", reset);
                        continue;
                    }
                };

                if let Err(e) = cmd_send(wallet_path, node_url, to, amount, 0.001).await {
                    println!("  {}Error: {}{}", "\x1b[1;31m", e, reset);
                }
            }
            "4" => {
                println!("  Rescanning wallet from height 0...");
                if let Ok(mut w) = ShieldedWallet::load(wallet_path) {
                    w.clear_notes();
                    w.save(wallet_path).ok();
                }
                cmd_balance(wallet_path, node_url).await?;
            }
            "0" | "q" | "quit" | "exit" => {
                println!("  Bye!");
                break;
            }
            _ => {
                println!("  Invalid choice");
            }
        }
    }
    Ok(())
}

async fn cmd_history(wallet_path: &str, _node_url: &str, limit: usize) -> anyhow::Result<()> {
    let green = "\x1b[1;32m";
    let red = "\x1b[1;31m";
    let cyan = "\x1b[1;36m";
    let reset = "\x1b[0m";

    let coin_decimals = config::COIN_DECIMALS;
    let divisor = 10u64.pow(coin_decimals) as f64;

    // Read TX history from wallet file
    let wallet = ShieldedWallet::load(wallet_path)?;
    let history = wallet.tx_history();

    if history.is_empty() {
        println!("  No transactions yet.");
        println!();
        println!("  Transactions will appear here after you send or receive TSN.");
        println!("  Explorer: https://explorer.tsnchain.com/");
        return Ok(());
    }

    println!();
    println!("  Transaction History ({}):", history.len());
    println!();

    for (i, tx) in history.iter().rev().take(limit).enumerate() {
        let arrow = if tx.direction == "sent" {
            format!("{}SENT{}", red, reset)
        } else {
            format!("{}RECEIVED{}", green, reset)
        };

        let amount_display = tx.amount as f64 / divisor;
        let fee_display = tx.fee as f64 / divisor;

        let counterparty_short = if tx.counterparty.len() > 16 {
            format!("{}…{}", &tx.counterparty[..8], &tx.counterparty[tx.counterparty.len()-8..])
        } else {
            tx.counterparty.clone()
        };

        let time_str = if tx.timestamp > 0 {
            let secs_ago = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(tx.timestamp);
            if secs_ago < 60 { format!("{}s ago", secs_ago) }
            else if secs_ago < 3600 { format!("{}m ago", secs_ago / 60) }
            else if secs_ago < 86400 { format!("{}h ago", secs_ago / 3600) }
            else { format!("{}d ago", secs_ago / 86400) }
        } else {
            "unknown".to_string()
        };

        println!("  {} #{}", arrow, i + 1);
        println!("    {}{:.4} TSN{}  →  {}  |  Fee: {:.4} TSN  |  {}",
            cyan, amount_display, reset, counterparty_short, fee_display, time_str);
        println!("    Hash: {}{}{}", green, tx.tx_hash, reset);
        println!();
    }

    println!("  Explorer: https://explorer.tsnchain.com/");
    Ok(())
}

async fn cmd_balance(wallet_path: &str, node_url: &str) -> anyhow::Result<()> {
    let mut wallet = ShieldedWallet::load(wallet_path)?;
    let coin_decimals = config::COIN_DECIMALS;
    let divisor = 10u64.pow(coin_decimals);
    let scanned_height = wallet.last_scanned_height();

    // Try to scan new blocks via running node API, then fallback to local DB
    let (api_ok, api_notes) = try_scan_via_api(&mut wallet, node_url, wallet_path).await;

    let mut new_notes = api_notes;
    let mut scan_source = if api_ok { "node API" } else { "" };

    if !api_ok {
        // Fallback: try local blockchain DB
        let data_dirs = ["data-miner", "data", "./data-miner", "./data"];
        for dir in &data_dirs {
            let db_path = format!("{}/blockchain", dir);
            if !std::path::Path::new(&db_path).exists() { continue; }
            if let Ok(chain) = ShieldedBlockchain::open(&db_path, GENESIS_DIFFICULTY) {
                let chain_height = chain.height();
                if chain_height > wallet.last_scanned_height() {
                    // Calculate starting position from commitment count
                    let mut pos = chain.fast_sync_commitment_offset();
                    // Count outputs from fast_sync_base to scan start
                    let scan_start = wallet.last_scanned_height() + 1;
                    let fs_base = chain.fast_sync_base_height();
                    if fs_base > 0 && scan_start > fs_base {
                        for h in (fs_base + 1)..scan_start {
                            if let Some(b) = chain.get_block_by_height(h) {
                                for tx in &b.transactions { pos += tx.outputs.len() as u64; }
                                for tx in &b.transactions_v2 { pos += tx.outputs.len() as u64; }
                                pos += 1; // coinbase
                            }
                        }
                    }
                    for h in scan_start..=chain_height {
                        if let Some(block) = chain.get_block_by_height(h) {
                            new_notes += wallet.scan_block(&block, pos);
                            for tx in &block.transactions { pos += tx.outputs.len() as u64; }
                            for tx in &block.transactions_v2 { pos += tx.outputs.len() as u64; }
                            pos += 1; // coinbase
                        }
                    }
                    wallet.save(wallet_path).ok();
                    scan_source = dir;
                }
                break;
            }
        }
    }

    // Display result — clean and simple
    let balance_raw = wallet.balance();
    let balance_coins = balance_raw as f64 / divisor as f64;
    let green = "\x1b[1;32m";
    let cyan = "\x1b[1;36m";
    let reset = "\x1b[0m";

    println!();
    println!("  Address:  {}", hex::encode(wallet.pk_hash()));
    if balance_raw > 0 {
        println!("  Balance:  {}{:.4} TSN{} ({} notes)", green, balance_coins, reset, wallet.note_count());
    } else {
        println!("  Balance:  0 TSN");
    }
    println!("  Scanned:  height {}", wallet.last_scanned_height());

    if new_notes > 0 {
        println!("  {}+{} new notes found{} (from {})", cyan, new_notes, reset, scan_source);
    }

    if wallet.last_scanned_height() == 0 && balance_raw == 0 {
        println!();
        println!("  Tip: Run your node to sync the blockchain first.");
    }
    println!();

    Ok(())
}

/// Try to scan wallet via a running node's API.
/// Uses /blocks/since/:height which returns full ShieldedBlock structs.
/// Returns (success, notes_found).
async fn cmd_send(wallet_path: &str, node_url: &str, to: &str, amount: f64, fee: f64) -> anyhow::Result<()> {
    use tsn::crypto::pq::commitment_pq::NoteCommitmentPQ;
    use tsn::crypto::pq::proof_pq::{SpendWitnessPQ, OutputWitnessPQ, TransactionProver};
    use tsn::crypto::note::encrypt_note_pq;
    use tsn::core::{SpendDescriptionV2, OutputDescriptionV2, ShieldedTransactionV2};
    use rand::RngCore;

    let green = "\x1b[1;32m";
    let cyan = "\x1b[1;36m";
    let reset = "\x1b[0m";

    // Validate recipient
    if to.len() != 64 || hex::decode(to).is_err() {
        anyhow::bail!("Invalid recipient address. Must be 64 hex characters (pk_hash).");
    }
    let mut recipient_pk_hash = [0u8; 32];
    hex::decode_to_slice(to, &mut recipient_pk_hash)?;

    // Convert amounts to base units (1 TSN = 10^9)
    let decimals = config::COIN_DECIMALS;
    let multiplier = 10u64.pow(decimals);
    let amount_base = (amount * multiplier as f64) as u64;
    let fee_base = (fee * multiplier as f64) as u64;
    let total_needed = amount_base + fee_base;

    // Load and scan wallet
    let mut wallet = ShieldedWallet::load(wallet_path)?;
    try_scan_via_api(&mut wallet, node_url, wallet_path).await;

    let balance = wallet.balance();
    println!();
    println!("  Wallet:    {}", wallet_path);
    println!("  Balance:   {}{:.4} TSN{}", green, balance as f64 / multiplier as f64, reset);
    println!("  Sending:   {}{:.4} TSN{} to {}...{}", cyan, amount, reset, &to[..8], &to[56..]);
    println!("  Fee:       {:.4} TSN", fee);

    if balance < total_needed {
        anyhow::bail!("Insufficient balance: have {:.4} TSN, need {:.4} TSN",
            balance as f64 / multiplier as f64,
            total_needed as f64 / multiplier as f64
        );
    }

    // Check PQ nullifiers against the node to filter already-spent notes
    {
        let nk_bytes = wallet.nullifier_key_bytes();
        let mut nullifier_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut nullifier_hexes: Vec<String> = Vec::new();
        let notes = wallet.notes_mut();
        for (i, note) in notes.iter().enumerate() {
            if !note.is_spent {
                if let Some(pq_cm) = note.pq_commitment {
                    let nf = tsn::crypto::pq::commitment_pq::derive_nullifier_pq(
                        &nk_bytes, &pq_cm, note.position
                    );
                    let nf_hex = hex::encode(nf);
                    nullifier_map.insert(nf_hex.clone(), i);
                    nullifier_hexes.push(nf_hex);
                }
            }
        }
        if !nullifier_hexes.is_empty() {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()?;
            let check_url = format!("{}/nullifiers/check", node_url);
            if let Ok(resp) = client.post(&check_url)
                .json(&serde_json::json!({"nullifiers": nullifier_hexes}))
                .send().await
            {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(spent_arr) = body["spent"].as_array() {
                        let notes = wallet.notes_mut();
                        let mut count = 0;
                        for s in spent_arr {
                            if let Some(h) = s.as_str() {
                                if let Some(&idx) = nullifier_map.get(h) {
                                    notes[idx].is_spent = true;
                                    count += 1;
                                }
                            }
                        }
                        if count > 0 {
                            eprintln!("  ({} spent notes filtered)", count);
                            wallet.save(wallet_path).ok();
                        }
                    }
                }
            }
        }
    }

    // Select notes (greedy: largest first)
    let unspent = wallet.unspent_notes();
    let mut selected = Vec::new();
    let mut selected_total = 0u64;

    let mut sorted: Vec<_> = unspent.iter().collect();
    sorted.sort_by(|a, b| b.note.value.cmp(&a.note.value));

    for note in sorted {
        if selected_total >= total_needed { break; }
        selected.push(note);
        selected_total += note.note.value;
    }

    let change = selected_total - total_needed;
    println!("  Notes:     {} selected ({:.4} TSN, change: {:.4} TSN)",
        selected.len(),
        selected_total as f64 / multiplier as f64,
        change as f64 / multiplier as f64
    );

    // Get merkle witnesses from node
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let nullifier_key = wallet.nullifier_key_bytes();
    let pk_hash = wallet.pk_hash();
    let keypair = wallet.keypair();

    let mut spend_witnesses = Vec::new();
    for note in &selected {
        let pos = note.position;
        let url = format!("{}/witness/v2/position/{}", node_url, pos);
        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("Failed to get witness for position {}: HTTP {}", pos, resp.status());
        }

        // Parse witness manually (API returns hex strings, not raw bytes)
        let v: serde_json::Value = resp.json().await?;
        let root_hex = v["root"].as_str().unwrap_or("");
        let mut root = [0u8; 32];
        if let Ok(bytes) = hex::decode(root_hex) {
            if bytes.len() == 32 { root.copy_from_slice(&bytes); }
        }
        let empty = vec![];
        let path_arr = v["path"].as_array().unwrap_or(&empty);
        let indices_arr = v["indices"].as_array().unwrap_or(&empty);
        let siblings: Vec<[u8; 32]> = path_arr.iter().filter_map(|s| {
            let h = s.as_str()?;
            let b = hex::decode(h).ok()?;
            if b.len() == 32 { let mut a = [0u8;32]; a.copy_from_slice(&b); Some(a) } else { None }
        }).collect();
        let indices: Vec<u8> = indices_arr.iter().filter_map(|i| i.as_u64().map(|n| n as u8)).collect();

        let witness = tsn::crypto::pq::merkle_pq::MerkleWitnessPQ {
            path: tsn::crypto::pq::merkle_pq::MerklePathPQ { siblings, indices },
            position: pos,
            root,
        };

        // Get PQ randomness (required for V2 spending)
        let randomness = match note.pq_randomness {
            Some(r) => r,
            None => {
                // Fallback: try to derive from Fr randomness (may not work)
                let mut r = [0u8; 32];
                use ark_serialize::CanonicalSerialize;
                note.note.randomness.serialize_compressed(&mut r[..]).ok();
                r
            }
        };

        // Pre-verify merkle witness before proof generation
        let stored_pq_cm = note.pq_commitment.unwrap_or([0u8; 32]);
        if !witness.verify(&tsn::crypto::pq::commitment_pq::NoteCommitmentPQ(stored_pq_cm)) {
            anyhow::bail!(
                "Merkle witness verification failed for note at position {}. \
                 The commitment in your wallet does not match the merkle tree. \
                 Try rescanning your wallet (delete notes and set last_scanned_height to 0).",
                pos
            );
        }

        spend_witnesses.push(SpendWitnessPQ {
            value: note.note.value,
            recipient_pk_hash: note.note.recipient_pk_hash,
            randomness,
            nullifier_key,
            position: pos,
            merkle_witness: witness,
        });
    }

    // Build output witnesses
    let mut rng = rand::thread_rng();
    let mut output_witnesses = Vec::new();

    let mut recipient_randomness = [0u8; 32];
    rng.fill_bytes(&mut recipient_randomness);
    output_witnesses.push(OutputWitnessPQ {
        value: amount_base,
        recipient_pk_hash,
        randomness: recipient_randomness,
    });

    let mut change_randomness = None;
    if change > 0 {
        let mut cr = [0u8; 32];
        rng.fill_bytes(&mut cr);
        output_witnesses.push(OutputWitnessPQ {
            value: change,
            recipient_pk_hash: pk_hash,
            randomness: cr,
        });
        change_randomness = Some(cr);
    }

    // Generate Plonky2 proof
    eprint!("  Proof:     generating...");
    let prover = TransactionProver::new();
    let proof = prover.prove(&spend_witnesses, &output_witnesses, fee_base)
        .map_err(|e| anyhow::anyhow!("Proof generation failed: {}", e))?;
    eprintln!(" done ({} bytes)", proof.size());

    // Build spend descriptions (sign with ML-DSA-65)
    let mut spends = Vec::new();
    for sw in &spend_witnesses {
        let nullifier = sw.nullifier();
        let anchor = sw.merkle_witness.root;
        let signature = tsn::crypto::sign(&nullifier, keypair);
        spends.push(SpendDescriptionV2 {
            anchor,
            nullifier,
            signature,
            public_key: keypair.public_key_bytes().to_vec(),
        });
    }

    // Build output descriptions
    let mut outputs = Vec::new();
    let rc = NoteCommitmentPQ::commit(amount_base, &recipient_pk_hash, &recipient_randomness);
    let re = encrypt_note_pq(amount_base, &recipient_pk_hash, &recipient_randomness);
    outputs.push(OutputDescriptionV2 {
        note_commitment: rc.to_bytes(),
        encrypted_note: re,
    });

    if let Some(cr) = change_randomness {
        let cc = NoteCommitmentPQ::commit(change, &pk_hash, &cr);
        let ce = encrypt_note_pq(change, &pk_hash, &cr);
        outputs.push(OutputDescriptionV2 {
            note_commitment: cc.to_bytes(),
            encrypted_note: ce,
        });
    }

    // Assemble and submit transaction
    let tx = ShieldedTransactionV2::new(spends, outputs, fee_base, proof);
    let tx_hash = hex::encode(tx.hash());

    eprint!("  Submit:    sending...");

    // Submit to local node
    let resp = client.post(&format!("{}/tx/v2", node_url))
        .json(&serde_json::json!({ "transaction": tx }))
        .send()
        .await?;

    if !resp.status().is_success() {
        let err = resp.text().await.unwrap_or_default();
        eprintln!(" FAILED");
        anyhow::bail!("Transaction rejected: {}", err);
    }

    // Also relay directly to seed nodes for faster propagation
    let seeds = config::get_seed_nodes();
    let tx_json = serde_json::json!({ "transaction": tx });
    for seed in &seeds {
        let url = format!("{}/tx/v2", seed);
        let _ = client.post(&url).json(&tx_json).send().await;
    }

    eprintln!(" {}confirmed!{} (relayed to {} seeds)", green, reset, seeds.len());
    println!();
    println!("  {}TX: {}{}", green, tx_hash, reset);
    println!();

    // Record TX in wallet history
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    wallet.add_tx(tsn::wallet::WalletTxRecord {
        tx_hash: tx_hash.clone(),
        direction: "sent".to_string(),
        amount: amount_base,
        fee: fee_base,
        counterparty: to.to_string(),
        height: 0, // will be updated when mined
        timestamp: now,
    });
    wallet.save(wallet_path).ok();

    Ok(())
}

async fn try_scan_via_api(wallet: &mut ShieldedWallet, node_url: &str, wallet_path: &str) -> (bool, usize) {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return (false, 0),
    };

    // Check node is reachable and get chain height
    let info_url = format!("{}/chain/info", node_url);
    let chain_height: u64 = match client.get(&info_url).send().await {
        Ok(r) if r.status().is_success() => {
            match r.json::<serde_json::Value>().await {
                Ok(v) => v["height"].as_u64().unwrap_or(0),
                Err(_) => return (false, 0),
            }
        }
        _ => return (false, 0),
    };

    let scanned_height = wallet.last_scanned_height();
    if chain_height <= scanned_height {
        return (true, 0); // already up to date
    }

    let blocks_to_scan = chain_height - scanned_height;
    if blocks_to_scan > 50 {
        eprint!("  Scanning {} blocks via outputs API...", blocks_to_scan);
    }

    // Use /outputs/since/ API — returns each output with its CORRECT position
    // from the server's merkle tree. This avoids position mismatch after fast-sync.
    let url = format!("{}/outputs/since/{}", node_url, scanned_height);
    let resp = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => {
            match r.json::<serde_json::Value>().await {
                Ok(v) => v,
                Err(_) => return (false, 0),
            }
        }
        _ => return (false, 0),
    };

    let outputs = match resp["outputs"].as_array() {
        Some(arr) => arr,
        None => return (false, 0),
    };

    let mut new_notes = 0usize;
    let mut max_height = scanned_height;

    for output in outputs {
        let position = output["position"].as_u64().unwrap_or(0);
        let block_height = output["block_height"].as_u64().unwrap_or(0);
        let note_commitment = output["note_commitment"].as_str().unwrap_or("");
        let note_commitment_pq = output["note_commitment_pq"].as_str().unwrap_or("");
        let ephemeral_pk_hex = output["ephemeral_pk"].as_str().unwrap_or("");
        let ciphertext_hex = output["ciphertext"].as_str().unwrap_or("");

        // Reconstruct EncryptedNote from hex data
        let ephemeral_pk = match hex::decode(ephemeral_pk_hex) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ciphertext = match hex::decode(ciphertext_hex) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let encrypted_note = tsn::crypto::note::EncryptedNote {
            ciphertext,
            ephemeral_pk,
        };

        if wallet.scan_encrypted_output(
            &encrypted_note,
            note_commitment,
            note_commitment_pq,
            position,
            block_height,
        ) {
            new_notes += 1;

            // Detect received TX (not mining reward)
            // Mining rewards are exactly miner_reward or dev_fee amounts
            let miner_rwd = config::miner_reward(config::BLOCK_REWARD);
            let dev_rwd = config::dev_fee(config::BLOCK_REWARD);
            let last_note = wallet.notes().last();
            if let Some(note) = last_note {
                let val = note.note.value;
                if val != miner_rwd && val != dev_rwd && val > 0 {
                    // This is a received transfer, not a mining reward
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    wallet.add_tx(tsn::wallet::WalletTxRecord {
                        tx_hash: format!("received-at-height-{}", block_height),
                        direction: "received".to_string(),
                        amount: val,
                        fee: 0,
                        counterparty: "unknown".to_string(),
                        height: block_height,
                        timestamp: now,
                    });
                }
            }
        }

        if block_height > max_height {
            max_height = block_height;
        }
    }

    // Update scanned height to the chain height (we scanned all available outputs)
    wallet.set_last_scanned_height(chain_height);

    // Check PQ nullifiers to mark spent notes
    {
        let nk_bytes = wallet.nullifier_key_bytes();
        let mut nullifier_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut nullifier_hexes: Vec<String> = Vec::new();
        let notes = wallet.notes_mut();
        for (i, note) in notes.iter().enumerate() {
            if !note.is_spent {
                if let Some(pq_cm) = note.pq_commitment {
                    let nf = tsn::crypto::pq::commitment_pq::derive_nullifier_pq(
                        &nk_bytes, &pq_cm, note.position
                    );
                    let nf_hex = hex::encode(nf);
                    nullifier_map.insert(nf_hex.clone(), i);
                    nullifier_hexes.push(nf_hex);
                }
            }
        }
        if !nullifier_hexes.is_empty() {
            let check_url = format!("{}/nullifiers/check", node_url);
            if let Ok(resp) = client.post(&check_url)
                .json(&serde_json::json!({"nullifiers": nullifier_hexes}))
                .send().await
            {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(spent_arr) = body["spent"].as_array() {
                        let notes = wallet.notes_mut();
                        for s in spent_arr {
                            if let Some(h) = s.as_str() {
                                if let Some(&idx) = nullifier_map.get(h) {
                                    notes[idx].is_spent = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if blocks_to_scan > 50 {
        eprintln!(" done ({} new notes).", new_notes);
    }

    if chain_height > scanned_height {
        wallet.save(wallet_path).ok();
    }
    (true, new_notes)
}

fn cmd_mine(
    wallet_path: &str,
    blocks: u64,
    difficulty: u64,
    jobs: usize,
    simd: Option<SimdMode>,
    mode: MiningMode,
) -> anyhow::Result<()> {
    let jobs = jobs.max(1);
    let simd = require_simd_support(simd);
    // Load wallet for mining rewards
    let wallet = ShieldedWallet::load(wallet_path)?;
    let miner_pk_hash = wallet.pk_hash();
    let viewing_key = wallet.viewing_key().clone();

    match mode {
        MiningMode::Mine => println!("Starting standalone miner..."),
        MiningMode::Benchmark => println!("Starting mining benchmark..."),
    }
    println!("Miner wallet: {}", wallet_path);
    println!("Miner pk_hash: {}", hex::encode(miner_pk_hash));
    println!("Difficulty: {} leading zero bits", difficulty);
    println!("Threads: {}", jobs);
    if let Some(simd) = simd {
        println!("SIMD mode: {:?}", simd);
    }
    let pool = MiningPool::new_with_simd(jobs, simd);
    let mut blockchain = ShieldedBlockchain::with_miner(difficulty, miner_pk_hash, &viewing_key);
    let mut blocks_mined = 0u64;
    let mut total_attempts = 0u64;
    let mut total_elapsed = std::time::Duration::ZERO;

    loop {
        let mempool_txs = vec![]; // Standalone miner has no mempool
        let mut block = blockchain.create_block_template(miner_pk_hash, &viewing_key, mempool_txs);

        println!(
            "\nMining block {} (prev: {}...)",
            blockchain.height() + 1,
            &hex::encode(&block.header.prev_hash)[..16]
        );

        let start = std::time::Instant::now();
        let attempts = pool.mine_block(&mut block);
        let elapsed = start.elapsed();
        total_attempts = total_attempts.saturating_add(attempts);
        total_elapsed += elapsed;

        println!(
            "Block mined! Hash: {}...",
            &block.hash_hex()[..16]
        );
        println!(
            "  {} attempts in {:.2}s ({:.0} H/s)",
            attempts,
            elapsed.as_secs_f64(),
            attempts as f64 / elapsed.as_secs_f64()
        );

        blockchain.add_block(block)?;

        blocks_mined += 1;
        println!(
            "  Chain height: {}, Commitments: {}",
            blockchain.height(),
            blockchain.state().commitment_count()
        );

        if blocks > 0 && blocks_mined >= blocks {
            println!("\nMined {} blocks, stopping.", blocks_mined);
            if total_elapsed.as_secs_f64() > 0.0 {
                let avg_hashrate = total_attempts as f64 / total_elapsed.as_secs_f64();
                let label = match mode {
                    MiningMode::Mine => "Summary",
                    MiningMode::Benchmark => "Benchmark summary",
                };
                println!("{}:", label);
                println!(
                    "  Total attempts: {} in {:.2}s",
                    total_attempts,
                    total_elapsed.as_secs_f64()
                );
                println!("  Avg hashrate: {:.0} H/s", avg_hashrate);
            }
            break;
        }
    }

    Ok(())
}

async fn cmd_node(
    port: u16,
    peers: Vec<String>,
    data_dir: &str,
    mine_wallet: Option<String>,
    jobs: usize,
    simd: Option<SimdMode>,
    public_url: Option<String>,
    force_mine: bool,
    faucet_wallet: Option<String>,
    faucet_daily_limit: Option<u64>,
    fast_sync: bool,
    node_role: NodeRole,
) -> anyhow::Result<()> {
    use tsn::network::{AppState, MinerStats, sync_from_peer, sync_loop, broadcast_block, discovery_loop};
    use tsn::crypto::proof::CircomVerifyingParams;
    use tsn::faucet::FaucetService;
    use tsn::storage::Database;
    use std::sync::RwLock;
    use tokio::sync::RwLock as TokioRwLock;

    let simd = require_simd_support(simd);

    // Create data directory if needed
    std::fs::create_dir_all(data_dir)?;

    // Load wallet for any role (miner: mining rewards, relay: relay rewards, light: balance/send)
    let miner_info = if let Some(wallet_path) = &mine_wallet {
        let wallet = ShieldedWallet::load(wallet_path)?;
        let pk_hash = wallet.pk_hash();
        let viewing_key = wallet.viewing_key().clone();
        Some((pk_hash, viewing_key))
    } else {
        None
    };

    let role_icon = match node_role {
        NodeRole::Miner => "⛏️",
        NodeRole::Relay => "🔄",
        NodeRole::LightClient => "💡",
    };

    let version_str = env!("CARGO_PKG_VERSION");
    let banner_line = format!("║     TSN Shielded Node v{:<19}║", version_str);
    println!();
    println!("╔═══════════════════════════════════════════╗");
    println!("{}", banner_line);
    println!("╚═══════════════════════════════════════════╝");
    println!();
    // ANSI color codes
    let green = "\x1b[1;32m";   // bold green
    let cyan = "\x1b[1;36m";    // bold cyan
    let yellow = "\x1b[1;33m";  // bold yellow
    let reset = "\x1b[0m";

    println!("  {} Role:        {}{} ({}){}", role_icon, green, node_role, node_role.description(), reset);
    println!("  Network:      {}", config::NETWORK_NAME);
    println!("  Port:         {}", port);
    println!("  Data:         {}", data_dir);
    if node_role.stores_full_chain() {
        println!("  Explorer:     https://explorer.tsnchain.com");
    }
    if let Some((ref pk_hash, _)) = miner_info {
        println!();
        match node_role {
            NodeRole::Miner => {
                println!("  {}⛏️  MINING ACTIVE{}", yellow, reset);
                println!("  Threads:      {}{}{}", cyan, jobs, reset);
                println!("  Address:      {}", hex::encode(pk_hash));
                println!("  Reward split: 92% miner / 5% dev fees / 3% relay pool");
            }
            NodeRole::Relay => {
                println!("  {}🔄 RELAY WALLET{}", yellow, reset);
                println!("  Address:      {}", hex::encode(pk_hash));
                println!("  Reward:       3% relay pool");
            }
            NodeRole::LightClient => {
                println!("  {}💡 WALLET ACTIVE{}", yellow, reset);
                println!("  Address:      {}", hex::encode(pk_hash));
            }
        }
    } else {
        match node_role {
            NodeRole::Miner => {
                println!();
                println!("  Mining:       INACTIVE (no wallet provided)");
            }
            NodeRole::Relay => {}
            NodeRole::LightClient => {}
        }
    }
    if !peers.is_empty() {
        println!("  Seed peers:   {}", peers.len());
    }
    println!();

    // Initialize blockchain with persistence
    let db_path = format!("{}/blockchain", data_dir);
    let mut blockchain = ShieldedBlockchain::open(&db_path, GENESIS_DIFFICULTY)?;

    // NOTE: Startup fork detection was removed in v1.3.4 — it caused false positives
    // when deploying to multiple nodes simultaneously (peers not yet ready → cumulative_work
    // mismatch → incorrectly wiped the chain). The post-mining fork check (comparing
    // cumulative_work after each mined block, see fork check section below) is sufficient
    // and doesn't have this race condition.

    // Fast sync: paginated block download from peers
    // Works for fresh nodes (height=0) AND nodes that are behind
    if fast_sync && !peers.is_empty() {
        let local_height = blockchain.height();
        // Check if any peer is ahead of us
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        // v1.4.0: Select sync peer by cumulative_work (heaviest chain), not just height.
        // Query /chain/info for work from each peer. Keep peers within 5% of max work.
        // v1.6.1: Select peers by HEIGHT only, not cumulative_work
        let mut eligible_peers: Vec<(String, u64)> = Vec::new(); // (url, height)
        let mut max_height = 0u64;
        for peer_url in &peers {
            let info_url = format!("{}/chain/info", peer_url);
            if let Ok(resp) = client.get(&info_url)
                .timeout(std::time::Duration::from_secs(10))
                .send().await
            {
                if let Ok(info) = resp.json::<serde_json::Value>().await {
                    let peer_height = info["height"].as_u64().unwrap_or(0);
                    if peer_height > local_height + 10 {
                        if peer_height > max_height {
                            max_height = peer_height;
                        }
                        eligible_peers.push((peer_url.clone(), peer_height));
                    }
                }
            }
        }
        // Keep only peers within 2 blocks of the highest
        eligible_peers.retain(|(_, h)| *h >= max_height.saturating_sub(2));
        // Random selection to distribute load across seeds
        use rand::seq::SliceRandom;
        let best_peer = eligible_peers.choose(&mut rand::thread_rng())
            .map(|(url, h)| (url.clone(), *h));

        if let Some((peer_url, peer_height)) = best_peer {
            let behind = peer_height - local_height;
            let start_time = std::time::Instant::now();

            // Strategy: if far behind (>100 blocks), use snapshot-based sync (instant)
            // Otherwise, use block-by-block trusted sync
            if behind > 50 {
                // ===== SNAPSHOT SYNC (instant) =====
                println!("Fast sync: {} blocks behind — downloading state snapshot...", behind);

                let snapshot_client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(600))
                    .build()?;

                // Get snapshot info
                let info_url = format!("{}/snapshot/info", peer_url);
                let mut snapshot_ok = false;

                if let Ok(resp) = snapshot_client.get(&info_url).send().await {
                    if let Ok(info) = resp.json::<serde_json::Value>().await {
                        if info["available"].as_bool() == Some(true) {
                            let snap_height = info["height"].as_u64().unwrap_or(0);
                            let snap_hash_str = info["block_hash"].as_str().unwrap_or("");
                            let snap_size = info["size_bytes"].as_u64().unwrap_or(0);
                            println!("  Snapshot available: height={}, size={}KB", snap_height, snap_size / 1024);

                            // Download compressed snapshot
                            let dl_url = format!("{}/snapshot/download", peer_url);
                            if let Ok(resp) = snapshot_client.get(&dl_url).send().await {
                                if resp.status().is_success() {
                                    let compressed = resp.bytes().await?;
                                    println!("  Downloaded {}KB compressed", compressed.len() / 1024);

                                    // Decompress
                                    use std::io::Read;
                                    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
                                    let mut json_data = Vec::new();
                                    if decoder.read_to_end(&mut json_data).is_ok() {
                                        // Parse snapshot
                                        if let Ok(snapshot) = serde_json::from_slice::<tsn::core::StateSnapshotPQ>(&json_data) {
                                            // Parse block hash
                                            let mut block_hash = [0u8; 32];
                                            if let Ok(hash_bytes) = hex::decode(snap_hash_str) {
                                                if hash_bytes.len() == 32 {
                                                    block_hash.copy_from_slice(&hash_bytes);
                                                }
                                            }

                                            // Get difficulty, next_difficulty AND cumulative_work from peer
                                            let (difficulty, next_diff, peer_work) = if let Ok(resp) = client.get(&format!("{}/chain/info", peer_url)).send().await {
                                                let info = resp.json::<serde_json::Value>().await.ok();
                                                let d = info.as_ref().and_then(|i| i["difficulty"].as_u64()).unwrap_or(GENESIS_DIFFICULTY);
                                                let nd = info.as_ref().and_then(|i| i["next_difficulty"].as_u64()).unwrap_or(d);
                                                let w = info.as_ref().and_then(|i| i["cumulative_work"].as_u64()).unwrap_or(0);
                                                (d, nd, w as u128)
                                            } else {
                                                (GENESIS_DIFFICULTY, GENESIS_DIFFICULTY, 0u128)
                                            };

                                            // Import snapshot — sets chain state instantly
                                            blockchain.import_snapshot_at_height(snapshot, snap_height, block_hash, difficulty, next_diff, peer_work);

                                            // Now sync only recent blocks (from snapshot height onward)
                                            println!("  Syncing recent blocks...");
                                            let mut synced = 0u64;
                                            let mut current = snap_height;
                                            loop {
                                                let url = format!("{}/blocks/since/{}", peer_url, current);
                                                match client.get(&url).send().await {
                                                    Ok(resp) if resp.status().is_success() => {
                                                        match resp.json::<Vec<serde_json::Value>>().await {
                                                            Ok(blocks) if !blocks.is_empty() => {
                                                                let count = blocks.len() as u64;
                                                                for bv in &blocks {
                                                                    if let Ok(block) = serde_json::from_value::<tsn::core::ShieldedBlock>(bv.clone()) {
                                                                        let _ = blockchain.add_block_trusted(block);
                                                                    }
                                                                }
                                                                current = blockchain.height();
                                                                synced += count;
                                                                if count < 50 { break; }
                                                            }
                                                            _ => break,
                                                        }
                                                    }
                                                    _ => break,
                                                }
                                            }

                                            let elapsed = start_time.elapsed().as_secs_f64();
                                            println!("  ✓ State restored at height {} + {} recent blocks in {:.1}s",
                                                snap_height, synced, elapsed);
                                            snapshot_ok = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if !snapshot_ok {
                    println!("  Snapshot unavailable — falling back to block sync...");
                }

                // Fall through to block sync if snapshot failed
                if !snapshot_ok {
                    println!("  Block-by-block sync (trusted)...");
                    let mut current_height = local_height;
                    let mut total = 0u64;
                    loop {
                        let prev_height = current_height;
                        let url = format!("{}/blocks/since/{}", peer_url, current_height);
                        match client.get(&url).send().await {
                            Ok(resp) if resp.status().is_success() => {
                                match resp.json::<Vec<serde_json::Value>>().await {
                                    Ok(blocks) if !blocks.is_empty() => {
                                        let n = blocks.len() as u64;
                                        for bv in &blocks {
                                            if let Ok(block) = serde_json::from_value::<tsn::core::ShieldedBlock>(bv.clone()) {
                                                let _ = blockchain.add_block_trusted(block);
                                            }
                                        }
                                        current_height = blockchain.height();
                                        total += n;
                                        if total % 500 == 0 || n < 50 {
                                            let e = start_time.elapsed().as_secs_f64();
                                            println!("  {} blocks — height: {} / {} — {:.0} b/s", total, current_height, peer_height, total as f64 / e);
                                        }
                                        // Break if no progress (prevents infinite loop)
                                        if current_height == prev_height { break; }
                                        if n < 50 { break; }
                                    }
                                    _ => break,
                                }
                            }
                            _ => break,
                        }
                    }
                    let elapsed = start_time.elapsed().as_secs_f64();
                    println!("  Fallback sync: {} blocks in {:.1}s", total, elapsed);
                }
            } else if behind > 10 {
                // ===== SMALL GAP: block-by-block trusted sync =====
                println!("Syncing {} blocks from {} (trusted)...", behind, peer_id(&peer_url));
                let mut current_height = local_height;
                let mut total = 0u64;
                loop {
                    let prev_height = current_height;
                    let url = format!("{}/blocks/since/{}", peer_url, current_height);
                    match client.get(&url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            match resp.json::<Vec<serde_json::Value>>().await {
                                Ok(blocks) if !blocks.is_empty() => {
                                    let n = blocks.len() as u64;
                                    for bv in &blocks {
                                        if let Ok(block) = serde_json::from_value::<tsn::core::ShieldedBlock>(bv.clone()) {
                                            let _ = blockchain.add_block_trusted(block);
                                        }
                                    }
                                    current_height = blockchain.height();
                                    total += n;
                                    if total % 500 == 0 || n < 50 {
                                        let e = start_time.elapsed().as_secs_f64();
                                        println!("  {} blocks — height: {} / {} — {:.0} b/s", total, current_height, peer_height, total as f64 / e);
                                    }
                                    if current_height == prev_height { break; }
                                    if n < 50 { break; }
                                }
                                _ => break,
                            }
                        }
                        _ => break,
                    }
                }
                let elapsed = start_time.elapsed().as_secs_f64();
                println!("  Synced {} blocks in {:.1}s", total, elapsed);
            }
        } else {
            println!("Node synced (height: {})", local_height);
        }
    }

    let mempool = Mempool::new();

    // Load Circom verification keys for proof verification
    println!();
    println!("Loading Circom verification keys...");

    // Look for verification keys in circuits/keys/ (committed) first, then circuits/build/ (local dev)
    let (spend_vkey_path, output_vkey_path) = find_verification_keys()?;

    println!("  Loading {}...", spend_vkey_path);
    println!("  Loading {}...", output_vkey_path);

    let verifying_params = CircomVerifyingParams::from_files(&spend_vkey_path, &output_vkey_path)
        .map_err(|e| anyhow::anyhow!("Failed to load verification keys: {}", e))?;

    blockchain.set_verifying_params(Arc::new(verifying_params));
    println!("  ZK proof verification ENABLED (Circom/snarkjs)");

    // Show assume-valid checkpoint status
    let assume_valid_height = blockchain.assume_valid_height();
    if assume_valid_height > 0 {
        println!("  Assume-valid checkpoint: height {} (proofs skipped during sync)", assume_valid_height);
    } else {
        println!("  Assume-valid: DISABLED (full proof verification from genesis)");
    }
    println!();

    // Initialize faucet if wallet provided
    let faucet_service = if let Some(faucet_path) = &faucet_wallet {
        let faucet_wlt = ShieldedWallet::load(faucet_path)?;
        let pk_hash = faucet_wlt.pk_hash();
        let faucet_pk_hash_hex = hex::encode(pk_hash);
        println!("Faucet enabled: {} (pk_hash)", &faucet_pk_hash_hex[..16]);

        // Extract keypair for signing
        let keypair = faucet_wlt.keypair().clone();

        // Open database for faucet claims
        let db = Arc::new(Database::open(&format!("{}/faucet", data_dir))?);

        let service = if let Some(limit) = faucet_daily_limit {
            let limit_base = limit * 1_000_000_000; // Convert TSN to base units
            println!("  Daily limit: {} TSN", limit);
            FaucetService::with_limits(keypair, pk_hash, db, limit_base, 86400)
        } else {
            println!("  Daily limit: 50 TSN (default)");
            FaucetService::new(keypair, pk_hash, db)
        };

        Some(TokioRwLock::new(service))
    } else {
        None
    };

    // Shared HTTP client for all outbound requests — prevents FD leaks from per-request clients
    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(5)
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let state = Arc::new(AppState {
        blockchain: RwLock::new(blockchain),
        mempool: RwLock::new(mempool),
        peers: RwLock::new(peers.clone()),
        miner_stats: RwLock::new(MinerStats::default()),
        faucet: faucet_service,
        sync_gate: tsn::network::SyncGate::new(),
        public_url: public_url.clone(),
        p2p_broadcast: RwLock::new(None),
        p2p_peer_id: RwLock::new(None),
        node_role: format!("{}", node_role),
        mining_cancel: RwLock::new(None),
        http_client,
        last_reorg_height: std::sync::atomic::AtomicU64::new(0),
        snapshot_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(3)),
        snapshot_cache: tokio::sync::RwLock::new(None),
        orphan_count: std::sync::atomic::AtomicU64::new(0),
        reorg_count: std::sync::atomic::AtomicU64::new(0),
        reorg_lock: tokio::sync::RwLock::new(()),
        banned_peers: std::sync::RwLock::new(std::collections::HashMap::new()),
        error_log: std::sync::RwLock::new(Vec::new()),
        auto_heal_mode: std::sync::RwLock::new("validation".to_string()),
    });

    // ========================================================================
    // CHECKPOINT VALIDATION AT STARTUP
    // If our chain doesn't match hardcoded checkpoints, rollback and re-sync.
    // ========================================================================
    {
        let chain = state.blockchain.read().unwrap();
        let local_height = chain.height();
        let mut violations = Vec::new();
        for &(cp_height, cp_hash) in crate::config::HARDCODED_CHECKPOINTS {
            if cp_height <= local_height {
                if let Some(actual_hash) = chain.get_hash_at_height(cp_height) {
                    let actual_hex = hex::encode(actual_hash);
                    // Skip placeholder hashes (fast-synced blocks before base)
                    if actual_hex != "0".repeat(64) && actual_hex != cp_hash {
                        violations.push((cp_height, cp_hash.to_string(), actual_hex));
                    }
                }
            }
        }
        if !violations.is_empty() {
            drop(chain);
            let lowest = violations.iter().map(|(h, _, _)| *h).min().unwrap();
            for (h, expected, actual) in &violations {
                tracing::error!(
                    "CHECKPOINT MISMATCH at height {}: expected {}, got {}",
                    h, &expected[..16], &actual[..16]
                );
            }
            tracing::warn!(
                "Chain is on a fork! Rolling back to height {} to re-sync from peers.",
                lowest.saturating_sub(1)
            );
            let rollback_target = lowest.saturating_sub(1);
            let mut chain = state.blockchain.write().unwrap();
            // Bypass MAX_REORG_DEPTH for checkpoint-forced rollback
            if local_height - rollback_target <= ShieldedBlockchain::MAX_REORG_DEPTH {
                let _ = chain.rollback_to_height(rollback_target);
            } else {
                // Too deep to rollback — wipe data and force fresh fast-sync
                tracing::error!(
                    "Checkpoint violation too deep ({} blocks). Wiping chain for fresh sync.",
                    local_height - rollback_target
                );
                drop(chain);
                let db_path = format!("{}/blockchain", data_dir);
                let _ = std::fs::remove_dir_all(&db_path);
                // Re-open empty blockchain
                let fresh = ShieldedBlockchain::open(&db_path, 1_500_000)
                    .expect("Failed to create fresh blockchain");
                *state.blockchain.write().unwrap() = fresh;
            }
        }
    }

    // Create router with API (wallet and explorer are served from static React app)
    let app = create_router(state.clone());

    // Build our own URL for peer announcements
    let our_url = public_url.unwrap_or_else(|| format!("http://localhost:{}", port));
    println!("Announcing as:  {}", our_url);

    // Start HTTP API server FIRST (non-blocking — explorer and wallet need this immediately)
    let api_port = port;
    let api_app = app;
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", api_port)).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("FATAL: Cannot bind port {}: {}", api_port, e);
                std::process::exit(1);
            }
        };
        tracing::info!("HTTP API listening on port {}", api_port);
        if let Err(e) = axum::serve(listener, api_app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await {
            eprintln!("HTTP server error: {}", e);
        }
    });

    // Start Prometheus metrics server on port 9090
    {
        let config = tsn::metrics::http_endpoint::MetricsServerConfig {
            port: 9090,
            bind_address: "0.0.0.0".to_string(),
            enable_cors: true,
        };
        match tsn::metrics::http_endpoint::start_metrics_server(config).await {
            Ok(_handle) => println!("Metrics server:  http://0.0.0.0:9090/metrics"),
            Err(e) => tracing::error!("Failed to start metrics server: {}", e),
        }
    }

    // Start version checker — blocks mining if node is outdated
    tokio::spawn(async {
        tsn::network::version_check::version_check_loop().await;
    });

    // Start auto-update loop — checks for new versions and self-updates
    tokio::spawn(async {
        tsn::network::auto_update::auto_update_loop().await;
    });

    // ========================================================================
    // SELF-HEALING WATCHDOG — monitors node health and auto-repairs
    // ========================================================================
    {
        let watchdog_state = state.clone();
        tokio::spawn(async move {
            let mut last_height: u64 = 0;
            let mut stuck_since: Option<std::time::Instant> = None;
            let mut resync_count: u32 = 0;
            let mut resync_window_start = std::time::Instant::now();
            let mut error_count: u32 = 0;

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;

                let current_height = {
                    let chain = watchdog_state.blockchain.read().unwrap();
                    chain.height()
                };

                // Reset resync counter every 5 minutes
                if resync_window_start.elapsed() > std::time::Duration::from_secs(300) {
                    resync_count = 0;
                    resync_window_start = std::time::Instant::now();
                }

                // Check auto_heal_mode
                let is_auto = *watchdog_state.auto_heal_mode.read().unwrap() == "automatic";

                // Check 1: All peers banned → clear bans (always auto, even in validation mode)
                {
                    let peers = watchdog_state.peers.read().unwrap();
                    let bans = watchdog_state.banned_peers.read().unwrap();
                    let now = std::time::Instant::now();
                    let active_bans = bans.values().filter(|t| now < **t).count();
                    if !peers.is_empty() && active_bans >= peers.len() {
                        drop(bans);
                        drop(peers);
                        tracing::warn!("WATCHDOG: All peers banned! Clearing ban list.");
                        tsn::network::log_node_error(&watchdog_state, "all_peers_banned", "All peers were banned, clearing ban list");
                        let mut bans = watchdog_state.banned_peers.write().unwrap();
                        bans.clear();
                    }
                }

                // Check 2: Height stagnant for 5+ minutes while peers exist
                if current_height > last_height {
                    last_height = current_height;
                    stuck_since = None;
                    error_count = 0;
                } else {
                    let peers_exist = !watchdog_state.peers.read().unwrap().is_empty();
                    if peers_exist {
                        if stuck_since.is_none() {
                            stuck_since = Some(std::time::Instant::now());
                        }
                        if let Some(since) = stuck_since {
                            if since.elapsed() > std::time::Duration::from_secs(300) {
                                let msg = format!("Height stuck at {} for 5+ min", current_height);
                                tracing::warn!("WATCHDOG: {}. Triggering snapshot re-sync.", msg);
                                tsn::network::log_node_error(&watchdog_state, "stuck_height", &msg);
                                if is_auto {
                                    let mut chain = watchdog_state.blockchain.write().unwrap();
                                    chain.reset_for_snapshot_resync();
                                } else {
                                    tracing::info!("WATCHDOG: Mode validation — action proposée, en attente d'approbation via /admin/force-resync");
                                }
                                stuck_since = None;
                                resync_count += 1;
                                last_height = 0;
                            }
                        }
                    }
                }

                // Check 3: Too many resyncs in short window → wipe completely
                if resync_count >= 3 {
                    let msg = format!("{} resyncs in 5 min — chain is unstable", resync_count);
                    tracing::error!("WATCHDOG: {}.", msg);
                    tsn::network::log_node_error(&watchdog_state, "resync_loop", &msg);
                    if is_auto {
                        tracing::warn!("WATCHDOG: Auto mode — full wipe + fresh sync.");
                        let mut chain = watchdog_state.blockchain.write().unwrap();
                        chain.reset_for_snapshot_resync();
                        let mut bans = watchdog_state.banned_peers.write().unwrap();
                        bans.clear();
                    } else {
                        tracing::warn!("WATCHDOG: Validation mode — action required: POST /admin/force-resync");
                    }
                    resync_count = 0;
                    last_height = 0;
                    stuck_since = None;
                }

                // Check 4: Verify checkpoints periodically (every 5 min)
                {
                    let chain = watchdog_state.blockchain.read().unwrap();
                    for &(cp_height, cp_hash) in crate::config::HARDCODED_CHECKPOINTS {
                        if cp_height <= chain.height() {
                            if let Some(actual) = chain.get_hash_at_height(cp_height) {
                                let actual_hex = hex::encode(actual);
                                if actual_hex != "0".repeat(64) && actual_hex != cp_hash {
                                    let msg = format!("Checkpoint violation at height {}", cp_height);
                                    tracing::error!("WATCHDOG: {}! Re-syncing.", msg);
                                    tsn::network::log_node_error(&watchdog_state, "checkpoint_violation", &msg);
                                    drop(chain);
                                    // Always auto for checkpoint violations — chain is on wrong fork
                                    let mut chain_w = watchdog_state.blockchain.write().unwrap();
                                    chain_w.reset_for_snapshot_resync();
                                    let mut bans = watchdog_state.banned_peers.write().unwrap();
                                    bans.clear();
                                    last_height = 0;
                                    stuck_since = None;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    // Sync from peers in background (non-blocking — API is already running)
    if !peers.is_empty() {
        println!("Peers: [{}]", peers.iter().map(|p| peer_id(p)).collect::<Vec<_>>().join(", "));

        let sync_state_init = state.clone();
        let sync_peers_init = peers.clone();
        let sync_our_url = our_url.clone();
        tokio::spawn(async move {
            let http_client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default();

            for peer in &sync_peers_init {
                let announce_url = format!("{}/peers", peer.trim_end_matches('/'));
                let _ = http_client.post(&announce_url)
                    .json(&serde_json::json!({ "url": sync_our_url }))
                    .send()
                    .await;

                match sync_from_peer(sync_state_init.clone(), peer).await {
                    Ok(n) if n > 0 => tracing::info!("Synced {} blocks from {}", n, peer_id(peer)),
                    Ok(_) => {}
                    Err(e) => tracing::debug!("Sync from {} failed: {}", peer_id(peer), e),
                }
            }
        });

        // Start background sync loop (HTTP fallback — checks every 30 seconds)
        let sync_state = state.clone();
        let sync_peers = state.peers.read().unwrap().clone();
        tokio::spawn(async move {
            sync_loop(sync_state, sync_peers, 10).await;
        });

        // Start peer discovery loop (checks every 60 seconds)
        let discovery_state = state.clone();
        tokio::spawn(async move {
            discovery_loop(discovery_state).await;
        });

        // Start libp2p P2P layer — PRIMARY block/tx propagation
        // GossipSub pushes blocks instantly to all connected peers (including NAT)
        // HTTP sync loop kept as temporary fallback for non-upgraded nodes
        {
            use tsn::network::p2p::{P2pConfig, P2pNode, P2pEvent, seeds_to_bootstrap};
            use tracing::{info, warn, debug};

            let p2p_port = port + 1; // P2P on next port (e.g. 9334 if HTTP is 9333)
            let seed_urls = state.peers.read().unwrap().clone();

            // Convert HTTP seed URLs to P2P multiaddrs (IP:p2p_port)
            let dial_seeds = seeds_to_bootstrap(&seed_urls, p2p_port);
            info!("P2P: dialing {} seed nodes on port {}", dial_seeds.len(), p2p_port);

            let p2p_config = P2pConfig {
                listen_port: p2p_port,
                bootstrap_peers: Vec::new(),
                dial_seeds,
                relay_server: node_role == NodeRole::Miner,
                // Use actual mining status for protocol role (not node_role which defaults to miner)
                protocol_version: format!("tsn/{}/{}", env!("CARGO_PKG_VERSION"),
                    if miner_info.is_some() && node_role == NodeRole::Miner { "miner" }
                    else if node_role == NodeRole::LightClient { "light" }
                    else { "relay" }),
            };

            let p2p = P2pNode::start(p2p_config).await
                .expect("FATAL: P2P layer failed to start — node cannot propagate blocks");

            println!();
            println!("  ╔═══════════════════════════════════════════╗");
            println!("  ║  Node ID: {}  ║", &p2p.peer_id.to_string()[..38]);
            println!("  ╚═══════════════════════════════════════════╝");
            println!("  Full PeerID: {}", p2p.peer_id);
            println!("  P2P port:    {}", p2p_port);

            // Store PeerID in AppState for /node/info endpoint
            {
                let mut pid = state.p2p_peer_id.write().unwrap();
                *pid = Some(p2p.peer_id.to_string());
            }

            let p2p_peer_id = p2p.peer_id;
            let p2p_command_tx = p2p.command_tx.clone();

            // Store P2P command sender in AppState for use by miner and API
            // (used to broadcast mined blocks and submitted transactions)
            {
                let mut p2p_tx = state.p2p_broadcast.write().unwrap();
                *p2p_tx = Some(p2p.command_tx.clone());
            }

            // Shared cancel signal: P2P handler sets this when a new block arrives,
            // causing the miner to immediately abort and restart on the new tip.
            let mining_cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
            {
                let mut mc = state.mining_cancel.write().unwrap();
                *mc = Some(Arc::clone(&mining_cancel));
            }

            // Spawn task to handle incoming P2P events
            let p2p_blockchain = state.clone();
            let p2p_cancel = Arc::clone(&mining_cancel);
            let mut p2p_events = p2p.event_rx;
            tokio::spawn(async move {
                while let Some(event) = p2p_events.recv().await {
                    match event {
                        P2pEvent::NewBlock(data) => {
                            match serde_json::from_slice::<tsn::core::ShieldedBlock>(&data) {
                                Ok(block) => {
                                    let height = block.coinbase.height;
                                    let result = {
                                        let mut chain = p2p_blockchain.blockchain.write().unwrap();
                                        chain.try_add_block(block)
                                    };
                                    match result {
                                        Ok(true) => {
                                            info!("P2P: new block #{} accepted", height);
                                            // Signal miner to cancel and restart on new tip
                                            p2p_cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                                        }
                                        Ok(false) => {
                                            // Stored as orphan or side chain — trigger sync but do NOT cancel mining.
                                            // Mining continues on current tip. If sync changes our tip,
                                            // the block acceptance handler above (Ok(true)) will cancel mining.
                                            let local_height = p2p_blockchain.blockchain.read().unwrap().height();
                                            tracing::info!("P2P: block #{} stored as orphan (local: {}), triggering sync", height, local_height);
                                            let sync_state = p2p_blockchain.clone();
                                            let sync_peers = p2p_blockchain.peers.read().unwrap().clone();
                                            tokio::spawn(async move {
                                                for peer in &sync_peers {
                                                    match tsn::network::sync_from_peer(sync_state.clone(), peer).await {
                                                        Ok(n) if n > 0 => {
                                                            tracing::info!("Orphan sync: got {} blocks from {}", n, tsn::network::peer_id(peer));
                                                            break;
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            });
                                        }
                                        Err(e) => tracing::debug!("P2P: block #{} rejected: {}", height, e),
                                    }
                                }
                                Err(e) => tracing::debug!("P2P: invalid block data: {}", e),
                            }
                        }
                        P2pEvent::NewTransaction(data) => {
                            // Add received transaction to mempool
                            if let Ok(tx) = serde_json::from_slice::<tsn::core::ShieldedTransactionV2>(&data) {
                                let mut mempool = p2p_blockchain.mempool.write().unwrap();
                                let wrapped = tsn::core::Transaction::V2(tx);
                                mempool.add_v2(wrapped);
                            }
                        }
                        P2pEvent::PeerConnected(peer) => {
                            debug!("P2P: peer {} connected", peer);
                        }
                        P2pEvent::PeerDisconnected(peer) => {
                            debug!("P2P: peer {} disconnected", peer);
                        }
                        P2pEvent::NatStatus(status) => {
                            info!("P2P: NAT status = {}", status);
                        }
                    }
                }
            });
        }
    }

    // Start tip broadcast loop (announces local tip to peers every 30 seconds)
    {
        let tip_state = state.clone();
        let tip_our_url = our_url.clone();
        let tip_local_url = format!("http://localhost:{}", port);
        let tip_local_ip_url = format!("http://127.0.0.1:{}", port);
        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;

                let (height, hash) = {
                    let chain = tip_state.blockchain.read().unwrap();
                    (chain.height(), hex::encode(chain.latest_hash()))
                };

                let mut peers = tip_state.peers.read().unwrap().clone();
                peers.retain(|p| p != &tip_our_url && p != &tip_local_url && p != &tip_local_ip_url);

                for peer in &peers {
                    let url = format!("{}/tip", peer);
                    let body = serde_json::json!({ "height": height, "hash": hash });
                    match client.post(&url).header("X-TSN-Version", env!("CARGO_PKG_VERSION")).json(&body).send().await {
                        Ok(resp) => {
                            if let Ok(tip_resp) = resp.json::<serde_json::Value>().await {
                                // Update sync gate with peer's tip
                                if let (Some(peer_height), Some(peer_hash)) = (
                                    tip_resp.get("height").and_then(|v| v.as_u64()),
                                    tip_resp.get("hash").and_then(|v| v.as_str()),
                                ) {
                                    if let Ok(hash_bytes) = hex::decode(peer_hash) {
                                        if hash_bytes.len() == 32 {
                                            let mut arr = [0u8; 32];
                                            arr.copy_from_slice(&hash_bytes);
                                            tip_state.sync_gate.update_tip(peer, peer_height, arr);
                                        }
                                    }
                                }
                            }
                        }
                        Err(_) => {} // Peer unreachable, skip silently
                    }
                }
            }
        });
    }

    // Scan blockchain for faucet notes if enabled
    if state.faucet.is_some() {
        println!("Scanning blockchain for faucet notes...");

        // Do initial scan in a blocking task to avoid blocking the async runtime
        let scan_state = state.clone();
        let (new_notes, balance) = tokio::task::spawn_blocking(move || {
            let blockchain = scan_state.blockchain.read().unwrap();
            let current_height = blockchain.height();

            // Collect blocks into a vec to avoid borrowing issues
            let blocks: Vec<_> = (0..=current_height)
                .filter_map(|h| blockchain.get_block_by_height(h))
                .collect();
            drop(blockchain);

            if let Some(ref faucet) = scan_state.faucet {
                let mut faucet_guard = faucet.blocking_write();

                let get_block = |height: u64| -> Option<ShieldedBlock> {
                    blocks.get(height as usize).cloned()
                };

                let new_notes = faucet_guard.scan_blockchain(get_block, current_height);
                let balance = faucet_guard.balance();
                (new_notes, balance)
            } else {
                (0, 0)
            }
        }).await.unwrap_or((0, 0));

        if new_notes > 0 {
            println!("  Found {} faucet notes, balance: {} TSN", new_notes, balance / 1_000_000_000);
        } else {
            println!("  No faucet notes found (balance: {} TSN)", balance / 1_000_000_000);
        }

        // Start background faucet scanning task (every 30 seconds)
        let faucet_scan_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;

                let scan_state = faucet_scan_state.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Some(ref faucet) = scan_state.faucet {
                        let blockchain = scan_state.blockchain.read().unwrap();
                        let current_height = blockchain.height();

                        let mut faucet_guard = faucet.blocking_write();
                        let last_scanned = faucet_guard.last_scanned_height();

                        // Only scan if there are new blocks
                        if current_height > last_scanned {
                            // Collect only new blocks
                            let blocks: Vec<_> = ((last_scanned + 1)..=current_height)
                                .filter_map(|h| blockchain.get_block_by_height(h))
                                .collect();
                            drop(blockchain);

                            let get_block = |height: u64| -> Option<ShieldedBlock> {
                                let idx = height.saturating_sub(last_scanned + 1) as usize;
                                blocks.get(idx).cloned()
                            };

                            let _new_notes = faucet_guard.scan_blockchain(get_block, current_height);
                        }
                    }
                }).await;
            }
        });
    }

    // Role-specific behavior summary
    let mining_active = miner_info.is_some();
    match node_role {
        NodeRole::LightClient => {
            tracing::info!("Light client mode: syncing headers only, skipping full block storage");
            println!("Mode: LIGHT CLIENT — header-only sync, minimal storage");
        }
        NodeRole::Relay => {
            tracing::info!("Relay mode: storing and relaying full blocks, mining disabled");
            println!("Mode: RELAY — full block relay, no mining");
        }
        NodeRole::Miner => {
            if !mining_active {
                tracing::info!("Miner mode: full node (no --mine wallet provided, mining inactive)");
            } else {
                tracing::info!("Miner mode: full node with active mining");
            }
        }
    }

    // Start integrated miner (ONLY for miner role — relay/light have wallets but don't mine)
    let mining_wallet = if node_role.can_mine() { miner_info } else { None };
    if let Some((miner_pk_hash, viewing_key)) = mining_wallet {
        if force_mine {
            println!("Force mining enabled - skipping sync verification");
        } else {
            println!("Waiting for initial sync before mining...");
            wait_for_initial_sync(state.clone(), 300).await?;
        }

        let jobs = jobs.max(1);
        let mine_state = state.clone();
        let mine_wallet_path = mine_wallet.clone();
        let announce_url = our_url.clone();
        let local_url = format!("http://localhost:{}", port);
        let local_ip_url = format!("http://127.0.0.1:{}", port);
        if let Some(simd) = simd {
            println!("SIMD mode: {:?}", simd);
        }
        let pool = Arc::new(MiningPool::new_with_simd(jobs, simd));

        tokio::spawn(async move {
            let client = mine_state.http_client.clone();
            println!("Starting integrated miner...");
            println!("Mining threads: {}", jobs);
            {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut stats = mine_state.miner_stats.write().unwrap();
                stats.is_mining = true;
                stats.last_updated = now;
            }

            let mut unaccepted_count: u32 = 0;
            let mut resync_attempts: u32 = 0;
            let mut last_resync_height: u64 = 0;
            // Auto-resync stuck detection
            let mut stuck_last_height: u64 = 0;
            let mut stuck_consecutive: u32 = 0;

            loop {
                // Post-reorg cooldown: wait once for network to stabilize before mining
                {
                    let last_reorg = mine_state.last_reorg_height.load(std::sync::atomic::Ordering::Relaxed);
                    if last_reorg > 0 {
                        tracing::info!("Post-reorg cooldown: waiting 3s after reorg at height {}", last_reorg);
                        // Reset immediately so we only wait ONCE per reorg
                        mine_state.last_reorg_height.store(0, std::sync::atomic::Ordering::Relaxed);
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        continue;
                    }
                }

                // Version gate: refuse to mine if node is outdated
                if !tsn::network::version_check::is_version_ok() {
                    tracing::warn!(
                        "Mining PAUSED — node version {} is below network minimum. Please upgrade!",
                        tsn::network::version_check::LOCAL_VERSION
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    continue;
                }

                // Sync gate: pause mining if too far behind VERIFIED peers
                // v1.3.3: only consider peers whose height we can verify via HTTP /tip
                // (gossip tips can come from fork chains and are unreliable)
                if !force_mine {
                    let local_height = mine_state.blockchain.read().unwrap().height();
                    let sync_client = mine_state.http_client.clone();
                    let peers_list = mine_state.peers.read().unwrap().clone();

                    // Query ACTUAL peer heights via HTTP (not gossip)
                    let mut verified_max_height: u64 = 0;
                    for peer in &peers_list {
                        let tip_url = format!("{}/tip", peer);
                        if let Ok(resp) = sync_client.get(&tip_url)
                            .timeout(std::time::Duration::from_secs(3))
                            .send().await
                        {
                            if let Ok(tip) = resp.json::<serde_json::Value>().await {
                                let h = tip["height"].as_u64().unwrap_or(0);
                                // Fix 5: skip peers at height 0
                                if h > 0 && h > verified_max_height {
                                    verified_max_height = h;
                                }
                            }
                        }
                    }

                    // Fix 3: only pause if verified peers are actually ahead
                    // (gossip network_tip is ignored — it can be from fork chains)
                    let gap = verified_max_height.saturating_sub(local_height);
                    if verified_max_height == 0 || gap <= 2 {
                        // Synced or no peers — reset backoff for next time
                        if resync_attempts > 0 {
                            resync_attempts = 0;
                            last_resync_height = 0;
                        }
                    } else if gap > 2 {
                        tracing::info!(
                            "Behind verified peers (local: {}, verified tip: {}, gap: {}). Waiting for sync...",
                            local_height, verified_max_height, gap
                        );

                        // Fix 2: exponential backoff (30s base, up to 300s)
                        let backoff_secs = std::cmp::min(30u64 * 2u64.pow(resync_attempts.min(4)), 300);
                        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;

                        let fresh_height = mine_state.blockchain.read().unwrap().height();
                        let fresh_gap = verified_max_height.saturating_sub(fresh_height);

                        if fresh_height > local_height {
                            // Sync is making progress — reset backoff
                            resync_attempts = 0;
                        } else if fresh_gap > 2 {
                            resync_attempts += 1;

                            // Fix 1: only re-sync via snapshot if we haven't tried at same height
                            if fresh_height != last_resync_height && resync_attempts <= 3 {
                                last_resync_height = fresh_height;
                                tracing::warn!(
                                    "Still behind (local: {}, tip: {}). Attempting snapshot sync (attempt #{})...",
                                    fresh_height, verified_max_height, resync_attempts
                                );

                                // v1.4.0: Find best VERIFIED peer by cumulative_work.
                                // Require at least 2 peers agreeing (within 5% of max work) before resyncing.
                                let mut peer_infos: Vec<(String, u64, u128)> = Vec::new(); // (url, height, work)
                                for peer in &peers_list {
                                    let info_url = format!("{}/chain/info", peer);
                                    if let Ok(resp) = sync_client.get(&info_url)
                                        .timeout(std::time::Duration::from_secs(5))
                                        .send().await
                                    {
                                        if let Ok(info) = resp.json::<serde_json::Value>().await {
                                            let h = info["height"].as_u64().unwrap_or(0);
                                            let w = info["cumulative_work"].as_u64().unwrap_or(0) as u128;
                                            if h > fresh_height {
                                                peer_infos.push((peer.clone(), h, w));
                                            }
                                        }
                                    }
                                }
                                // v1.6.1: Select peer by HEIGHT only, not work
                                let max_h = peer_infos.iter().map(|(_, h, _)| *h).max().unwrap_or(0);
                                let agreeing: Vec<_> = peer_infos.iter()
                                    .filter(|(_, h, _)| *h >= max_h.saturating_sub(2))
                                    .collect();
                                let best: Option<(String, u64)> = if agreeing.len() >= 2 || (peer_infos.len() == 1 && !peer_infos.is_empty()) {
                                    agreeing.iter()
                                        .max_by_key(|(_, h, _)| *h)
                                        .map(|(url, h, _)| (url.clone(), *h))
                                } else {
                                    tracing::warn!(
                                        "Auto-resync: only {}/{} peers at max height — skipping resync",
                                        agreeing.len(), peer_infos.len()
                                    );
                                    None
                                };

                                if let Some((peer_url, _)) = best {
                                    let info_url = format!("{}/snapshot/info", peer_url);
                                    if let Ok(resp) = sync_client.get(&info_url).send().await {
                                        if let Ok(info) = resp.json::<serde_json::Value>().await {
                                            if info["available"].as_bool() == Some(true) {
                                                let snap_height = info["height"].as_u64().unwrap_or(0);
                                                // Fix 1: don't import snapshot at same or lower height
                                                // v1.3.3: also reject snapshots below highest hardcoded checkpoint
                                                let highest_cp = crate::config::HARDCODED_CHECKPOINTS.iter()
                                                    .map(|(h, _)| *h).max().unwrap_or(0);
                                                if snap_height > fresh_height && snap_height >= highest_cp {
                                                    let snap_hash_str = info["block_hash"].as_str().unwrap_or("");
                                                    let dl_url = format!("{}/snapshot/download", peer_url);
                                                    if let Ok(resp) = sync_client.get(&dl_url).send().await {
                                                        if let Ok(compressed) = resp.bytes().await {
                                                            use std::io::Read;
                                                            let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
                                                            let mut json_data = Vec::new();
                                                            if decoder.read_to_end(&mut json_data).is_ok() {
                                                                if let Ok(snapshot) = serde_json::from_slice::<tsn::core::StateSnapshotPQ>(&json_data) {
                                                                    let mut block_hash = [0u8; 32];
                                                                    if let Ok(bytes) = hex::decode(snap_hash_str) {
                                                                        if bytes.len() == 32 { block_hash.copy_from_slice(&bytes); }
                                                                    }
                                                                    let ci_url = format!("{}/chain/info", peer_url);
                                                                    let (diff, next_diff, peer_work) = if let Ok(r) = sync_client.get(&ci_url).send().await {
                                                                        let i = r.json::<serde_json::Value>().await.ok();
                                                                        let d = i.as_ref().and_then(|v| v["difficulty"].as_u64()).unwrap_or(1000);
                                                                        let nd = i.as_ref().and_then(|v| v["next_difficulty"].as_u64()).unwrap_or(d);
                                                                        let w = i.as_ref().and_then(|v| v["cumulative_work"].as_u64()).unwrap_or(0);
                                                                        (d, nd, w as u128)
                                                                    } else { (1000, 1000, 0u128) };

                                                                    let mut chain = mine_state.blockchain.write().unwrap();
                                                                    chain.import_snapshot_at_height(snapshot, snap_height, block_hash, diff, next_diff, peer_work);
                                                                    println!("Re-synced to height {} from network.", snap_height);
                                                                    resync_attempts = 0;
                                                                }
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    tracing::info!("Snapshot height {} <= local {}, skipping", snap_height, fresh_height);
                                                }
                                            }
                                        }
                                    }
                                }
                            } else if resync_attempts > 3 {
                                // After 3 failed attempts, give up re-syncing and mine anyway
                                tracing::warn!(
                                    "Re-sync stuck after {} attempts at height {}. Mining anyway.",
                                    resync_attempts, fresh_height
                                );
                                // Don't reset — will keep mining until sync catches up naturally
                            }
                            continue;
                        }
                    }
                }

                // Auto-resync: detect stuck node and trigger full wipe+resync
                if !force_mine {
                    let current_height = mine_state.blockchain.read().unwrap().height();
                    let sync_client = mine_state.http_client.clone();
                    let peers_list = mine_state.peers.read().unwrap().clone();

                    // v1.4.0: Compare cumulative_work for stuck detection (not just height)
                    if current_height > stuck_last_height {
                        // Node is making progress — reset stuck counter
                        stuck_consecutive = 0;
                        stuck_last_height = current_height;
                    } else if current_height == stuck_last_height {
                        // Same height as last check (including height 0) — query verified peers via /chain/info
                        let mut verified_max_height: u64 = 0;
                        let mut best_peer: Option<String> = None;
                        let mut _peer_max_work: u128 = 0;
                        let _local_work = mine_state.blockchain.read().unwrap().cumulative_work();
                        for peer in &peers_list {
                            let info_url = format!("{}/chain/info", peer);
                            if let Ok(resp) = sync_client.get(&info_url)
                                .timeout(std::time::Duration::from_secs(5))
                                .send().await
                            {
                                if let Ok(info) = resp.json::<serde_json::Value>().await {
                                    let h = info["height"].as_u64().unwrap_or(0);
                                    // v1.6.1: Select peer by height only
                                    if h > verified_max_height {
                                        verified_max_height = h;
                                        best_peer = Some(peer.clone());
                                    }
                                }
                            }
                        }

                        let gap = verified_max_height.saturating_sub(current_height);
                        if verified_max_height > 0 && gap > 50 {
                            stuck_consecutive += 1;
                            tracing::warn!(
                                "Stuck check #{}: node at height {}, peers at {} (gap {})",
                                stuck_consecutive, current_height, verified_max_height, gap
                            );

                            if stuck_consecutive >= 3 {
                                tracing::warn!(
                                    "Node stuck at height {} for {} checks, peers at {}. Auto-resyncing...",
                                    current_height, stuck_consecutive, verified_max_height
                                );

                                // v1.4.1: Do NOT wipe chain. Attempt snapshot sync WITHOUT wiping first.
                                // If snapshot is at a higher height with more work, import it on top.
                                // Wiping was the cause of catastrophic chain loss.
                                tracing::info!("Attempting snapshot sync without chain wipe...");

                                // Attempt snapshot sync from best peer
                                if let Some(peer_url) = best_peer {
                                    let info_url = format!("{}/snapshot/info", peer_url);
                                    if let Ok(resp) = sync_client.get(&info_url).send().await {
                                        if let Ok(info) = resp.json::<serde_json::Value>().await {
                                            if info["available"].as_bool() == Some(true) {
                                                let snap_height = info["height"].as_u64().unwrap_or(0);
                                                let highest_cp = crate::config::HARDCODED_CHECKPOINTS.iter()
                                                    .map(|(h, _)| *h).max().unwrap_or(0);
                                                if snap_height > 0 && snap_height >= highest_cp {
                                                    let snap_hash_str = info["block_hash"].as_str().unwrap_or("");
                                                    let dl_url = format!("{}/snapshot/download", peer_url);
                                                    if let Ok(resp) = sync_client.get(&dl_url).send().await {
                                                        if let Ok(compressed) = resp.bytes().await {
                                                            use std::io::Read;
                                                            let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
                                                            let mut json_data = Vec::new();
                                                            if decoder.read_to_end(&mut json_data).is_ok() {
                                                                if let Ok(snapshot) = serde_json::from_slice::<tsn::core::StateSnapshotPQ>(&json_data) {
                                                                    let mut block_hash = [0u8; 32];
                                                                    if let Ok(bytes) = hex::decode(snap_hash_str) {
                                                                        if bytes.len() == 32 { block_hash.copy_from_slice(&bytes); }
                                                                    }
                                                                    let ci_url = format!("{}/chain/info", peer_url);
                                                                    let (diff, next_diff, peer_work) = if let Ok(r) = sync_client.get(&ci_url).send().await {
                                                                        let i = r.json::<serde_json::Value>().await.ok();
                                                                        let d = i.as_ref().and_then(|v| v["difficulty"].as_u64()).unwrap_or(1000);
                                                                        let nd = i.as_ref().and_then(|v| v["next_difficulty"].as_u64()).unwrap_or(d);
                                                                        let w = i.as_ref().and_then(|v| v["cumulative_work"].as_u64()).unwrap_or(0);
                                                                        (d, nd, w as u128)
                                                                    } else { (1000, 1000, 0u128) };

                                                                    let mut chain = mine_state.blockchain.write().unwrap();
                                                                    chain.import_snapshot_at_height(snapshot, snap_height, block_hash, diff, next_diff, peer_work);
                                                                    tracing::info!("Auto-resync complete: jumped to height {} from peer {}", snap_height, peer_url);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                // Reset stuck tracking after resync attempt
                                stuck_consecutive = 0;
                                stuck_last_height = 0;
                                resync_attempts = 0;
                                last_resync_height = 0;
                                continue;
                            }
                        } else {
                            // Gap is small or no peers — not stuck
                            stuck_consecutive = 0;
                        }
                    } else {
                        // First check or height 0 — initialize tracking
                        stuck_last_height = current_height;
                    }
                }

                // Get mempool transactions (both V1 and V2)
                let (mempool_txs, mempool_txs_v2) = {
                    let mempool = mine_state.mempool.read().unwrap();
                    let v1 = mempool.get_transactions(100);
                    let all_v2 = mempool.get_shielded_v2_transactions(100);
                    drop(mempool);

                    // Filter V2 transactions: only include those with valid anchors
                    // This prevents invalid TX anchors from blocking mining
                    let chain = mine_state.blockchain.read().unwrap();
                    let v2: Vec<_> = all_v2.into_iter().filter(|tx| {
                        tx.spends.iter().all(|spend| chain.state().is_valid_anchor_pq(&spend.anchor))
                    }).collect();
                    drop(chain);

                    if !v2.is_empty() {
                        println!("  Including {} V2 transactions in block template", v2.len());
                    }
                    (v1, v2)
                };

                // Minimum block interval: wait until enough time has passed since last block.
                // This is critical: ensures ~8-10s between blocks regardless of hashrate.
                // Without this, fast miners find blocks in <1s and fork before propagation.
                {
                    let min_interval = crate::config::MIN_BLOCK_INTERVAL_SECS;
                    let wait_secs = {
                        let chain = mine_state.blockchain.read().unwrap();
                        let tip_height = chain.height();
                        if tip_height > 0 {
                            if let Some(prev_block) = chain.get_block_by_height(tip_height) {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                let earliest = prev_block.header.timestamp + min_interval;
                                if now < earliest { earliest - now } else { 0 }
                            } else { 0 }
                        } else { 0 }
                    };
                    if wait_secs > 0 {
                        tracing::info!("Waiting {}s for minimum block interval ({}s required)", wait_secs, min_interval);
                        tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;
                    }
                }

                // Acquire reorg READ lock — blocks if a rollback is in progress
                let _reorg_read = mine_state.reorg_lock.read().await;

                // Create block template with both V1 and V2 transactions
                let mut block = {
                    let chain = mine_state.blockchain.read().unwrap();
                    chain.create_block_template_with_v2(miner_pk_hash, &viewing_key, mempool_txs, mempool_txs_v2)
                };
                // Save the prev_hash to detect stale blocks after PoW
                let template_prev_hash = block.header.prev_hash;

                // Drop reorg lock during PoW (cancel signal handles abort)
                drop(_reorg_read);

                let (height, difficulty) = {
                    let chain = mine_state.blockchain.read().unwrap();
                    (chain.height() + 1, block.header.difficulty)
                };

                let v2_count = block.transactions_v2.len();
                if v2_count > 0 {
                    println!("Mining block {} (difficulty: {}, V2 txs: {})...", height, difficulty, v2_count);
                } else {
                    println!("Mining block {} (difficulty: {})...", height, difficulty);
                }

                // Get or create the mining cancel signal
                let cancel_signal = {
                    let mc = mine_state.mining_cancel.read().unwrap();
                    mc.clone().unwrap_or_else(|| Arc::new(std::sync::atomic::AtomicBool::new(false)))
                };
                // Reset cancel before starting mining
                if cancel_signal.load(std::sync::atomic::Ordering::Relaxed) {
                    tracing::debug!("MINING_CANCEL=false reason=mining_cycle_start");
                }
                cancel_signal.store(false, std::sync::atomic::Ordering::Relaxed);

                // Mine in a blocking task to not block the async runtime
                let mine_state_for_stats = mine_state.clone();
                let pool = Arc::clone(&pool);
                let cancel_for_mine = Arc::clone(&cancel_signal);
                let mined_block = tokio::task::spawn_blocking(move || {
                    let start = std::time::Instant::now();
                    let attempts = pool.mine_block_cancellable(&mut block, Some(cancel_for_mine));
                    let elapsed = start.elapsed();

                    if attempts == 0 {
                        // Cancelled by P2P new block — return None
                        return None;
                    }

                    let hashrate = if elapsed.as_secs_f64() > 0.0 {
                        (attempts as f64 / elapsed.as_secs_f64()) as u64
                    } else {
                        0
                    };
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    {
                        let mut stats = mine_state_for_stats.miner_stats.write().unwrap();
                        stats.hashrate_hps = hashrate;
                        stats.last_attempts = attempts;
                        stats.last_elapsed_ms = elapsed.as_millis() as u64;
                        stats.last_updated = now;
                    }

                    // Display hashrate info
                    let hr_display = if hashrate > 1_000_000 {
                        format!("{:.2} MH/s", hashrate as f64 / 1_000_000.0)
                    } else if hashrate > 1_000 {
                        format!("{:.2} KH/s", hashrate as f64 / 1_000.0)
                    } else {
                        format!("{} H/s", hashrate)
                    };
                    eprintln!("  ⛏ {} ({} attempts in {:.1}s)", hr_display, attempts, elapsed.as_secs_f64());

                    Some(block)
                }).await.expect("CRITICAL: mining task panicked");

                // If cancelled, restart on new tip (with cooldown after reorg)
                let mined_block = match mined_block {
                    Some(b) => b,
                    None => {
                        tracing::debug!("Mining cancelled — restarting on new tip");
                        continue;
                    }
                };

                // Re-acquire reorg lock before adding block — ensures no reorg in progress
                let _reorg_read_post = mine_state.reorg_lock.read().await;

                // Check if tip changed during PoW (reorg happened while mining)
                {
                    let chain = mine_state.blockchain.read().unwrap();
                    let current_tip = chain.latest_hash();
                    if template_prev_hash != current_tip {
                        tracing::warn!(
                            "Mined block is stale (tip changed during PoW). Discarding."
                        );
                        drop(_reorg_read_post);
                        continue;
                    }
                }

                // Add to local chain
                {
                    let mut chain = mine_state.blockchain.write().unwrap();
                    match chain.add_block(mined_block.clone()) {
                        Ok(()) => {
                            println!(
                                "💎 Mined block #{} (hash: {})",
                                chain.height(),
                                mined_block.hash_hex()
                            );

                            // Save mined coinbase note to wallet (so balance updates immediately)
                            // Use the correct global position in the commitment tree
                            if let Some(ref wp) = mine_wallet_path {
                                if let Ok(mut wallet) = ShieldedWallet::load(wp) {
                                    // The miner reward commitment was just added to the tree.
                                    // Its position = tree_size_before_this_block's commitments
                                    // = current_tree_size - N (where N = commitments in this block)
                                    let tree_size = chain.state().commitment_count() as u64;
                                    // This block added: 1 (miner) + optionally 1 (dev fee) = 1-2 commitments
                                    let coinbase_commitments = if mined_block.coinbase.has_dev_fee() { 2u64 } else { 1u64 };
                                    let tx_commitments: u64 = mined_block.transactions.iter().map(|t| t.outputs.len() as u64).sum::<u64>()
                                        + mined_block.transactions_v2.iter().map(|t| t.outputs.len() as u64).sum::<u64>();
                                    let block_start_pos = tree_size - coinbase_commitments - tx_commitments;

                                    let new_notes = wallet.scan_block(&mined_block, block_start_pos);
                                    if new_notes > 0 {
                                        wallet.save(wp).ok();
                                    }
                                }
                            }

                            // Remove mined transactions from mempool (both V1 and V2)
                            let mut tx_hashes: Vec<[u8; 32]> = mined_block
                                .transactions
                                .iter()
                                .map(|tx| tx.hash())
                                .collect();
                            tx_hashes.extend(mined_block.transactions_v2.iter().map(|tx| tx.hash()));

                            let mut mempool = mine_state.mempool.write().unwrap();
                            mempool.remove_confirmed(&tx_hashes);

                            // Remove transactions with spent nullifiers (both V1 and V2)
                            let mut nullifiers: Vec<[u8; 32]> = mined_block.nullifiers().iter().map(|n| n.0).collect();
                            nullifiers.extend(mined_block.transactions_v2.iter().flat_map(|tx| tx.spends.iter().map(|s| s.nullifier)));
                            mempool.remove_spent_nullifiers(&nullifiers);

                            // Re-validate remaining mempool transactions
                            let removed = mempool.revalidate(chain.state());
                            if removed > 0 {
                                println!("  Removed {} invalid transactions from mempool", removed);
                            }
                        }
                        Err(e) => {
                            println!("Failed to add mined block: {}", e);
                            mine_state.orphan_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            continue;
                        }
                    }
                }

                // Broadcast via P2P GossipSub (primary — instant push to all peers)
                {
                    let p2p_tx = mine_state.p2p_broadcast.read().unwrap().clone();
                    if let Some(tx) = p2p_tx {
                        if let Ok(block_data) = serde_json::to_vec(&mined_block) {
                            let _ = tx.send(tsn::network::p2p::P2pCommand::BroadcastBlock(block_data)).await;
                        }
                    }
                }

                // Broadcast via HTTP (fallback for non-upgraded nodes)
                let mut current_peers = mine_state.peers.read().unwrap().clone();
                current_peers.retain(|peer| {
                    peer != &announce_url && peer != &local_url && peer != &local_ip_url
                });
                if !current_peers.is_empty() {
                    broadcast_block(&mined_block, &current_peers, &client).await;
                }

                // v1.6.1: Fork check by HEIGHT + HASH, never by cumulative_work.
                // Peer-reported work is unreliable (different fast-sync estimates).
                if let Some(peer) = current_peers.first() {
                    let height = mined_block.coinbase.height;
                    let ci_url = format!("{}/chain/info", peer);
                    if let Ok(resp) = client.get(&ci_url).timeout(std::time::Duration::from_secs(5)).send().await {
                        if let Ok(peer_info) = resp.json::<serde_json::Value>().await {
                            let peer_height = peer_info.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
                            let peer_hash = peer_info.get("latest_hash").and_then(|v| v.as_str()).unwrap_or("");

                            let local_hash_hex = {
                                let chain = mine_state.blockchain.read().unwrap();
                                hex::encode(chain.latest_hash())
                            };

                            if peer_hash == local_hash_hex {
                                // Same tip — no fork
                                tracing::info!("Block #{} mined, synced with peers at height {}", height, peer_height);
                                unaccepted_count = 0;
                            } else if peer_height > height {
                                // Peer is ahead by height — we might be on a fork
                                unaccepted_count += 1;
                                tracing::warn!(
                                    "FORK: peer ahead (peer h={}, local h={}, strike {}/2)",
                                    peer_height, height, unaccepted_count
                                );
                                if unaccepted_count >= 2 {
                                    tracing::error!("FORK CONFIRMED: peer is ahead. Re-syncing...");
                                    mine_state.reorg_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    let _ = tsn::network::sync_from_peer(mine_state.clone(), peer).await;
                                    // BUG FIX: Do NOT set mining_cancel here.
                                    // sync_from_peer already cancels mining during reorg internally.
                                    // Setting cancel=true AFTER sync returns kills the next mining
                                    // cycle before it starts, creating a deadlock:
                                    //   cancel=true → mine returns None → sync gate sees gap → waits
                                    //   → nobody mines → gap never closes → mining stalled forever.
                                    unaccepted_count = 0;
                                }
                            } else {
                                // We're at same height or ahead — peer will sync to us
                                tracing::info!("Block #{} mined, at or ahead of peers (local h={}, peer h={})", height, height, peer_height);
                                unaccepted_count = 0;
                            }
                        }
                    }
                }
            }
        });
    }

    let chain_height = state.blockchain.read().unwrap().height();
    println!();
    println!("Chain height: {}", chain_height);
    println!("Node is running. Press Ctrl+C to stop.");
    println!();

    // Keep the main task alive (API + sync + P2P all run in spawned tasks)
    tokio::signal::ctrl_c().await?;
    println!("Shutting down...");

    Ok(())
}
