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
#[command(name = "tsn")]
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
    use std::path::Path;

    // Paths to check (in order of preference)
    let committed_spend = "circuits/keys/spend_vkey.json";
    let committed_output = "circuits/keys/output_vkey.json";
    let build_spend = "circuits/build/spend_vkey.json";
    let build_output = "circuits/build/output_vkey.json";

    // Check committed keys first (production)
    if Path::new(committed_spend).exists() && Path::new(committed_output).exists() {
        // Verify checksums for committed keys
        let spend_data = std::fs::read(committed_spend)?;
        let output_data = std::fs::read(committed_output)?;

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
            if local_height == info.height && local_hash == info.latest_hash {
                println!(
                    "Local chain matches peer {} at height {}.",
                    peer_url, local_height
                );
                return Ok(());
            }

            println!(
                "Waiting for sync... local height={}, peer height={}",
                local_height, info.height
            );
            let _ = tsn::network::sync_from_peer(state.clone(), &peer_url).await;
        } else {
            println!("Waiting for sync... no peer info available yet.");
        }

        if Instant::now() >= deadline {
            return Err(anyhow::anyhow!(
                "Timed out waiting for sync; local tip does not match any peer."
            ));
        }

        sleep(Duration::from_secs(5)).await;
    }
}

#[derive(Subcommand)]
enum Commands {
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Suppress logs for simple commands (balance, new-wallet)
    let is_quiet_cmd = matches!(cli.command, Some(Commands::Balance { .. }) | Some(Commands::NewWallet { .. }));
    let log_level = if is_quiet_cmd { "error" } else { "info" };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_level.into()),
        )
        .init();

    match cli.command {
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
            // ---- DEFAULT MODE: auto-detect everything and run ----
            let node_role = auto_detect_role();
            let wallet = cli.wallet.or_else(auto_detect_wallet);
            let port = cli.port.unwrap_or_else(config::get_port);
            let data_dir = cli.data_dir.unwrap_or_else(config::get_data_dir);
            let jobs = cli.threads.unwrap_or(1);

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
    // Auto-create
    println!("No wallet found — creating new wallet...");
    std::fs::create_dir_all(data_dir).ok();
    let wallet = ShieldedWallet::generate();
    let path = data_wallet.to_string_lossy().to_string();
    wallet.save(&path).expect("Failed to create wallet");
    println!("New wallet created: {}", path);
    println!("Address: {}", hex::encode(wallet.pk_hash()));
    println!("IMPORTANT: Back up this wallet file! Without it, your mined coins are lost.");
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
        }
    }
    // Check current directory
    let cwd_wallet = std::path::Path::new("wallet.json");
    if cwd_wallet.exists() {
        return Some("wallet.json".to_string());
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
                    for h in (wallet.last_scanned_height() + 1)..=chain_height {
                        if let Some(block) = chain.get_block_by_height(h) {
                            new_notes += wallet.scan_block(&block, 0);
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
async fn try_scan_via_api(wallet: &mut ShieldedWallet, node_url: &str, wallet_path: &str) -> (bool, usize) {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
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
                Ok(v) => {
                    let h = v["height"].as_u64().unwrap_or(0);
                    h
                }
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
        eprint!("  Scanning {} blocks...", blocks_to_scan);
    }

    // Fetch full blocks via /blocks/since/:height (returns Vec<ShieldedBlock>)
    let mut new_notes = 0usize;
    let mut current = scanned_height;

    // Fetch blocks from the node. After fast-sync, the node may only have recent blocks.
    // Try scanned_height first, then fall back to height 0 (which returns from earliest available).
    let url = format!("{}/blocks/since/{}", node_url, scanned_height);
    let body = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => {
            match r.text().await {
                Ok(b) => b,
                Err(_) => return (false, 0),
            }
        }
        _ => return (false, 0),
    };

    // If empty, the node doesn't have blocks from our scanned_height (fast-sync).
    // Binary search for the first available block.
    let body = if body == "[]" {
        // The node did fast-sync — blocks before the snapshot don't exist.
        // Skip ahead: wallet can't scan blocks it doesn't have, so jump to what's available.
        let mut try_height = chain_height.saturating_sub(200);
        let mut found_body = String::from("[]");
        // Binary search for first available block
        let mut lo = scanned_height;
        let mut hi = chain_height;
        while lo + 1 < hi {
            let mid = (lo + hi) / 2;
            if let Ok(r) = client.get(&format!("{}/blocks/since/{}", node_url, mid)).send().await {
                if let Ok(b) = r.text().await {
                    if b != "[]" {
                        hi = mid;
                        found_body = b;
                    } else {
                        lo = mid;
                    }
                } else { break; }
            } else { break; }
        }
        // Also update scanned_height to skip the gap (we can't scan blocks we don't have)
        wallet.set_last_scanned_height(hi);
        found_body
    } else {
        body
    };

    if let Ok(blocks) = serde_json::from_str::<Vec<tsn::core::ShieldedBlock>>(&body) {
        for (i, block) in blocks.iter().enumerate() {
            let block_h = if block.coinbase.height > 0 {
                block.coinbase.height
            } else {
                wallet.last_scanned_height() + 1 + i as u64
            };
            new_notes += wallet.scan_block(block, 0);
            wallet.set_last_scanned_height(block_h);
        }
    }

    if blocks_to_scan > 50 {
        eprintln!(" done.");
    }

    let scanned_now = wallet.last_scanned_height();
    if scanned_now > scanned_height {
        wallet.save(wallet_path).ok();
    }
    (scanned_now > scanned_height, new_notes)
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

    println!();
    println!("╔═══════════════════════════════════════════╗");
    println!("║     TSN Shielded Node v0.6.0              ║");
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
        println!("  Explorer:     http://localhost:{}/explorer", port);
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

    // Fast sync: paginated block download from peers
    // Works for fresh nodes (height=0) AND nodes that are behind
    if fast_sync && !peers.is_empty() {
        let local_height = blockchain.height();
        // Check if any peer is ahead of us
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        // Find best peer
        let mut best_peer: Option<(String, u64)> = None;
        for peer_url in &peers {
            let tip_url = format!("{}/tip", peer_url);
            if let Ok(resp) = client.get(&tip_url).send().await {
                if let Ok(tip) = resp.json::<serde_json::Value>().await {
                    let peer_height = tip["height"].as_u64().unwrap_or(0);
                    if peer_height > local_height + 10 {
                        if best_peer.is_none() || peer_height > best_peer.as_ref().unwrap().1 {
                            best_peer = Some((peer_url.clone(), peer_height));
                        }
                    }
                }
            }
        }

        if let Some((peer_url, peer_height)) = best_peer {
            let behind = peer_height - local_height;
            let start_time = std::time::Instant::now();

            // Strategy: if far behind (>100 blocks), use snapshot-based sync (instant)
            // Otherwise, use block-by-block trusted sync
            if behind > 50 {
                // ===== SNAPSHOT SYNC (instant) =====
                println!("Fast sync: {} blocks behind — downloading state snapshot...", behind);

                let snapshot_client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(120))
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

                                            // Get difficulty AND next_difficulty from peer
                                            let (difficulty, next_diff) = if let Ok(resp) = client.get(&format!("{}/chain/info", peer_url)).send().await {
                                                let info = resp.json::<serde_json::Value>().await.ok();
                                                let d = info.as_ref().and_then(|i| i["difficulty"].as_u64()).unwrap_or(GENESIS_DIFFICULTY);
                                                let nd = info.as_ref().and_then(|i| i["next_difficulty"].as_u64()).unwrap_or(d);
                                                (d, nd)
                                            } else {
                                                (GENESIS_DIFFICULTY, GENESIS_DIFFICULTY)
                                            };

                                            // Import snapshot — sets chain state instantly
                                            blockchain.import_snapshot_at_height(snapshot, snap_height, block_hash, difficulty, next_diff);

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
    });

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
                    Err(e) => tracing::warn!("Sync from {} failed: {}", peer_id(peer), e),
                }
            }
        });

        // Start background sync loop (HTTP fallback — checks every 30 seconds)
        let sync_state = state.clone();
        let sync_peers = state.peers.read().unwrap().clone();
        tokio::spawn(async move {
            sync_loop(sync_state, sync_peers, 30).await;
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
                protocol_version: "tsn/0.6.0".to_string(),
            };

            let p2p = P2pNode::start(p2p_config).await
                .expect("FATAL: P2P layer failed to start — node cannot propagate blocks");

            println!("  P2P:          {} (port {})", p2p.peer_id, p2p_port);

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

            // Spawn task to handle incoming P2P events
            let p2p_blockchain = state.clone();
            let mut p2p_events = p2p.event_rx;
            tokio::spawn(async move {
                while let Some(event) = p2p_events.recv().await {
                    match event {
                        P2pEvent::NewBlock(data) => {
                            match serde_json::from_slice::<tsn::core::ShieldedBlock>(&data) {
                                Ok(block) => {
                                    let height = block.coinbase.height;
                                    let mut chain = p2p_blockchain.blockchain.write().unwrap();
                                    match chain.add_block(block) {
                                        Ok(_) => info!("P2P: new block {} accepted", height),
                                        Err(e) => debug!("P2P: block rejected: {}", e),
                                    }
                                }
                                Err(e) => debug!("P2P: invalid block data: {}", e),
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
                            info!("P2P: peer {} connected", peer);
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
                    match client.post(&url).json(&body).send().await {
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
        let announce_url = our_url.clone();
        let local_url = format!("http://localhost:{}", port);
        let local_ip_url = format!("http://127.0.0.1:{}", port);
        if let Some(simd) = simd {
            println!("SIMD mode: {:?}", simd);
        }
        let pool = Arc::new(MiningPool::new_with_simd(jobs, simd));

        tokio::spawn(async move {
            let client = reqwest::Client::new();
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

            loop {
                // Sync gate: pause mining if too far behind network tip
                {
                    let local_height = mine_state.blockchain.read().unwrap().height();
                    while !mine_state.sync_gate.can_mine(local_height) {
                        let net_tip = mine_state.sync_gate.network_tip_height();
                        tracing::warn!(
                            "Sync required: local height {} < network tip {}, pausing mining...",
                            local_height, net_tip
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        // Re-check with fresh local height (might have synced)
                        let fresh_height = mine_state.blockchain.read().unwrap().height();
                        if mine_state.sync_gate.can_mine(fresh_height) {
                            break;
                        }
                    }
                }

                // Get mempool transactions (both V1 and V2)
                let (mempool_txs, mempool_txs_v2) = {
                    let mempool = mine_state.mempool.read().unwrap();
                    let v1 = mempool.get_transactions(100);
                    let v2 = mempool.get_shielded_v2_transactions(100);
                    if !v2.is_empty() {
                        println!("  Including {} V2 transactions in block template", v2.len());
                    }
                    (v1, v2)
                };

                // Create block template with both V1 and V2 transactions
                let mut block = {
                    let chain = mine_state.blockchain.read().unwrap();
                    chain.create_block_template_with_v2(miner_pk_hash, &viewing_key, mempool_txs, mempool_txs_v2)
                };

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

                // Mine in a blocking task to not block the async runtime
                let mine_state_for_stats = mine_state.clone();
                let pool = Arc::clone(&pool);
                let mined_block = tokio::task::spawn_blocking(move || {
                    let start = std::time::Instant::now();
                    let attempts = pool.mine_block(&mut block);
                    let elapsed = start.elapsed();
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

                    block
                }).await.expect("CRITICAL: mining task panicked");

                // Add to local chain
                {
                    let mut chain = mine_state.blockchain.write().unwrap();
                    match chain.add_block(mined_block.clone()) {
                        Ok(()) => {
                            println!(
                                "Mined block {} (hash: {}...)",
                                chain.height(),
                                &mined_block.hash_hex()[..16]
                            );

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
                    broadcast_block(&mined_block, &current_peers).await;
                }

                // Best-effort: check whether a peer accepted the mined block
                if let Some(peer) = current_peers.first() {
                    let height = mined_block.coinbase.height;
                    let url = format!("{}/block/height/{}", peer, height);
                    let result = client.get(&url).send().await;
                    match result {
                        Ok(resp) if resp.status().is_success() => {
                            if let Ok(info) = resp.json::<serde_json::Value>().await {
                                let peer_hash = info.get("hash").and_then(|v| v.as_str()).unwrap_or("");
                                if peer_hash == mined_block.hash_hex() {
                                    tracing::info!("Peer accepted block at height {}.", height);
                                } else {
                                    tracing::info!("Peer has different block at height {}.", height);
                                }
                            }
                        }
                        _ => {
                            tracing::warn!("Could not confirm peer acceptance for height {}.", height);
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
