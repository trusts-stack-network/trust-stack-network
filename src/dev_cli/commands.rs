use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "tsn-dev")]
#[command(about = "TSN Development CLI - Tools for testing, debugging and development", long_about = None)]
pub struct DevCli {
    #[command(subcommand)]
    pub command: DevCommands,
}

#[derive(Subcommand)]
pub enum DevCommands {
    /// Generate test transactions and blocks
    Generate {
        #[command(subcommand)]
        target: GenerateTarget,
    },
    /// Simulate network conditions and load testing
    Simulate {
        #[command(subcommand)]
        scenario: SimulateScenario,
    },
    /// Inspect internal data structures and state
    Inspect {
        #[command(subcommand)]
        target: InspectTarget,
    },
    /// Interactive debugging tools
    Debug {
        #[command(subcommand)]
        tool: DebugTool,
    },
    /// Validate and test cryptographic components
    Crypto {
        #[command(subcommand)]
        operation: CryptoOperation,
    },
}

#[derive(Subcommand)]
pub enum GenerateTarget {
    /// Generate test transactions
    Transactions {
        /// Number of transactions to generate
        #[arg(short, long, default_value = "10")]
        count: u32,
        /// Output file for transactions (JSON format)
        #[arg(short, long, default_value = "test_transactions.json")]
        output: PathBuf,
        /// Wallet file to use for generating transactions
        #[arg(short, long, default_value = "wallet.json")]
        wallet: PathBuf,
        /// Transaction type: transfer, mint, burn
        #[arg(short, long, default_value = "transfer")]
        tx_type: String,
        /// Amount range for transfers (min,max in TSN)
        #[arg(long, default_value = "1,100")]
        amount_range: String,
    },
    /// Generate test blocks
    Blocks {
        /// Number of blocks to generate
        #[arg(short, long, default_value = "5")]
        count: u32,
        /// Output directory for blocks
        #[arg(short, long, default_value = "test_blocks")]
        output: PathBuf,
        /// Include transactions in blocks
        #[arg(short, long, default_value = "5")]
        transactions_per_block: u32,
        /// Starting difficulty
        #[arg(short, long, default_value = "16")]
        difficulty: u64,
    },
    /// Generate test wallets
    Wallets {
        /// Number of wallets to generate
        #[arg(short, long, default_value = "3")]
        count: u32,
        /// Output directory for wallets
        #[arg(short, long, default_value = "test_wallets")]
        output: PathBuf,
        /// Pre-fund wallets with test tokens
        #[arg(short, long)]
        prefund: bool,
        /// Amount to prefund each wallet (in TSN)
        #[arg(long, default_value = "1000")]
        prefund_amount: u64,
    },
}

#[derive(Subcommand)]
pub enum SimulateScenario {
    /// Simulate network load with multiple nodes
    NetworkLoad {
        /// Number of virtual nodes to simulate
        #[arg(short, long, default_value = "5")]
        nodes: u32,
        /// Transactions per second to generate
        #[arg(short, long, default_value = "10")]
        tps: u32,
        /// Duration of simulation in seconds
        #[arg(short, long, default_value = "60")]
        duration: u64,
        /// Target node URL
        #[arg(short, long, default_value = "http://localhost:8333")]
        target: String,
    },
    /// Simulate network partitions and reconnections
    NetworkPartition {
        /// Duration of partition in seconds
        #[arg(short, long, default_value = "30")]
        partition_duration: u64,
        /// Nodes to partition (comma-separated URLs)
        #[arg(short, long)]
        nodes: String,
    },
    /// Simulate mining competition between multiple miners
    MiningCompetition {
        /// Number of miners to simulate
        #[arg(short, long, default_value = "3")]
        miners: u32,
        /// Mining duration in seconds
        #[arg(short, long, default_value = "300")]
        duration: u64,
        /// Difficulty level
        #[arg(short, long, default_value = "18")]
        difficulty: u64,
    },
    /// Simulate high-frequency trading patterns
    HighFrequencyTrading {
        /// Number of trading bots
        #[arg(short, long, default_value = "10")]
        bots: u32,
        /// Trades per minute per bot
        #[arg(short, long, default_value = "60")]
        trades_per_minute: u32,
        /// Duration in minutes
        #[arg(short, long, default_value = "10")]
        duration: u64,
    },
}

#[derive(Subcommand)]
pub enum InspectTarget {
    /// Inspect blockchain state and structure
    Blockchain {
        /// Data directory to inspect
        #[arg(short, long, default_value = "data")]
        data_dir: PathBuf,
        /// Show detailed block information
        #[arg(short, long)]
        verbose: bool,
        /// Block height to inspect (latest if not specified)
        #[arg(short, long)]
        height: Option<u64>,
    },
    /// Inspect mempool contents
    Mempool {
        /// Node URL to query
        #[arg(short, long, default_value = "http://localhost:8333")]
        node: String,
        /// Show transaction details
        #[arg(short, long)]
        verbose: bool,
        /// Filter by transaction type
        #[arg(short, long)]
        tx_type: Option<String>,
    },
    /// Inspect wallet state and notes
    Wallet {
        /// Wallet file to inspect
        #[arg(short, long, default_value = "wallet.json")]
        wallet: PathBuf,
        /// Show private information (keys, notes)
        #[arg(short, long)]
        show_private: bool,
        /// Node URL for balance queries
        #[arg(short, long, default_value = "http://localhost:8333")]
        node: String,
    },
    /// Inspect network peer connections
    Network {
        /// Node URL to query
        #[arg(short, long, default_value = "http://localhost:8333")]
        node: String,
        /// Show detailed peer information
        #[arg(short, long)]
        verbose: bool,
    },
    /// Inspect storage database
    Storage {
        /// Data directory to inspect
        #[arg(short, long, default_value = "data")]
        data_dir: PathBuf,
        /// Show database statistics
        #[arg(short, long)]
        stats: bool,
        /// Show raw key-value pairs
        #[arg(short, long)]
        raw: bool,
    },
}

#[derive(Subcommand)]
pub enum DebugTool {
    /// Interactive transaction validator
    ValidateTransaction {
        /// Transaction file (JSON)
        #[arg(short, long)]
        transaction: PathBuf,
        /// Show step-by-step validation
        #[arg(short, long)]
        verbose: bool,
        /// Skip ZK proof verification (faster)
        #[arg(short, long)]
        skip_proofs: bool,
    },
    /// Interactive block validator
    ValidateBlock {
        /// Block file (JSON)
        #[arg(short, long)]
        block: PathBuf,
        /// Show step-by-step validation
        #[arg(short, long)]
        verbose: bool,
        /// Skip ZK proof verification (faster)
        #[arg(short, long)]
        skip_proofs: bool,
    },
    /// Trace transaction execution
    TraceExecution {
        /// Transaction hash to trace
        #[arg(short, long)]
        tx_hash: String,
        /// Node URL to query
        #[arg(short, long, default_value = "http://localhost:8333")]
        node: String,
        /// Show internal state changes
        #[arg(short, long)]
        show_state: bool,
    },
    /// Performance profiler for operations
    Profile {
        /// Operation to profile: mining, validation, sync
        #[arg(short, long)]
        operation: String,
        /// Duration in seconds
        #[arg(short, long, default_value = "30")]
        duration: u64,
        /// Output file for profiling data
        #[arg(short, long, default_value = "profile.json")]
        output: PathBuf,
    },
    /// Memory usage analyzer
    MemoryAnalysis {
        /// Node URL to analyze
        #[arg(short, long, default_value = "http://localhost:8333")]
        node: String,
        /// Sampling interval in seconds
        #[arg(short, long, default_value = "5")]
        interval: u64,
        /// Duration in seconds
        #[arg(short, long, default_value = "60")]
        duration: u64,
    },
}

#[derive(Subcommand)]
pub enum CryptoOperation {
    /// Test post-quantum signature schemes
    TestSignatures {
        /// Number of signatures to test
        #[arg(short, long, default_value = "100")]
        count: u32,
        /// Signature scheme: ml-dsa-65, ecdsa
        #[arg(short, long, default_value = "ml-dsa-65")]
        scheme: String,
        /// Benchmark performance
        #[arg(short, long)]
        benchmark: bool,
    },
    /// Test ZK proof generation and verification
    TestProofs {
        /// Number of proofs to test
        #[arg(short, long, default_value = "10")]
        count: u32,
        /// Proof system: plonky2, groth16
        #[arg(short, long, default_value = "plonky2")]
        system: String,
        /// Benchmark performance
        #[arg(short, long)]
        benchmark: bool,
    },
    /// Test hash functions and commitment schemes
    TestHashing {
        /// Hash function: poseidon2, sha256, blake3
        #[arg(short, long, default_value = "poseidon2")]
        function: String,
        /// Input size in bytes
        #[arg(short, long, default_value = "1024")]
        input_size: usize,
        /// Number of iterations
        #[arg(short, long, default_value = "1000")]
        iterations: u32,
    },
    /// Test encryption/decryption
    TestEncryption {
        /// Encryption scheme: chacha20poly1305, aes-gcm
        #[arg(short, long, default_value = "chacha20poly1305")]
        scheme: String,
        /// Data size in bytes
        #[arg(short, long, default_value = "1024")]
        data_size: usize,
        /// Number of operations
        #[arg(short, long, default_value = "100")]
        iterations: u32,
    },
    /// Test commitment schemes
    TestCommitments {
        /// Commitment scheme: pedersen, poseidon
        #[arg(short, long, default_value = "poseidon")]
        scheme: String,
        /// Number of commitments to test
        #[arg(short, long, default_value = "100")]
        count: u32,
        /// Benchmark performance
        #[arg(short, long)]
        benchmark: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        // Test que les commandes peuvent être parsées
        let cli = DevCli::parse_from(["tsn-dev", "generate", "transactions", "--count", "5"]);
        match cli.command {
            DevCommands::Generate { target } => {
                match target {
                    GenerateTarget::Transactions { count, .. } => {
                        assert_eq!(count, 5);
                    }
                    _ => panic!("Expected Transactions target"),
                }
            }
            _ => panic!("Expected Generate command"),
        }
    }

    #[test]
    fn test_default_values() {
        let cli = DevCli::parse_from(["tsn-dev", "crypto", "test-signatures"]);
        match cli.command {
            DevCommands::Crypto { operation } => {
                match operation {
                    CryptoOperation::TestSignatures { count, scheme, benchmark } => {
                        assert_eq!(count, 100);
                        assert_eq!(scheme, "ml-dsa-65");
                        assert!(!benchmark);
                    }
                    _ => panic!("Expected TestSignatures operation"),
                }
            }
            _ => panic!("Expected Crypto command"),
        }
    }
}
