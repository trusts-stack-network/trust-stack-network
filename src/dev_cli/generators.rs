use anyhow::{Result, Context};
use rand::{thread_rng, Rng};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use crate::core::{Block, Transaction, Account};
use crate::crypto::keys::KeyPair;
use crate::crypto::address::Address;
use crate::wallet::Wallet;

/// Générateur de données de test pour le développement
pub struct TestDataGenerator {
    rng: rand::rngs::ThreadRng,
}

impl TestDataGenerator {
    pub fn new() -> Self {
        Self {
            rng: thread_rng(),
        }
    }

    /// Génère des transactions de test
    pub async fn generate_transactions(
        &mut self,
        count: u32,
        output_file: PathBuf,
        wallet_file: PathBuf,
        tx_type: String,
        amount_range: String,
    ) -> Result<()> {
        println!("🏭 Génération de {} transactions de test...", count);

        // Charger le wallet
        let wallet = self.load_or_create_wallet(&wallet_file).await?;
        
        // Parser la plage de montants
        let (min_amount, max_amount) = self.parse_amount_range(&amount_range)?;

        let mut transactions = Vec::new();

        for i in 0..count {
            let transaction = match tx_type.as_str() {
                "transfer" => self.generate_transfer_transaction(&wallet, min_amount, max_amount).await?,
                "mint" => self.generate_mint_transaction(&wallet, min_amount, max_amount).await?,
                "burn" => self.generate_burn_transaction(&wallet, min_amount, max_amount).await?,
                _ => return Err(anyhow::anyhow!("Type de transaction non supporté: {}", tx_type)),
            };

            transactions.push(transaction);
            
            if (i + 1) % 10 == 0 {
                println!("  ✅ {} transactions générées", i + 1);
            }
        }

        // Sauvegarder les transactions
        self.save_transactions_to_file(&transactions, &output_file).await?;
        
        println!("💾 {} transactions sauvegardées dans {:?}", count, output_file);
        Ok(())
    }

    /// Génère des blocs de test
    pub async fn generate_blocks(
        &mut self,
        count: u32,
        output_dir: PathBuf,
        transactions_per_block: u32,
        starting_difficulty: u64,
    ) -> Result<()> {
        println!("🏭 Génération de {} blocs de test...", count);

        // Créer le répertoire de sortie
        fs::create_dir_all(&output_dir)
            .context("Erreur lors de la création du répertoire de sortie")?;

        let mut previous_hash = [0u8; 32]; // Genesis block hash
        let mut current_height = 0u64;
        let mut current_difficulty = starting_difficulty;

        for i in 0..count {
            // Générer les transactions pour ce bloc
            let mut transactions = Vec::new();
            for _ in 0..transactions_per_block {
                let tx = self.generate_random_transaction().await?;
                transactions.push(tx);
            }

            // Générer le bloc
            let block = self.generate_block(
                current_height,
                previous_hash,
                transactions,
                current_difficulty,
            ).await?;

            // Sauvegarder le bloc
            let block_file = output_dir.join(format!("block_{:06}.json", current_height));
            self.save_block_to_file(&block, &block_file).await?;

            // Préparer pour le bloc suivant
            previous_hash = block.hash();
            current_height += 1;
            
            // Ajuster la difficulté (simulation simple)
            if i % 10 == 9 {
                current_difficulty = current_difficulty.saturating_add(1);
            }

            if (i + 1) % 5 == 0 {
                println!("  ✅ {} blocs générés", i + 1);
            }
        }

        println!("💾 {} blocs sauvegardés dans {:?}", count, output_dir);
        Ok(())
    }

    /// Génère des wallets de test
    pub async fn generate_wallets(
        &mut self,
        count: u32,
        output_dir: PathBuf,
        prefund: bool,
        prefund_amount: u64,
    ) -> Result<()> {
        println!("🏭 Génération de {} wallets de test...", count);

        // Créer le répertoire de sortie
        fs::create_dir_all(&output_dir)
            .context("Erreur lors de la création du répertoire de sortie")?;

        let mut wallet_info = Vec::new();

        for i in 0..count {
            // Générer une nouvelle paire de clés
            let keypair = KeyPair::generate();
            let address = Address::from_public_key(&keypair.public_key());

            // Créer le wallet
            let wallet = Wallet::new(keypair, address.clone());

            // Sauvegarder le wallet
            let wallet_file = output_dir.join(format!("wallet_{:03}.json", i + 1));
            self.save_wallet_to_file(&wallet, &wallet_file).await?;

            // Collecter les informations pour le résumé
            wallet_info.push(json!({
                "id": i + 1,
                "address": address.to_string(),
                "file": wallet_file.file_name().unwrap().to_string_lossy(),
                "prefunded": prefund,
                "prefund_amount": if prefund { prefund_amount } else { 0 }
            }));

            if (i + 1) % 5 == 0 {
                println!("  ✅ {} wallets générés", i + 1);
            }
        }

        // Sauvegarder le fichier de résumé
        let summary_file = output_dir.join("wallets_summary.json");
        let summary = json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "total_wallets": count,
            "prefunded": prefund,
            "prefund_amount": prefund_amount,
            "wallets": wallet_info
        });

        fs::write(&summary_file, serde_json::to_string_pretty(&summary)?)
            .context("Erreur lors de la sauvegarde du résumé")?;

        println!("💾 {} wallets sauvegardés dans {:?}", count, output_dir);
        println!("📋 Résumé disponible dans {:?}", summary_file);

        if prefund {
            println!("💰 Note: Les wallets sont marqués comme pré-financés avec {} TSN", prefund_amount);
            println!("    Vous devez manuellement transférer les fonds depuis un wallet existant.");
        }

        Ok(())
    }

    // === MÉTHODES PRIVÉES DE GÉNÉRATION ===

    async fn load_or_create_wallet(&mut self, wallet_file: &PathBuf) -> Result<Wallet> {
        if wallet_file.exists() {
            // Charger le wallet existant
            let wallet_data = fs::read_to_string(wallet_file)
                .context("Erreur lors de la lecture du fichier wallet")?;
            
            let wallet: Wallet = serde_json::from_str(&wallet_data)
                .context("Erreur lors du parsing du wallet")?;
            
            Ok(wallet)
        } else {
            // Créer un nouveau wallet
            println!("  📝 Création d'un nouveau wallet: {:?}", wallet_file);
            
            let keypair = KeyPair::generate();
            let address = Address::from_public_key(&keypair.public_key());
            let wallet = Wallet::new(keypair, address);
            
            // Sauvegarder le nouveau wallet
            self.save_wallet_to_file(&wallet, wallet_file).await?;
            
            Ok(wallet)
        }
    }

    fn parse_amount_range(&self, range_str: &str) -> Result<(u64, u64)> {
        let parts: Vec<&str> = range_str.split(',').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Format de plage invalide. Utilisez 'min,max'"));
        }

        let min = parts[0].trim().parse::<u64>()
            .context("Montant minimum invalide")?;
        let max = parts[1].trim().parse::<u64>()
            .context("Montant maximum invalide")?;

        if min > max {
            return Err(anyhow::anyhow!("Le montant minimum ne peut pas être supérieur au maximum"));
        }

        Ok((min, max))
    }

    async fn generate_transfer_transaction(&mut self, wallet: &Wallet, min_amount: u64, max_amount: u64) -> Result<Transaction> {
        // Générer une adresse de destination aléatoire
        let dest_keypair = KeyPair::generate();
        let dest_address = Address::from_public_key(&dest_keypair.public_key());
        
        let amount = self.rng.gen_range(min_amount..=max_amount);
        let fee = self.rng.gen_range(1..=10); // Frais aléatoires entre 1 et 10
        let nonce = self.rng.gen::<u64>();

        let transaction = Transaction::new_transfer(
            wallet.address().clone(),
            dest_address,
            amount,
            fee,
            nonce,
        );

        // Signer la transaction
        let signed_transaction = wallet.sign_transaction(transaction)?;
        
        Ok(signed_transaction)
    }

    async fn generate_mint_transaction(&mut self, wallet: &Wallet, min_amount: u64, max_amount: u64) -> Result<Transaction> {
        let amount = self.rng.gen_range(min_amount..=max_amount);
        let fee = self.rng.gen_range(1..=5);
        let nonce = self.rng.gen::<u64>();

        let transaction = Transaction::new_mint(
            wallet.address().clone(),
            amount,
            fee,
            nonce,
        );

        let signed_transaction = wallet.sign_transaction(transaction)?;
        
        Ok(signed_transaction)
    }

    async fn generate_burn_transaction(&mut self, wallet: &Wallet, min_amount: u64, max_amount: u64) -> Result<Transaction> {
        let amount = self.rng.gen_range(min_amount..=max_amount);
        let fee = self.rng.gen_range(1..=5);
        let nonce = self.rng.gen::<u64>();

        let transaction = Transaction::new_burn(
            wallet.address().clone(),
            amount,
            fee,
            nonce,
        );

        let signed_transaction = wallet.sign_transaction(transaction)?;
        
        Ok(signed_transaction)
    }

    async fn generate_random_transaction(&mut self) -> Result<Transaction> {
        // Générer des adresses aléatoires
        let from_keypair = KeyPair::generate();
        let from_address = Address::from_public_key(&from_keypair.public_key());
        
        let to_keypair = KeyPair::generate();
        let to_address = Address::from_public_key(&to_keypair.public_key());

        let amount = self.rng.gen_range(1..=1000);
        let fee = self.rng.gen_range(1..=10);
        let nonce = self.rng.gen::<u64>();

        let transaction = Transaction::new_transfer(
            from_address,
            to_address,
            amount,
            fee,
            nonce,
        );

        // Pour les transactions aléatoires, on ne peut pas les signer
        // car on n'a pas accès à la clé privée dans un vrai contexte
        // On retourne la transaction non signée pour les tests
        Ok(transaction)
    }

    async fn generate_block(
        &mut self,
        height: u64,
        previous_hash: [u8; 32],
        transactions: Vec<Transaction>,
        difficulty: u64,
    ) -> Result<Block> {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let nonce = self.rng.gen::<u64>();

        let block = Block::new(
            height,
            previous_hash,
            transactions,
            timestamp,
            difficulty,
            nonce,
        );

        Ok(block)
    }

    // === MÉTHODES DE SAUVEGARDE ===

    async fn save_transactions_to_file(&self, transactions: &[Transaction], file_path: &PathBuf) -> Result<()> {
        let transactions_json: Vec<Value> = transactions
            .iter()
            .map(|tx| self.transaction_to_json(tx))
            .collect();

        let output = json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "count": transactions.len(),
            "transactions": transactions_json
        });

        fs::write(file_path, serde_json::to_string_pretty(&output)?)
            .context("Erreur lors de la sauvegarde des transactions")?;

        Ok(())
    }

    async fn save_block_to_file(&self, block: &Block, file_path: &PathBuf) -> Result<()> {
        let block_json = self.block_to_json(block);

        fs::write(file_path, serde_json::to_string_pretty(&block_json)?)
            .context("Erreur lors de la sauvegarde du bloc")?;

        Ok(())
    }

    async fn save_wallet_to_file(&self, wallet: &Wallet, file_path: &PathBuf) -> Result<()> {
        let wallet_json = self.wallet_to_json(wallet);

        fs::write(file_path, serde_json::to_string_pretty(&wallet_json)?)
            .context("Erreur lors de la sauvegarde du wallet")?;

        Ok(())
    }

    // === MÉTHODES DE SÉRIALISATION JSON ===

    fn transaction_to_json(&self, transaction: &Transaction) -> Value {
        json!({
            "hash": hex::encode(transaction.hash()),
            "type": transaction.tx_type(),
            "from": transaction.from().to_string(),
            "to": transaction.to().to_string(),
            "amount": transaction.amount(),
            "fee": transaction.fee(),
            "nonce": transaction.nonce(),
            "timestamp": transaction.timestamp(),
            "signature": hex::encode(transaction.signature()),
        })
    }

    fn block_to_json(&self, block: &Block) -> Value {
        let transactions_json: Vec<Value> = block.transactions
            .iter()
            .map(|tx| self.transaction_to_json(tx))
            .collect();

        json!({
            "height": block.height,
            "hash": hex::encode(block.hash()),
            "previous_hash": hex::encode(block.previous_hash),
            "merkle_root": hex::encode(block.merkle_root),
            "timestamp": block.timestamp,
            "difficulty": block.difficulty,
            "nonce": block.nonce,
            "transaction_count": block.transactions.len(),
            "transactions": transactions_json
        })
    }

    fn wallet_to_json(&self, wallet: &Wallet) -> Value {
        json!({
            "address": wallet.address().to_string(),
            "public_key": hex::encode(wallet.public_key().as_bytes()),
            // Note: On ne sauvegarde jamais la clé privée en clair dans un vrai contexte
            // Ici c'est pour les tests de développement uniquement
            "private_key_encrypted": "ENCRYPTED_FOR_DEV_ONLY",
            "created_at": chrono::Utc::now().to_rfc3339(),
            "version": "1.0.0"
        })
    }
}

/// Générateur de données de performance pour les benchmarks
pub struct PerformanceDataGenerator {
    rng: rand::rngs::ThreadRng,
}

impl PerformanceDataGenerator {
    pub fn new() -> Self {
        Self {
            rng: thread_rng(),
        }
    }

    /// Génère un dataset pour les tests de performance
    pub async fn generate_performance_dataset(
        &mut self,
        transaction_count: u32,
        block_count: u32,
        output_dir: PathBuf,
    ) -> Result<()> {
        println!("🚀 Génération d'un dataset de performance...");
        println!("   {} transactions, {} blocs", transaction_count, block_count);

        fs::create_dir_all(&output_dir)
            .context("Erreur lors de la création du répertoire")?;

        // Générer les transactions
        let mut test_generator = TestDataGenerator::new();
        let tx_file = output_dir.join("performance_transactions.json");
        
        test_generator.generate_transactions(
            transaction_count,
            tx_file,
            output_dir.join("temp_wallet.json"),
            "transfer".to_string(),
            "1,1000".to_string(),
        ).await?;

        // Générer les blocs
        let blocks_dir = output_dir.join("performance_blocks");
        test_generator.generate_blocks(
            block_count,
            blocks_dir,
            transaction_count / block_count,
            16,
        ).await?;

        // Générer le fichier de configuration pour les benchmarks
        let config = json!({
            "dataset_type": "performance",
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "transaction_count": transaction_count,
            "block_count": block_count,
            "files": {
                "transactions": "performance_transactions.json",
                "blocks_directory": "performance_blocks"
            },
            "benchmark_scenarios": [
                {
                    "name": "transaction_validation",
                    "description": "Validation de transactions en lot"
                },
                {
                    "name": "block_mining",
                    "description": "Simulation de minage de blocs"
                },
                {
                    "name": "merkle_tree_construction",
                    "description": "Construction d'arbres de Merkle"
                }
            ]
        });

        let config_file = output_dir.join("benchmark_config.json");
        fs::write(&config_file, serde_json::to_string_pretty(&config)?)
            .context("Erreur lors de la sauvegarde de la configuration")?;

        println!("✅ Dataset de performance généré dans {:?}", output_dir);
        println!("📋 Configuration disponible dans {:?}", config_file);

        Ok(())
    }
}