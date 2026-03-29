use anyhow::{Result, Context};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, RwLock};
use tokio::time::{sleep, interval};
use tokio::task::JoinSet;
use rand::{thread_rng, Rng};
use crate::core::Transaction;
use crate::wallet::Wallet;

pub struct NetworkLoadSimulator {
    client: Client,
    target_url: String,
    stats: Arc<RwLock<SimulationStats>>,
}

#[derive(Debug, Clone, Default)]
pub struct SimulationStats {
    pub transactions_sent: u64,
    pub transactions_confirmed: u64,
    pub transactions_failed: u64,
    pub average_response_time: f64,
    pub peak_tps: f64,
    pub errors: Vec<String>,
}

impl NetworkLoadSimulator {
    pub fn new(target_url: String) -> Self {
        Self {
            client: Client::new(),
            target_url,
            stats: Arc::new(RwLock::new(SimulationStats::default())),
        }
    }

    pub async fn simulate_load(
        &self,
        nodes: u32,
        tps: u32,
        duration: u64,
    ) -> Result<SimulationStats> {
        println!("🚀 Démarrage de la simulation de charge réseau");
        println!("   📊 {} nœuds virtuels, {} TPS, {} secondes", nodes, tps, duration);
        println!("   🎯 Cible: {}", self.target_url);

        let start_time = Instant::now();
        let end_time = start_time + Duration::from_secs(duration);
        
        // Créer un semaphore pour limiter les connexions concurrentes
        let semaphore = Arc::new(Semaphore::new(nodes as usize * 2));
        
        // Créer des wallets pour chaque nœud virtuel
        let mut wallets = Vec::new();
        for _ in 0..nodes {
            wallets.push(Wallet::new());
        }
        let wallets = Arc::new(wallets);

        let mut join_set = JoinSet::new();

        // Lancer les générateurs de transactions
        for node_id in 0..nodes {
            let client = self.client.clone();
            let target_url = self.target_url.clone();
            let stats = self.stats.clone();
            let semaphore = semaphore.clone();
            let wallets = wallets.clone();
            
            join_set.spawn(async move {
                Self::node_transaction_generator(
                    node_id,
                    client,
                    target_url,
                    tps / nodes, // TPS par nœud
                    end_time,
                    stats,
                    semaphore,
                    wallets,
                ).await
            });
        }

        // Lancer le moniteur de statistiques
        let stats_monitor = self.stats.clone();
        join_set.spawn(async move {
            Self::stats_monitor(stats_monitor, duration).await
        });

        // Attendre que toutes les tâches se terminent
        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                eprintln!("❌ Erreur dans une tâche de simulation: {}", e);
            }
        }

        let final_stats = self.stats.read().await.clone();
        self.print_final_stats(&final_stats, duration).await;

        Ok(final_stats)
    }

    async fn node_transaction_generator(
        node_id: u32,
        client: Client,
        target_url: String,
        node_tps: u32,
        end_time: Instant,
        stats: Arc<RwLock<SimulationStats>>,
        semaphore: Arc<Semaphore>,
        wallets: Arc<Vec<Wallet>>,
    ) {
        let mut interval = interval(Duration::from_millis(1000 / node_tps as u64));
        let mut rng = thread_rng();

        while Instant::now() < end_time {
            interval.tick().await;

            let _permit = match semaphore.try_acquire() {
                Ok(permit) => permit,
                Err(_) => {
                    // Trop de connexions, on skip cette transaction
                    continue;
                }
            };

            // Sélectionner un wallet aléatoire
            let wallet_index = rng.gen_range(0..wallets.len());
            let wallet = &wallets[wallet_index];

            // Générer une transaction de test
            let transaction = Self::generate_test_transaction(wallet, &mut rng).await;
            
            let client = client.clone();
            let target_url = target_url.clone();
            let stats = stats.clone();

            // Envoyer la transaction de manière asynchrone
            tokio::spawn(async move {
                let start = Instant::now();
                
                match Self::send_transaction(&client, &target_url, &transaction).await {
                    Ok(_) => {
                        let response_time = start.elapsed().as_millis() as f64;
                        let mut stats_guard = stats.write().await;
                        stats_guard.transactions_sent += 1;
                        stats_guard.average_response_time = 
                            (stats_guard.average_response_time * (stats_guard.transactions_sent - 1) as f64 + response_time) 
                            / stats_guard.transactions_sent as f64;
                    }
                    Err(e) => {
                        let mut stats_guard = stats.write().await;
                        stats_guard.transactions_failed += 1;
                        stats_guard.errors.push(format!("Node {}: {}", node_id, e));
                    }
                }
            });
        }
    }

    async fn generate_test_transaction(wallet: &Wallet, rng: &mut impl Rng) -> Transaction {
        // Générer une transaction de transfert simple pour les tests
        let amount = rng.gen_range(1..=100);
        let recipient_address = wallet.get_address(); // Pour simplifier, on s'envoie à nous-même
        
        // Dans un vrai cas, on utiliserait wallet.create_transfer_transaction()
        // Ici on crée une transaction basique pour la démo
        Transaction::new_transfer(
            wallet.get_address(),
            recipient_address,
            amount,
            rng.gen::<u64>(), // nonce aléatoire
            chrono::Utc::now().timestamp() as u64,
        )
    }

    async fn send_transaction(
        client: &Client,
        target_url: &str,
        transaction: &Transaction,
    ) -> Result<Value> {
        let url = format!("{}/api/v1/transactions", target_url);
        
        let response = client
            .post(&url)
            .json(transaction)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .context("Erreur lors de l'envoi de la transaction")?;

        if response.status().is_success() {
            let result: Value = response.json().await
                .context("Erreur lors du parsing de la réponse")?;
            Ok(result)
        } else {
            Err(anyhow::anyhow!("Erreur HTTP: {}", response.status()))
        }
    }

    async fn stats_monitor(stats: Arc<RwLock<SimulationStats>>, duration: u64) {
        let mut interval = interval(Duration::from_secs(5));
        let start_time = Instant::now();
        let mut last_tx_count = 0;

        while start_time.elapsed().as_secs() < duration {
            interval.tick().await;
            
            let stats_guard = stats.read().await;
            let current_tx_count = stats_guard.transactions_sent;
            let elapsed = start_time.elapsed().as_secs_f64();
            let current_tps = (current_tx_count - last_tx_count) as f64 / 5.0; // TPS sur les 5 dernières secondes
            
            println!(
                "📈 Stats: {} tx envoyées, {} confirmées, {} échouées | TPS actuel: {:.1} | Temps moyen: {:.1}ms",
                current_tx_count,
                stats_guard.transactions_confirmed,
                stats_guard.transactions_failed,
                current_tps,
                stats_guard.average_response_time
            );

            last_tx_count = current_tx_count;
        }
    }

    async fn print_final_stats(&self, stats: &SimulationStats, duration: u64) {
        println!("\n🏁 === RÉSULTATS DE LA SIMULATION ===");
        println!("⏱️  Durée: {} secondes", duration);
        println!("📤 Transactions envoyées: {}", stats.transactions_sent);
        println!("✅ Transactions confirmées: {}", stats.transactions_confirmed);
        println!("❌ Transactions échouées: {}", stats.transactions_failed);
        println!("📊 TPS moyen: {:.2}", stats.transactions_sent as f64 / duration as f64);
        println!("📊 TPS pic: {:.2}", stats.peak_tps);
        println!("⏱️  Temps de réponse moyen: {:.1}ms", stats.average_response_time);
        
        if !stats.errors.is_empty() {
            println!("\n❌ Erreurs rencontrées:");
            for (i, error) in stats.errors.iter().take(10).enumerate() {
                println!("   {}. {}", i + 1, error);
            }
            if stats.errors.len() > 10 {
                println!("   ... et {} autres erreurs", stats.errors.len() - 10);
            }
        }
        println!("=====================================\n");
    }
}

pub struct MiningSimulator {
    miners: Vec<MinerNode>,
}

#[derive(Debug)]
struct MinerNode {
    id: u32,
    hash_rate: u64, // hashes per second
    blocks_mined: u64,
    total_hashes: u64,
}

impl MinerNode {
    fn new(id: u32, hash_rate: u64) -> Self {
        Self {
            id,
            hash_rate,
            blocks_mined: 0,
            total_hashes: 0,
        }
    }
}

impl MiningSimulator {
    pub fn new() -> Self {
        Self {
            miners: Vec::new(),
        }
    }

    pub async fn simulate_mining_competition(
        &mut self,
        miners_count: u32,
        duration: u64,
        difficulty: u64,
    ) -> Result<()> {
        println!("⛏️  Démarrage de la simulation de compétition minière");
        println!("   👥 {} mineurs, difficulté {}, {} secondes", miners_count, difficulty, duration);

        // Initialiser les mineurs avec des hash rates variables
        let mut rng = thread_rng();
        for i in 0..miners_count {
            let base_hash_rate = 1000; // 1000 H/s de base
            let variation = rng.gen_range(50..=200); // Variation de 50% à 200%
            let hash_rate = base_hash_rate * variation / 100;
            
            self.miners.push(MinerNode::new(i, hash_rate));
            println!("   ⚡ Mineur {} initialisé: {} H/s", i, hash_rate);
        }

        let start_time = Instant::now();
        let end_time = start_time + Duration::from_secs(duration);
        
        let mut current_block_height = 0;
        let target = Self::calculate_target(difficulty);

        while Instant::now() < end_time {
            // Simuler une ronde de minage
            let winner = self.simulate_mining_round(target, &mut rng).await;
            
            if let Some(winner_id) = winner {
                current_block_height += 1;
                self.miners[winner_id as usize].blocks_mined += 1;
                
                println!(
                    "🎉 Bloc {} miné par le mineur {} ! (Total: {} blocs)",
                    current_block_height,
                    winner_id,
                    self.miners[winner_id as usize].blocks_mined
                );
            }

            // Attendre un peu avant la prochaine ronde
            sleep(Duration::from_millis(100)).await;
        }

        self.print_mining_results(duration).await;
        Ok(())
    }

    async fn simulate_mining_round(&mut self, target: u64, rng: &mut impl Rng) -> Option<u32> {
        // Chaque mineur essaie de miner pendant cette ronde
        for miner in &mut self.miners {
            let hashes_this_round = miner.hash_rate / 10; // 100ms de minage
            miner.total_hashes += hashes_this_round;

            // Simuler les tentatives de hash
            for _ in 0..hashes_this_round {
                let hash_value: u64 = rng.gen();
                if hash_value < target {
                    return Some(miner.id);
                }
            }
        }
        None
    }

    fn calculate_target(difficulty: u64) -> u64 {
        // Calcul simplifié du target basé sur la difficulté
        // Plus la difficulté est élevée, plus le target est bas
        u64::MAX / (1 << difficulty)
    }

    async fn print_mining_results(&self, duration: u64) {
        println!("\n⛏️  === RÉSULTATS DE LA COMPÉTITION MINIÈRE ===");
        println!("⏱️  Durée: {} secondes", duration);
        
        let total_blocks: u64 = self.miners.iter().map(|m| m.blocks_mined).sum();
        let total_hashes: u64 = self.miners.iter().map(|m| m.total_hashes).sum();
        
        println!("🏗️  Blocs totaux minés: {}", total_blocks);
        println!("🔢 Hashes totaux: {}", total_hashes);
        println!("📊 Hash rate réseau: {:.2} H/s", total_hashes as f64 / duration as f64);
        
        println!("\n👥 Résultats par mineur:");
        let mut sorted_miners = self.miners.clone();
        sorted_miners.sort_by(|a, b| b.blocks_mined.cmp(&a.blocks_mined));
        
        for (rank, miner) in sorted_miners.iter().enumerate() {
            let percentage = if total_blocks > 0 {
                (miner.blocks_mined as f64 / total_blocks as f64) * 100.0
            } else {
                0.0
            };
            
            println!(
                "   {}. Mineur {} : {} blocs ({:.1}%) - {} H/s - {} hashes totaux",
                rank + 1,
                miner.id,
                miner.blocks_mined,
                percentage,
                miner.hash_rate,
                miner.total_hashes
            );
        }
        println!("===============================================\n");
    }
}

pub struct HighFrequencyTradingSimulator;

impl HighFrequencyTradingSimulator {
    pub async fn simulate_hft(
        bots: u32,
        trades_per_minute: u32,
        duration: u64,
        target_url: &str,
    ) -> Result<()> {
        println!("🤖 Démarrage de la simulation de trading haute fréquence");
        println!("   🤖 {} bots, {} trades/min chacun, {} minutes", bots, trades_per_minute, duration);

        let client = Client::new();
        let mut join_set = JoinSet::new();
        let stats = Arc::new(RwLock::new(SimulationStats::default()));

        for bot_id in 0..bots {
            let client = client.clone();
            let target_url = target_url.to_string();
            let stats = stats.clone();

            join_set.spawn(async move {
                Self::trading_bot(
                    bot_id,
                    client,
                    target_url,
                    trades_per_minute,
                    duration,
                    stats,
                ).await
            });
        }

        // Moniteur de stats
        let stats_monitor = stats.clone();
        join_set.spawn(async move {
            Self::hft_stats_monitor(stats_monitor, duration * 60).await
        });

        // Attendre toutes les tâches
        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                eprintln!("❌ Erreur dans un bot de trading: {}", e);
            }
        }

        let final_stats = stats.read().await.clone();
        Self::print_hft_results(&final_stats, duration).await;

        Ok(())
    }

    async fn trading_bot(
        bot_id: u32,
        client: Client,
        target_url: String,
        trades_per_minute: u32,
        duration_minutes: u64,
        stats: Arc<RwLock<SimulationStats>>,
    ) {
        let mut rng = thread_rng();
        let wallet = Wallet::new();
        let trade_interval = Duration::from_millis(60_000 / trades_per_minute as u64);
        let end_time = Instant::now() + Duration::from_secs(duration_minutes * 60);

        let mut interval = interval(trade_interval);

        while Instant::now() < end_time {
            interval.tick().await;

            // Générer un trade aléatoire
            let trade_type = if rng.gen_bool(0.5) { "buy" } else { "sell" };
            let amount = rng.gen_range(1..=50);
            let price = rng.gen_range(90..=110); // Prix autour de 100

            let start = Instant::now();
            
            match Self::execute_trade(&client, &target_url, &wallet, trade_type, amount, price).await {
                Ok(_) => {
                    let response_time = start.elapsed().as_millis() as f64;
                    let mut stats_guard = stats.write().await;
                    stats_guard.transactions_sent += 1;
                    stats_guard.average_response_time = 
                        (stats_guard.average_response_time * (stats_guard.transactions_sent - 1) as f64 + response_time) 
                        / stats_guard.transactions_sent as f64;
                }
                Err(e) => {
                    let mut stats_guard = stats.write().await;
                    stats_guard.transactions_failed += 1;
                    stats_guard.errors.push(format!("Bot {}: {}", bot_id, e));
                }
            }
        }
    }

    async fn execute_trade(
        client: &Client,
        target_url: &str,
        wallet: &Wallet,
        trade_type: &str,
        amount: u64,
        price: u64,
    ) -> Result<Value> {
        // Simuler un ordre de trading
        let order = json!({
            "type": trade_type,
            "amount": amount,
            "price": price,
            "trader": wallet.get_address().to_string(),
            "timestamp": chrono::Utc::now().timestamp()
        });

        let url = format!("{}/api/v1/orders", target_url);
        
        let response = client
            .post(&url)
            .json(&order)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .context("Erreur lors de l'envoi de l'ordre")?;

        if response.status().is_success() {
            let result: Value = response.json().await
                .context("Erreur lors du parsing de la réponse")?;
            Ok(result)
        } else {
            Err(anyhow::anyhow!("Erreur HTTP: {}", response.status()))
        }
    }

    async fn hft_stats_monitor(stats: Arc<RwLock<SimulationStats>>, duration_seconds: u64) {
        let mut interval = interval(Duration::from_secs(10));
        let start_time = Instant::now();

        while start_time.elapsed().as_secs() < duration_seconds {
            interval.tick().await;
            
            let stats_guard = stats.read().await;
            let elapsed_minutes = start_time.elapsed().as_secs_f64() / 60.0;
            let tpm = stats_guard.transactions_sent as f64 / elapsed_minutes; // Trades per minute
            
            println!(
                "📈 HFT Stats: {} trades, {} échoués | TPM: {:.1} | Latence moy: {:.1}ms",
                stats_guard.transactions_sent,
                stats_guard.transactions_failed,
                tpm,
                stats_guard.average_response_time
            );
        }
    }

    async fn print_hft_results(stats: &SimulationStats, duration_minutes: u64) {
        println!("\n🤖 === RÉSULTATS HFT SIMULATION ===");
        println!("⏱️  Durée: {} minutes", duration_minutes);
        println!("📤 Trades exécutés: {}", stats.transactions_sent);
        println!("❌ Trades échoués: {}", stats.transactions_failed);
        println!("📊 TPM moyen: {:.2}", stats.transactions_sent as f64 / duration_minutes as f64);
        println!("⏱️  Latence moyenne: {:.1}ms", stats.average_response_time);
        
        let success_rate = if stats.transactions_sent + stats.transactions_failed > 0 {
            (stats.transactions_sent as f64 / (stats.transactions_sent + stats.transactions_failed) as f64) * 100.0
        } else {
            0.0
        };
        println!("✅ Taux de succès: {:.1}%", success_rate);
        println!("==================================\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_calculation() {
        let target_16 = MiningSimulator::calculate_target(16);
        let target_20 = MiningSimulator::calculate_target(20);
        
        // Plus la difficulté est élevée, plus le target est bas
        assert!(target_20 < target_16);
    }

    #[tokio::test]
    async fn test_mining_simulation() {
        let mut simulator = MiningSimulator::new();
        
        // Test avec une durée très courte
        let result = simulator.simulate_mining_competition(2, 1, 10).await;
        assert!(result.is_ok());
        
        // Vérifier que les mineurs ont été créés
        assert_eq!(simulator.miners.len(), 2);
    }
}