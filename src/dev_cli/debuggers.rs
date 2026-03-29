use crate::core::{Block, Transaction};
use crate::crypto::signature::verify_transaction_signature;
use crate::crypto::proof::verify_transaction_proof;
use crate::network::api::ApiClient;
use anyhow::{Context, Result};
use serde_json;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Interactive transaction validator with step-by-step debugging
pub async fn validate_transaction_interactive(
    transaction_file: PathBuf,
    verbose: bool,
    skip_proofs: bool,
) -> Result<()> {
    println!("🔍 Chargement de la transaction depuis {:?}", transaction_file);
    
    let transaction_data = std::fs::read_to_string(&transaction_file)
        .with_context(|| format!("Impossible de lire le fichier {:?}", transaction_file))?;
    
    let transaction: Transaction = serde_json::from_str(&transaction_data)
        .with_context(|| "Impossible de parser la transaction JSON")?;
    
    println!("✅ Transaction chargée : {}", transaction.hash());
    
    if verbose {
        println!("📋 Détails de la transaction :");
        println!("  - Hash: {}", transaction.hash());
        println!("  - Type: {:?}", transaction.transaction_type());
        println!("  - Timestamp: {}", transaction.timestamp());
        println!("  - Taille: {} bytes", serde_json::to_vec(&transaction)?.len());
    }
    
    // Étape 1: Validation de la structure
    println!("\n🔧 Étape 1: Validation de la structure...");
    if let Err(e) = transaction.validate_structure() {
        println!("❌ Erreur de structure: {}", e);
        return Err(e);
    }
    println!("✅ Structure valide");
    
    // Étape 2: Validation de la signature
    println!("\n🔐 Étape 2: Validation de la signature...");
    match verify_transaction_signature(&transaction) {
        Ok(true) => println!("✅ Signature valide"),
        Ok(false) => {
            println!("❌ Signature invalide");
            return Err(anyhow::anyhow!("Signature invalide"));
        }
        Err(e) => {
            println!("❌ Erreur lors de la vérification de signature: {}", e);
            return Err(e);
        }
    }
    
    // Étape 3: Validation des preuves ZK (optionnel)
    if !skip_proofs {
        println!("\n🧮 Étape 3: Validation des preuves ZK...");
        match verify_transaction_proof(&transaction) {
            Ok(true) => println!("✅ Preuves ZK valides"),
            Ok(false) => {
                println!("❌ Preuves ZK invalides");
                return Err(anyhow::anyhow!("Preuves ZK invalides"));
            }
            Err(e) => {
                println!("❌ Erreur lors de la vérification des preuves: {}", e);
                return Err(e);
            }
        }
    } else {
        println!("\n⏭️  Étape 3: Validation des preuves ZK ignorée");
    }
    
    println!("\n🎉 Transaction valide !");
    Ok(())
}

/// Interactive block validator with step-by-step debugging
pub async fn validate_block_interactive(
    block_file: PathBuf,
    verbose: bool,
    skip_proofs: bool,
) -> Result<()> {
    println!("🔍 Chargement du bloc depuis {:?}", block_file);
    
    let block_data = std::fs::read_to_string(&block_file)
        .with_context(|| format!("Impossible de lire le fichier {:?}", block_file))?;
    
    let block: Block = serde_json::from_str(&block_data)
        .with_context(|| "Impossible de parser le bloc JSON")?;
    
    println!("✅ Bloc chargé : {}", block.hash());
    
    if verbose {
        println!("📋 Détails du bloc :");
        println!("  - Hash: {}", block.hash());
        println!("  - Hauteur: {}", block.height());
        println!("  - Parent: {}", block.parent_hash());
        println!("  - Timestamp: {}", block.timestamp());
        println!("  - Transactions: {}", block.transactions().len());
        println!("  - Taille: {} bytes", serde_json::to_vec(&block)?.len());
    }
    
    // Étape 1: Validation de la structure du bloc
    println!("\n🔧 Étape 1: Validation de la structure du bloc...");
    if let Err(e) = block.validate_structure() {
        println!("❌ Erreur de structure: {}", e);
        return Err(e);
    }
    println!("✅ Structure du bloc valide");
    
    // Étape 2: Validation du proof-of-work
    println!("\n⛏️  Étape 2: Validation du proof-of-work...");
    if let Err(e) = block.validate_pow() {
        println!("❌ Proof-of-work invalide: {}", e);
        return Err(e);
    }
    println!("✅ Proof-of-work valide");
    
    // Étape 3: Validation des transactions
    println!("\n💳 Étape 3: Validation des transactions ({})...", block.transactions().len());
    for (i, tx) in block.transactions().iter().enumerate() {
        if verbose {
            println!("  Validation transaction {}/{}: {}", i + 1, block.transactions().len(), tx.hash());
        }
        
        // Validation de la signature
        match verify_transaction_signature(tx) {
            Ok(true) => {
                if verbose { println!("    ✅ Signature valide"); }
            }
            Ok(false) => {
                println!("    ❌ Signature invalide pour tx {}", tx.hash());
                return Err(anyhow::anyhow!("Transaction {} a une signature invalide", tx.hash()));
            }
            Err(e) => {
                println!("    ❌ Erreur signature pour tx {}: {}", tx.hash(), e);
                return Err(e);
            }
        }
        
        // Validation des preuves ZK (optionnel)
        if !skip_proofs {
            match verify_transaction_proof(tx) {
                Ok(true) => {
                    if verbose { println!("    ✅ Preuves ZK valides"); }
                }
                Ok(false) => {
                    println!("    ❌ Preuves ZK invalides pour tx {}", tx.hash());
                    return Err(anyhow::anyhow!("Transaction {} a des preuves ZK invalides", tx.hash()));
                }
                Err(e) => {
                    println!("    ❌ Erreur preuves ZK pour tx {}: {}", tx.hash(), e);
                    return Err(e);
                }
            }
        }
    }
    println!("✅ Toutes les transactions sont valides");
    
    println!("\n🎉 Bloc valide !");
    Ok(())
}

/// Trace l'exécution d'une transaction sur le réseau
pub async fn trace_transaction_execution(
    tx_hash: String,
    node_url: String,
    show_state: bool,
) -> Result<()> {
    println!("🔍 Traçage de la transaction {} sur {}", tx_hash, node_url);
    
    let client = ApiClient::new(&node_url)?;
    
    // Récupérer les détails de la transaction
    println!("\n📡 Récupération des détails de la transaction...");
    let tx_details = client.get_transaction(&tx_hash).await
        .with_context(|| format!("Impossible de récupérer la transaction {}", tx_hash))?;
    
    println!("✅ Transaction trouvée dans le bloc {}", tx_details.block_hash);
    println!("📋 Détails :");
    println!("  - Status: {:?}", tx_details.status);
    println!("  - Bloc: {} (hauteur {})", tx_details.block_hash, tx_details.block_height);
    println!("  - Index dans le bloc: {}", tx_details.transaction_index);
    println!("  - Gas utilisé: {}", tx_details.gas_used);
    println!("  - Frais: {} TSN", tx_details.fee);
    
    if show_state {
        println!("\n🔄 Changements d'état :");
        for change in &tx_details.state_changes {
            println!("  - {}: {} → {}", change.account, change.before, change.after);
        }
    }
    
    // Tracer la propagation réseau
    println!("\n🌐 Traçage de la propagation réseau...");
    let propagation_info = client.get_transaction_propagation(&tx_hash).await
        .with_context(|| "Impossible de récupérer les infos de propagation")?;
    
    println!("📊 Statistiques de propagation :");
    println!("  - Première vue: {}", propagation_info.first_seen);
    println!("  - Confirmée: {}", propagation_info.confirmed_at);
    println!("  - Délai de propagation: {}ms", propagation_info.propagation_delay_ms);
    println!("  - Nœuds ayant vu la tx: {}", propagation_info.nodes_seen);
    
    Ok(())
}

/// Profiler de performance pour différentes opérations
pub async fn profile_operation(
    operation: String,
    duration: u64,
    output_file: PathBuf,
) -> Result<()> {
    println!("📊 Profilage de l'opération '{}' pendant {}s", operation, duration);
    
    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(duration);
    
    let mut samples = Vec::new();
    let mut sample_count = 0;
    
    while Instant::now() < end_time {
        let sample_start = Instant::now();
        
        // Exécuter l'opération selon le type
        let result = match operation.as_str() {
            "mining" => profile_mining_operation().await,
            "validation" => profile_validation_operation().await,
            "sync" => profile_sync_operation().await,
            _ => {
                return Err(anyhow::anyhow!("Opération '{}' non supportée", operation));
            }
        };
        
        let sample_duration = sample_start.elapsed();
        sample_count += 1;
        
        let sample = ProfileSample {
            timestamp: sample_start,
            duration_ms: sample_duration.as_millis() as u64,
            operation: operation.clone(),
            success: result.is_ok(),
            error: result.err().map(|e| e.to_string()),
        };
        
        samples.push(sample);
        
        if sample_count % 10 == 0 {
            println!("📈 {} échantillons collectés...", sample_count);
        }
        
        // Attendre avant le prochain échantillon
        sleep(Duration::from_millis(100)).await;
    }
    
    // Calculer les statistiques
    let total_samples = samples.len();
    let successful_samples = samples.iter().filter(|s| s.success).count();
    let avg_duration = samples.iter().map(|s| s.duration_ms).sum::<u64>() / total_samples as u64;
    let min_duration = samples.iter().map(|s| s.duration_ms).min().unwrap_or(0);
    let max_duration = samples.iter().map(|s| s.duration_ms).max().unwrap_or(0);
    
    println!("\n📊 Résultats du profilage :");
    println!("  - Échantillons totaux: {}", total_samples);
    println!("  - Échantillons réussis: {} ({:.1}%)", successful_samples, 
             (successful_samples as f64 / total_samples as f64) * 100.0);
    println!("  - Durée moyenne: {}ms", avg_duration);
    println!("  - Durée min/max: {}ms / {}ms", min_duration, max_duration);
    
    // Sauvegarder les données
    let profile_data = ProfileData {
        operation,
        duration_seconds: duration,
        total_samples,
        successful_samples,
        avg_duration_ms: avg_duration,
        min_duration_ms: min_duration,
        max_duration_ms: max_duration,
        samples,
    };
    
    let json_data = serde_json::to_string_pretty(&profile_data)?;
    std::fs::write(&output_file, json_data)
        .with_context(|| format!("Impossible d'écrire le fichier {:?}", output_file))?;
    
    println!("💾 Données de profilage sauvegardées dans {:?}", output_file);
    
    Ok(())
}

/// Analyseur d'utilisation mémoire
pub async fn analyze_memory_usage(
    node_url: String,
    interval: u64,
    duration: u64,
) -> Result<()> {
    println!("🧠 Analyse de la mémoire sur {} (échantillonnage: {}s, durée: {}s)", 
             node_url, interval, duration);
    
    let client = ApiClient::new(&node_url)?;
    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(duration);
    
    let mut samples = Vec::new();
    
    while Instant::now() < end_time {
        let sample_start = Instant::now();
        
        // Récupérer les stats mémoire du nœud
        match client.get_memory_stats().await {
            Ok(stats) => {
                samples.push(MemorySample {
                    timestamp: sample_start,
                    heap_used_mb: stats.heap_used / 1024 / 1024,
                    heap_total_mb: stats.heap_total / 1024 / 1024,
                    rss_mb: stats.rss / 1024 / 1024,
                    mempool_size: stats.mempool_transactions,
                    blockchain_size_mb: stats.blockchain_size / 1024 / 1024,
                });
                
                println!("📊 Heap: {}MB / {}MB, RSS: {}MB, Mempool: {} tx", 
                         stats.heap_used / 1024 / 1024,
                         stats.heap_total / 1024 / 1024,
                         stats.rss / 1024 / 1024,
                         stats.mempool_transactions);
            }
            Err(e) => {
                println!("⚠️  Erreur lors de la récupération des stats: {}", e);
            }
        }
        
        sleep(Duration::from_secs(interval)).await;
    }
    
    // Analyser les tendances
    if !samples.is_empty() {
        let avg_heap = samples.iter().map(|s| s.heap_used_mb).sum::<u64>() / samples.len() as u64;
        let max_heap = samples.iter().map(|s| s.heap_used_mb).max().unwrap_or(0);
        let avg_rss = samples.iter().map(|s| s.rss_mb).sum::<u64>() / samples.len() as u64;
        let max_rss = samples.iter().map(|s| s.rss_mb).max().unwrap_or(0);
        
        println!("\n📈 Analyse de la mémoire :");
        println!("  - Heap moyen/max: {}MB / {}MB", avg_heap, max_heap);
        println!("  - RSS moyen/max: {}MB / {}MB", avg_rss, max_rss);
        
        // Détecter les fuites potentielles
        if samples.len() >= 10 {
            let first_half_avg = samples[..samples.len()/2].iter()
                .map(|s| s.heap_used_mb).sum::<u64>() / (samples.len()/2) as u64;
            let second_half_avg = samples[samples.len()/2..].iter()
                .map(|s| s.heap_used_mb).sum::<u64>() / (samples.len()/2) as u64;
            
            if second_half_avg > first_half_avg * 110 / 100 {
                println!("⚠️  Fuite mémoire potentielle détectée (+{}MB)", 
                         second_half_avg - first_half_avg);
            }
        }
    }
    
    Ok(())
}

// Fonctions d'aide pour le profilage
async fn profile_mining_operation() -> Result<()> {
    // Simuler une opération de minage
    sleep(Duration::from_millis(50)).await;
    Ok(())
}

async fn profile_validation_operation() -> Result<()> {
    // Simuler une validation de transaction
    sleep(Duration::from_millis(10)).await;
    Ok(())
}

async fn profile_sync_operation() -> Result<()> {
    // Simuler une synchronisation
    sleep(Duration::from_millis(100)).await;
    Ok(())
}

// Structures de données pour le profilage
#[derive(serde::Serialize, serde::Deserialize)]
struct ProfileSample {
    timestamp: Instant,
    duration_ms: u64,
    operation: String,
    success: bool,
    error: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProfileData {
    operation: String,
    duration_seconds: u64,
    total_samples: usize,
    successful_samples: usize,
    avg_duration_ms: u64,
    min_duration_ms: u64,
    max_duration_ms: u64,
    samples: Vec<ProfileSample>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MemorySample {
    timestamp: Instant,
    heap_used_mb: u64,
    heap_total_mb: u64,
    rss_mb: u64,
    mempool_size: usize,
    blockchain_size_mb: u64,
}