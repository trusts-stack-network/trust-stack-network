//! Scanner statique pour détecter les unwrap(), expect() et panic!()
//!
//! Ce module fournit des outils pour scanner le codebase et identifier
//! les occurrences non justifiées de fonctions de panics.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Résultat d'un scan de fichier
#[derive(Debug, Clone)]
pub struct PanicScanResult {
    /// Chemin du fichier scanné
    pub file_path: PathBuf,
    /// Lignes contenant des unwrap()
    pub unwrap_lines: Vec<LineInfo>,
    /// Lignes contenant des expect()
    pub expect_lines: Vec<LineInfo>,
    /// Lignes contenant des panic!()
    pub panic_lines: Vec<LineInfo>,
    /// Lignes contenant des unwrap_or_default() (safe)
    pub unwrap_or_default_lines: Vec<LineInfo>,
}

/// Information sur une ligne de code
#[derive(Debug, Clone)]
pub struct LineInfo {
    pub line_number: usize,
    pub content: String,
    pub context: String, // 3 lignes avant/après
}

impl PanicScanResult {
    /// Créer un nouveau résultat de scan
    pub fn new(file_path: PathBuf) -> Self {
        Self {
            file_path,
            unwrap_lines: Vec::new(),
            expect_lines: Vec::new(),
            panic_lines: Vec::new(),
            unwrap_or_default_lines: Vec::new(),
        }
    }

    /// Nombre total de panics potentiels
    pub fn total_panics(&self) -> usize {
        self.unwrap_lines.len() + self.expect_lines.len() + self.panic_lines.len()
    }

    /// Nombre de unwrap() non sécurisés
    pub fn dangerous_unwraps(&self) -> usize {
        // unwrap_or_default est considéré comme sûr
        self.unwrap_lines.len()
    }
}

/// Scanner de codebase pour détecter les panics
pub struct PanicScanner {
    /// Répertoire racine à scanner
    root_dir: PathBuf,
    /// Fichiers à exclure
    exclude_patterns: Vec<String>,
    /// Résultats du scan
    results: Vec<PanicScanResult>,
}

impl PanicScanner {
    /// Créer un nouveau scanner
    pub fn new(root_dir: impl AsRef<Path>) -> Self {
        Self {
            root_dir: root_dir.as_ref().to_path_buf(),
            exclude_patterns: vec![
                "target/".to_string(),
                ".git/".to_string(),
                "tests/".to_string(), // Exclure les tests eux-mêmes
            ],
            results: Vec::new(),
        }
    }

    /// Ajouter un pattern d'exclusion
    pub fn exclude(mut self, pattern: &str) -> Self {
        self.exclude_patterns.push(pattern.to_string());
        self
    }

    /// Scanner le codebase
    pub fn scan(&mut self) -> Result<&[PanicScanResult], ScanError> {
        self.results.clear();
        self.scan_directory(&self.root_dir.clone())?;
        Ok(&self.results)
    }

    /// Scanner un répertoire récursivement
    fn scan_directory(&mut self, dir: &Path) -> Result<(), ScanError> {
        if self.should_exclude(dir) {
            return Ok(());
        }

        for entry in fs::read_dir(dir).map_err(|e| ScanError::IoError(e))? {
            let entry = entry.map_err(|e| ScanError::IoError(e))?;
            let path = entry.path();

            if path.is_dir() {
                self.scan_directory(&path)?;
            } else if path.extension().map_or(false, |ext| ext == "rs") {
                self.scan_file(&path)?;
            }
        }

        Ok(())
    }

    /// Scanner un fichier Rust
    fn scan_file(&mut self, path: &Path) -> Result<(), ScanError> {
        if self.should_exclude(path) {
            return Ok(());
        }

        let content = fs::read_to_string(path).map_err(|e| ScanError::IoError(e))?;
        let lines: Vec<&str> = content.lines().collect();

        let mut result = PanicScanResult::new(path.to_path_buf());

        for (i, line) in lines.iter().enumerate() {
            let line_num = i + 1;
            let trimmed = line.trim();

            // Ignorer les commentaires
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            // Détecter unwrap() mais pas unwrap_or_default() ou unwrap_or()
            if trimmed.contains(".unwrap()") && 
               !trimmed.contains("unwrap_or_default()") &&
               !trimmed.contains("unwrap_or(") {
                let context = self.get_context(&lines, i);
                result.unwrap_lines.push(LineInfo {
                    line_number: line_num,
                    content: line.to_string(),
                    context,
                });
            }

            // Détecter expect()
            if trimmed.contains(".expect(") {
                let context = self.get_context(&lines, i);
                result.expect_lines.push(LineInfo {
                    line_number: line_num,
                    content: line.to_string(),
                    context,
                });
            }

            // Détecter panic!()
            if trimmed.contains("panic!(") {
                let context = self.get_context(&lines, i);
                result.panic_lines.push(LineInfo {
                    line_number: line_num,
                    content: line.to_string(),
                    context,
                });
            }

            // Détecter unwrap_or_default() (pour statistiques)
            if trimmed.contains("unwrap_or_default()") {
                let context = self.get_context(&lines, i);
                result.unwrap_or_default_lines.push(LineInfo {
                    line_number: line_num,
                    content: line.to_string(),
                    context,
                });
            }
        }

        // Ne garder que les fichiers avec des résultats
        if result.total_panics() > 0 {
            self.results.push(result);
        }

        Ok(())
    }

    /// Obtenir le contexte (3 lignes avant/après)
    fn get_context(&self, lines: &[&str], index: usize) -> String {
        let start = index.saturating_sub(3);
        let end = (index + 4).min(lines.len());
        
        lines[start..end]
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let line_num = start + i + 1;
                let marker = if start + i == index { ">>>" } else { "   " };
                format!("{} {}: {}", marker, line_num, line)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Vérifier si un chemin doit être exclu
    fn should_exclude(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        self.exclude_patterns.iter().any(|pattern| {
            path_str.contains(pattern)
        })
    }

    /// Générer un rapport
    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str("# Panic Audit Report\n\n");
        report.push_str(&format!("Generated: {}\n", chrono::Local::now()));
        report.push_str(&format!("Root directory: {}\n\n", self.root_dir.display()));

        // Statistiques globales
        let total_unwraps: usize = self.results.iter().map(|r| r.unwrap_lines.len()).sum();
        let total_expects: usize = self.results.iter().map(|r| r.expect_lines.len()).sum();
        let total_panics: usize = self.results.iter().map(|r| r.panic_lines.len()).sum();
        let total_safe: usize = self.results.iter().map(|r| r.unwrap_or_default_lines.len()).sum();

        report.push_str("## Summary\n\n");
        report.push_str(&format!("- Files with panics: {}\n", self.results.len()));
        report.push_str(&format!("- Total unwrap(): {}\n", total_unwraps));
        report.push_str(&format!("- Total expect(): {}\n", total_expects));
        report.push_str(&format!("- Total panic!(): {}\n", total_panics));
        report.push_str(&format!("- Safe unwrap_or_default(): {}\n\n", total_safe));

        // Détails par fichier
        report.push_str("## Details by File\n\n");
        
        for result in &self.results {
            report.push_str(&format!("### {}\n\n", result.file_path.display()));
            
            if !result.unwrap_lines.is_empty() {
                report.push_str("#### unwrap() calls:\n\n");
                for line in &result.unwrap_lines {
                    report.push_str(&format!(
                        "Line {}:\n```rust\n{}\n```\n\n",
                        line.line_number, line.content
                    ));
                }
            }

            if !result.expect_lines.is_empty() {
                report.push_str("#### expect() calls:\n\n");
                for line in &result.expect_lines {
                    report.push_str(&format!(
                        "Line {}:\n```rust\n{}\n```\n\n",
                        line.line_number, line.content
                    ));
                }
            }

            if !result.panic_lines.is_empty() {
                report.push_str("#### panic!() calls:\n\n");
                for line in &result.panic_lines {
                    report.push_str(&format!(
                        "Line {}:\n```rust\n{}\n```\n\n",
                        line.line_number, line.content
                    ));
                }
            }
        }

        // Recommandations
        report.push_str("## Recommendations\n\n");
        report.push_str("1. Remplacer tous les `unwrap()` par `?` ou `match`\n");
        report.push_str("2. Documenter tous les `expect()` avec un commentaire justifiant le panic\n");
        report.push_str("3. Utiliser `unwrap_or_default()` ou `unwrap_or()` quand approprié\n");
        report.push_str("4. Activer `clippy::unwrap_used` dans le CI\n");

        report
    }
}

/// Erreurs de scan
#[derive(Debug)]
pub enum ScanError {
    IoError(std::io::Error),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for ScanError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test que le scanner détecte correctement les unwrap()
    #[test]
    fn test_scanner_detects_unwrap() {
        // Créer un fichier temporaire avec du code de test
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_unwrap.rs");
        
        fs::write(
            &test_file,
            r#"
fn test_function() {
    let x = Some(42);
    let y = x.unwrap(); // Dangerous
    let z = x.unwrap_or_default(); // Safe
}
"#
        ).unwrap();

        let mut scanner = PanicScanner::new(&temp_dir);
        let results = scanner.scan().unwrap();

        // Nettoyer
        let _ = fs::remove_file(&test_file);

        // Vérifier que le fichier a été trouvé
        assert!(!results.is_empty(), "Should find unwrap in test file");
    }

    /// Test que le rapport est généré correctement
    #[test]
    fn test_report_generation() {
        let scanner = PanicScanner::new("/tmp");
        let report = scanner.generate_report();
        
        assert!(report.contains("Panic Audit Report"));
        assert!(report.contains("Summary"));
    }

    /// Test d'intégration sur le codebase TSN
    #[test]
    #[ignore = "Long running test - run manually"]
    fn test_scan_tsn_codebase() {
        let mut scanner = PanicScanner::new("../../src");
        let results = scanner.scan().expect("Failed to scan codebase");

        println!("Found {} files with potential panics", results.len());
        
        for result in results {
            println!("\nFile: {}", result.file_path.display());
            println!("  unwrap(): {}", result.unwrap_lines.len());
            println!("  expect(): {}", result.expect_lines.len());
            println!("  panic!(): {}", result.panic_lines.len());
        }

        // Générer le rapport
        let report = scanner.generate_report();
        let report_path = PathBuf::from("../../docs/security/panic_scan_report.md");
        fs::write(report_path, report).expect("Failed to write report");
    }
}

/// Fonction utilitaire pour exécuter le scan depuis la ligne de commande
pub fn run_audit() {
    println!("🔍 Starting panic audit scan...");
    
    let mut scanner = PanicScanner::new("src");
    match scanner.scan() {
        Ok(results) => {
            println!("\n📊 Scan Results:");
            println!("================");
            
            let total_unwraps: usize = results.iter().map(|r| r.unwrap_lines.len()).sum();
            let total_expects: usize = results.iter().map(|r| r.expect_lines.len()).sum();
            let total_panics: usize = results.iter().map(|r| r.panic_lines.len()).sum();
            
            println!("Files with panics: {}", results.len());
            println!("Total unwrap(): {}", total_unwraps);
            println!("Total expect(): {}", total_expects);
            println!("Total panic!(): {}", total_panics);
            
            if !results.is_empty() {
                println!("\n⚠️  Found potential panics in the following files:");
                for result in results {
                    println!("\n  📄 {}", result.file_path.display());
                    if !result.unwrap_lines.is_empty() {
                        println!("     - {} unwrap() calls", result.unwrap_lines.len());
                    }
                    if !result.expect_lines.is_empty() {
                        println!("     - {} expect() calls", result.expect_lines.len());
                    }
                    if !result.panic_lines.is_empty() {
                        println!("     - {} panic!() calls", result.panic_lines.len());
                    }
                }
                
                println!("\n❌ Audit FAILED - Please fix the issues above");
                std::process::exit(1);
            } else {
                println!("\n✅ Audit PASSED - No dangerous panics found");
            }
        }
        Err(e) => {
            eprintln!("❌ Scan failed: {}", e);
            std::process::exit(1);
        }
    }
}