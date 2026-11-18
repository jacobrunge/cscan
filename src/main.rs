use anyhow::{Context, Result, bail};
use clap::{Parser as ClapParser, ValueEnum};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

mod analyzer;
mod output;
mod rules;

use analyzer::analyze;
use output::to_sarif;

/// Static analyzer that finds memory-safety bugs in C source code
#[derive(ClapParser)]
#[command(version)]
struct Cli {
    /// File or Directory to scan
    path: String,

    /// Output
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

#[derive(Clone, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

fn is_c_file(path: &Path) -> bool {
    match path.extension() {
        Some(ext) => ext == "c" || ext == "h",
        None => false,
    }
}

fn collect_files(root: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root) {
        let Ok(entry) = entry else {
            continue;
        };
        if entry.file_type().is_file() && is_c_file(entry.path()) {
            files.push(entry.path().to_path_buf());
        }
    }
    files
}

fn run() -> Result<bool> {
    let cli = Cli::parse();

    let files = collect_files(&cli.path);
    if files.is_empty() {
        bail!("No .c or .h files found in {}", cli.path);
    }

    let mut findings = Vec::new();
    for file in &files {
        let path = file.display().to_string();
        let source =
            fs::read_to_string(file).with_context(|| format!("Failed to read file {}", path))?;
        findings.extend(analyze(&source, &path)?);
    }

    match cli.format {
        Format::Text => {
            for f in &findings {
                println!(
                    "{}:{}: [{:?}] CWE-{}: {}",
                    f.path, f.line, f.severity, f.cwe, f.message
                );
            }
            println!("{} finding(s) in {} file(s)", findings.len(), files.len());
        }
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&findings)?);
        }
        Format::Sarif => {
            println!("{}", serde_json::to_string_pretty(&to_sarif(&findings))?);
        }
    }
        Ok(!findings.is_empty())
}

fn main() {
    match run() {
        Ok(true) => std::process::exit(1),
        Ok(false) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {:#}", e);
            std::process::exit(2);
        }
    }
}
