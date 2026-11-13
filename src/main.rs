use anyhow::{Context, Result, bail};
use clap::{Parser as ClapParser, ValueEnum};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use rules::{Severity};
mod analyzer;
mod rules;
use analyzer::{Finding, analyze};

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

fn to_sarif(findings: &[Finding]) -> serde_json::Value {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical => "error",
                Severity::High => "warning",
            };
            json!({
                "ruleId": format!("CWE-{}", f.cwe),
                "level": level,
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.path.replace('\\', "/") },
                        "region": { "startLine": f.line }
                    }
                }]
            })
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cscan",
                    "version": env!("CARGO_PKG_VERSION")
                }
            },
            "results": results
        }]
    })
}

fn main() -> Result<()> {
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
    if !findings.is_empty() {
        std::process::exit(1)
    }
    Ok(())
}

// Unit testing below

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sarif_output_has_rule_and_location() {
        let source = "void f(char *buf) { gets(buf); }";
        let findings = analyze(source, "src\\test.c").unwrap();
        let sarif = to_sarif(&findings);

        assert_eq!(sarif["version"], "2.1.0");

        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "CWE-242");
        assert_eq!(result["level"], "error");

        let location = &result["locations"][0]["physicalLocation"];
        assert_eq!(location["region"]["startLine"], 1);
        assert_eq!(location["artifactLocation"]["uri"], "src/test.c");
    }
}
