use anyhow::{Context, Result, bail};
use clap::{Parser as ClapParser, ValueEnum};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use tree_sitter::{Node, Parser};
use walkdir::WalkDir;

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
}

#[derive(Debug, PartialEq, Serialize)]
enum Severity {
    High,
    Critical,
}

#[derive(Debug, Serialize)]
struct Finding {
    path: String,
    line: usize,
    function: String,
    severity: Severity,
    cwe: u32,
}

fn classify(name: &str) -> Option<(Severity, u32)> {
    match name {
        "gets" => Some((Severity::Critical, 242)),
        "strcpy" | "strcat" | "vsprintf" | "sprintf" => Some((Severity::High, 120)),
        _ => None,
    }
}

fn walk(node: Node, source: &str, path: &str, findings: &mut Vec<Finding>) {
    if node.kind() == "call_expression" {
        let function = node.child_by_field_name("function").unwrap();
        let name = function.utf8_text(source.as_bytes()).unwrap();
        if let Some((severity, cwe)) = classify(name) {
            findings.push(Finding {
                path: path.to_string(),
                line: node.start_position().row + 1,
                function: name.to_string(),
                severity,
                cwe,
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, path, findings);
    }
}

fn analyze(source: &str, path: &str) -> Result<Vec<Finding>> {
    let mut parser = Parser::new();

    parser.set_language(&tree_sitter_c::LANGUAGE.into())?;

    let tree = parser
        .parse(source, None)
        .context("Failed to parse source code")?;

    let mut findings = Vec::new();
    walk(tree.root_node(), source, path, &mut findings);
    Ok(findings)
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
                    "{}:{}: [{:?}] CWE-{}: call to {}",
                    f.path, f.line, f.severity, f.cwe, f.function
                );
            }
            println!("{} finding(s) in {} file(s)", findings.len(), files.len());
        }
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&findings)?);
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
    fn finds_strcpy() {
        let source = "void f(char *a, char *b) {strcpy(a, b); }";
        let findings = analyze(source, "test.c").unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].function, "strcpy");
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cwe, 120);
    }
    #[test]
    fn ignores_safe_calls() {
        let source = r#"void f(char *a) { printf("%s", a);
        puts(a); }"#;

        let findings = analyze(source, "test.c").unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_comments_and_strings() {
        let source = r#"/* Never use strcpy */
        void f(void) { 
        const char *msg = "gets is unsafe"; }"#;

        let findings = analyze(source, "test.c").unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn finds_nested_calls() {
        let source = r#"void f(char *a, char *b) {
         strcpy(a, gets(b)); 
         }"#;

        let findings = analyze(source, "test.c").unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].function, "strcpy");
        assert_eq!(findings[1].function, "gets");
    }

    #[test]
    fn gets_is_critical() {
        let source = "void f(char *buf) { gets(buf); }";
        let findings = analyze(source, "test.c").unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].function, "gets");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].cwe, 242);
    }
}
