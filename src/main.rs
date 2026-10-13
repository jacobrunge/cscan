use anyhow::{Context, Result};
use std::env;
use std::fs;
use tree_sitter::{Node, Parser};

#[derive(Debug)]
enum Severity {
    High,
    Critical,
}

#[derive(Debug)]
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
        "strcpy" | "strcat" => Some((Severity::High, 120)),
        "sprintf" => Some((Severity::High, 120)),
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

fn main() -> Result<()> {
    let path = env::args().nth(1).context("Usage: cscan <file.c>")?;
    let source =
        fs::read_to_string(&path).with_context(|| format!("Failed to read file {}", path))?;

    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_c::LANGUAGE.into())?;

    let tree = parser
        .parse(&source, None)
        .context("Failed to parse source code")?;

    let mut findings = Vec::new();
    walk(tree.root_node(), &source, &path, &mut findings);

    for f in &findings {
        println!(
            "{}:{}: [{:?}] CWE-{}: call to {}",
            f.path, f.line, f.severity, f.cwe, f.function
        );
    }
    println!("{} finding(s)", findings.len());
    Ok(())
}
