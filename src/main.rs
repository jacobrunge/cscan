use anyhow::{Context, Result};
use std::env;
use std::fs;
use tree_sitter::{Node, Parser};

#[derive(Debug, PartialEq)]
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

fn main() -> Result<()> {
    let path = env::args().nth(1).context("Usage: cscan <file.c>")?;
    let source =
        fs::read_to_string(&path).with_context(|| format!("Failed to read file {}", path))?;

    let findings = analyze(&source, &path)?;

    for f in &findings {
        println!(
            "{}:{}: [{:?}] CWE-{}: call to {}",
            f.path, f.line, f.severity, f.cwe, f.function
        );
    }
    println!("{} finding(s)", findings.len());
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
        void f(const char *msg) { *msg = "gets in unsafe"; }"#;
        
        let findings = analyze(source, "test.c").unwrap();
        assert!(findings.is_empty());
    }

    #[test] 
    fn finds_nested_calls() {
        let source = r#"void f(char *a, char *b) {
         strcpy(a, gets(b)); 
         }"#;

        let findings = analyze(source, "test,c").unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].function, "strcpy");
        assert_eq!(findings[1].function, "gets");





    }
}
