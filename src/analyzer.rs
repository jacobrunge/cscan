use anyhow::{Context, Result};
use serde::Serialize;
use tree_sitter::{Node, Parser};

use crate::rules::{Severity, classify, has_non_literal_format};

#[derive(Debug, Serialize)]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub cwe: u32,
    pub function: String,
    pub message: String,
    pub severity: Severity,
}

pub fn walk(node: Node, source: &str, path: &str, findings: &mut Vec<Finding>) {
    if node.kind() == "call_expression" {
        let function = node.child_by_field_name("function").unwrap();
        let name = function.utf8_text(source.as_bytes()).unwrap();
        if let Some((severity, cwe)) = classify(name) {
            findings.push(Finding {
                path: path.to_string(),
                line: node.start_position().row + 1,
                function: name.to_string(),
                message: format!("call to {}", name),
                severity,
                cwe,
            });
        }
        if has_non_literal_format(node, name) {
            findings.push(Finding {
                path: path.to_string(),
                line: node.start_position().row + 1,
                function: name.to_string(),
                message: format!("non-literal format string in call to {}", name),
                severity: Severity::High,
                cwe: 134,
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, path, findings);
    }
}

pub fn analyze(source: &str, path: &str) -> Result<Vec<Finding>> {
    let mut parser = Parser::new();

    parser.set_language(&tree_sitter_c::LANGUAGE.into())?;

    let tree = parser
        .parse(source, None)
        .context("Failed to parse source code")?;

    let mut findings = Vec::new();
    walk(tree.root_node(), source, path, &mut findings);
    Ok(findings)
}

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
    #[test]
    fn flags_non_literal_format_string() {
        let source = "void f(char *input) { printf(input); }";
        let findings = analyze(source, "test.c").unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].function, "printf");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cwe, 134);
    }

    #[test]
    fn allows_literal_format_string() {
        let source = r#"void f(char *input) { printf("%s", input); }"#;
        let findings = analyze(source, "test.c").unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn sprintf_with_variable_format() {
        let source = "void f (char *buf, char *input) {
        sprintf(buf,input); }";
        let findings = analyze(source, "test.c").unwrap();

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].function, "sprintf");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cwe, 120);
        assert_eq!(findings[1].cwe, 134);
    }

    #[test]
    fn check_fprintf_expected_arg() {
        let source = "void f(char *input) {
        fprintf(stderr, input); }";
        let findings = analyze(source, "test.c").unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].function, "fprintf");
        assert_eq!(findings[0].cwe, 134);
    }

    #[test]
    fn allows_fprintf_literal_format() {
        let source = r#"void f(char *input) {
        fprintf(stderr, "hello"); }"#;
        let findings = analyze(source, "test.c").unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn allows_comment_before_format() {
        let source = r#"void f(char *input) {
        printf(/* greeting */ "hi");"#;
        let findings = analyze(source, "test.c").unwrap();

        assert!(findings.is_empty());
    }
}


