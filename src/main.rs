use tree_sitter::{Node, Parser};
use anyhow::{Context, Result};
use std::env;
use std::fs;


fn walk(node: Node, source: &str) {
    if node.kind() == "call_expression" {
        let function = node.child_by_field_name("function").unwrap();
        let name = function.utf8_text(source.as_bytes()).unwrap();
        let line = node.start_position().row + 1;
        let banned = ["gets", "strcpy", "strcat", "sprintf"];
        if banned.contains(&name) {
            println!("line {}: call to banned function {}", line, name);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source);
    }
}

fn main() -> Result <()> {
   let path = env::args().nth(1).context("Usage: cscan <file.c>")?;
   let source = fs::read_to_string(&path).with_context(|| format!("Failed to read file {}", path))?;
   

    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .unwrap();

    let tree = parser.parse(&source, None).context("Failed to parse source code")?;

    walk(tree.root_node(), &source);
    Ok(())
}
