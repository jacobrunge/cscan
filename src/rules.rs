use serde::Serialize;
use tree_sitter::Node;

#[derive(Debug, PartialEq, Serialize)]
pub enum Severity {
    High,
    Critical,
}

pub fn classify(name: &str) -> Option<(Severity, u32)> {
    match name {
        "gets" => Some((Severity::Critical, 242)),
        "strcpy" | "strcat" | "vsprintf" | "sprintf" => Some((Severity::High, 120)),
        _ => None,
    }
}

fn format_arg_index(name: &str) -> Option<u32> {
    match name {
        "printf" => Some(0),
        "fprintf" | "sprintf" | "syslog" => Some(1),
        "snprintf" => Some(2),
        _ => None,
    }
}

pub fn has_non_literal_format(call: Node, name: &str) -> bool {
    let Some(index) = format_arg_index(name) else {
        return false;
    };
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    let Some(format) = arguments
        .named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .nth(index as usize)
    else {
        return false;
    };
    !matches!(format.kind(), "string_literal" | "concatenated_string")
}

