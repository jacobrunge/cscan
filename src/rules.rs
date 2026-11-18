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

fn scanf_format_index(name: &str) -> Option<u32> {
    match name {
        "scanf" => Some(0),
        "fscanf" | "sscanf" => Some(1),
        _ => None,
    }
}

pub fn has_non_literal_format(call: Node, name: &str) -> bool {
    let Some(index) = format_arg_index(name) else {
        return false;
    };
    let Some(format) = nth_argument(call, index) else {
        return false;
    };
    !matches!(format.kind(), "string_literal" | "concatenated_string")
}

pub fn has_unbounded_scanf(call: Node, name: &str, source: &str) -> bool {
    let Some(index) = scanf_format_index(name) else {
        return false;
    };
    let Some(format) = nth_argument(call, index) else {
        return false;
    };
    if format.kind() != "string_literal" {
        return false;
    }
    let text = format.utf8_text(source.as_bytes()).unwrap_or("");
    has_unbounded_string_conversion(text)
}

fn has_unbounded_string_conversion(format: &str) -> bool {
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            continue;
        }
        if chars.peek() == Some(&'%') || chars.peek() == Some(&'*') {
            chars.next();
            continue;
        }
        let mut has_width = false;
        while chars.peek().is_some_and(|d| d.is_ascii_digit()) {
            has_width = true;
            chars.next();
        }
        if !has_width && matches!(chars.peek(), Some('s') | Some('[')) {
            return true;
        }
    }
    false
}

fn nth_argument(call: Node, index: u32) -> Option<Node> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .nth(index as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_unbounded_string_conversions() {
        assert!(has_unbounded_string_conversion("%s"));
        assert!(has_unbounded_string_conversion("name: %s"));
        assert!(has_unbounded_string_conversion("%d %s"));
        assert!(has_unbounded_string_conversion("%[a-z]"));
    }

    #[test]
    fn allows_bounded_or_non_string_conversions() {
        assert!(!has_unbounded_string_conversion("%63s"));
        assert!(!has_unbounded_string_conversion("%d"));
        assert!(!has_unbounded_string_conversion("100%%s"));
        assert!(!has_unbounded_string_conversion("%*s"));
        assert!(!has_unbounded_string_conversion("no conversions"));
    }
}
