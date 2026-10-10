use tree_sitter:: {Node, Parser};

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



fn main() {

    let source: &str = 
    "int main(int argc, char *argv[]) {
    char a[8];
    strcpy(a, argv[1]);
    gets(a);
    printf(\"%s\", a);
    return 0; 
    }"; 

    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_c::LANGUAGE.into()).unwrap();

    let tree = parser.parse(source, None).unwrap();

    let root = tree.root_node();
    walk(root, source);
}





