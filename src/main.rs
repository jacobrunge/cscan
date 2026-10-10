use tree_sitter::Parser; 

fn main() {

    let source : &str = 
    "int main(void) {
    char a[8];
    strcpy(a, argv[1]);
    return 0; 
    }"; 

    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_c::LANGUAGE.into()).unwrap();

    let tree = parser.parse(source, None).unwrap();

    let root = tree.root_node();
    println!("{}", root.to_sexp());
}