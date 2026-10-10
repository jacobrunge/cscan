#Step 1: Creation and file management
 In the terminal, running "cargo init --name {filename} will make (3) things appear in the your file expolorer
 (1). Cargo.toml
      - This is the projects manifest. 
        Package: holds the name, version and edition. 
        Dependencies: Libraries will be added in here when introduced
(2). Main
     - This is the programs entry point, contains fn main() 

(3). .GitIgnore
      - Contains /target, the folder where compiled output will go. 
      *Sidenote - Cargo init created a Git repo, which is why the file exits. 

#Step 2: Adding dependencies
 Instead of writing an entire C parser, we will use the fine tuned libraries, or "crates" as they are called in Rust. 

 In terminal, run: 
  
  "cargo add tree-sitter tree-sitter-c"
  -Tree sitter is the parsing engine, used by GitHub. This turns C source test into a syntx tree. Tree sitter is fully written in C, so this build compiles C code. C++ build tools are needed. 

  "cargo add clap --features derive" 
  -Clap parses command line arguments, it lets you describe arguments as a struct. Clap generates parsing code, like Java annotations. 

  "cargo add walkdir anyhow" 
   -Walkdir walks a folder to find every .c and .h extension file. Anyhow makes error handling more simple. Rust does not have exceptions, Anyhow gives a single error type that will hold any error. This can also give you more context, e.g: “while reading foo.c”

   "cargo add serde --features derive"
   "cargo add serde_json"
    -Serde converts Rust DS to and from formats s.a JSON. Used for JSON output and SARIF. 
    
    "cargo build" 
    - Builds and compiles every crate. 

    
