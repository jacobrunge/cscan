# cscan
![cscan](https://github.com/jacobrunge/cscan/actions/workflows/cscan.yml/badge.svg)

A static analyzer written in Rust that scans C source code for memory-safety and format-string vulnerabilities. cscan parses each file into a syntax tree with [tree-sitter](https://tree-sitter.github.io/), reports dangerous function calls with their CWE ID and severity, and exits with a non-zero code so it can gate a CI pipeline.

## Example

```
$ cscan tests/fixtures
tests/fixtures/lib/subfolder.c:7: [High] CWE-120: call to strcat
tests/fixtures/vulnerable.c:7: [High] CWE-120: call to strcpy
tests/fixtures/vulnerable.c:8: [High] CWE-120: call to strcat
tests/fixtures/vulnerable.c:14: [High] CWE-120: call to vsprintf
tests/fixtures/vulnerable.c:25: [Critical] CWE-242: call to gets
tests/fixtures/vulnerable.c:26: [High] CWE-134: non-literal format string in call to printf
tests/fixtures/vulnerable.c:27: [High] CWE-120: call to strcpy
tests/fixtures/vulnerable.c:27: [Critical] CWE-242: call to gets
tests/fixtures/vulnerable.c:30: [High] CWE-120: call to sprintf
9 finding(s) in 3 file(s)
```

## What it detects

| CWE | Vulnerability | Functions | Severity |
|-----|---------------|-----------|----------|
| [CWE-242](https://cwe.mitre.org/data/definitions/242.html) | Use of inherently dangerous function | `gets` | Critical |
| [CWE-120](https://cwe.mitre.org/data/definitions/120.html) | Buffer copy without checking size of input | `strcpy`, `strcat`, `sprintf`, `vsprintf` | High |
| [CWE-134](https://cwe.mitre.org/data/definitions/134.html) | Use of externally controlled format string | `printf`, `fprintf`, `sprintf`, `snprintf`, `syslog` | High |

A single call can produce more than one finding. `sprintf(buf, input)` is reported as both a buffer overflow (CWE-120) and a format string vulnerability (CWE-134).

## How it works

1. **Collect files.** cscan walks the target path recursively and selects every `.c` and `.h` file.
2. **Parse.** Each file is parsed into a concrete syntax tree using the tree-sitter C grammar.
3. **Walk the tree.** A recursive traversal visits every `call_expression` node and reads the name of the called function.
4. **Apply rules.**
   - *Dangerous functions:* the name is matched against a table of functions that perform unbounded writes, each mapped to a CWE and severity.
   - *Format strings:* for each function in the `printf` family, cscan knows which argument holds the format string (index 0 for `printf`, 1 for `fprintf`, 2 for `snprintf`). If that argument is not a string literal, the call is flagged. Comments between arguments are skipped so they cannot shift the position.
5. **Report.** Findings are printed as text or JSON, and the process exits with code `1` if any were found.

### Why a parser instead of grep?

A text search for `strcpy` also matches comments, string literals, and identifiers like `my_strcpy_wrapper`, so it produces false positives. Working on the syntax tree means cscan only reports real function calls. It also makes rules that depend on structure possible, such as checking whether a particular argument is a literal. That is something a regular expression cannot do reliably.

## Installation

Requires a [Rust toolchain](https://rustup.rs/).

```
git clone <https://github.com/jacobrunge/cscan>
cd cscan
cargo build --release
```

The binary is written to `target/release/cscan`.

## Usage

```
cscan <PATH> [--format <text|json|sarif>]
```

`PATH` can be a single file or a directory, which is scanned recursively.

```
cargo run -- tests/fixtures
cargo run -- tests/fixtures --format json
cargo run -- tests/fixtures --format sarif
```

JSON output is an array of findings:

```json
[
  {
    "path": "tests/fixtures/vulnerable.c",
    "line": 7,
    "cwe": 120,
    "function": "strcpy",
    "message": "call to strcpy",
    "severity": "High"
  }
]
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings |
| `1` | Findings were reported, or an error occurred |

## CI integration

The workflow in `.github/workflows/cscan.yml` runs on every push and pull request. It runs the test suite, builds cscan, scans the repository, and uploads the results as SARIF, so findings appear in the repo's **Security → Code scanning** tab and as annotations on pull requests.


## Testing

```
cargo test
```

Unit tests cover each rule, including the negative cases: names inside comments and strings, literal format strings, and comments placed before the format argument. Example C programs in `tests/fixtures/` (`vulnerable.c`, `safe.c`) are used for end-to-end checks.

## Limitations

cscan is a syntactic analyzer, and it has the trade-offs that come with that:

- **No data-flow analysis.** It cannot tell whether a variable passed as a format string actually comes from an attacker, so `printf(msg)` is flagged even when `msg` is a constant.
- **No bounds reasoning.** `strcpy` is always flagged, even when the destination is provably large enough.
- **Indirect calls are missed.** Calls made through macros, function pointers, or wrapper functions are not detected.
- **No preprocessing.** `#include`s and macros are not expanded, so code hidden behind `#ifdef` is analyzed as written.

## Roadmap

- [x] SARIF output for GitHub code scanning
- [ ] Configuration file to enable or disable individual rules
- [ ] Inline suppression comments for accepted findings
- [ ] Separate exit code for errors versus findings
- [ ] More rules: `memcpy` size checks, `scanf("%s")`, unchecked `malloc`
- [ ] Measure precision and recall against the NIST Juliet C/C++ test suite
