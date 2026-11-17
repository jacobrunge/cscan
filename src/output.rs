use serde_json::json;

use crate::analyzer::Finding;
use crate::rules::Severity;

pub fn to_sarif(findings: &[Finding]) -> serde_json::Value {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical => "error",
                Severity::High => "warning",
            };
            json!({
                "ruleId": format!("CWE-{}", f.cwe),
                "level": level,
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.path.replace('\\', "/") },
                        "region": { "startLine": f.line }
                    }
                }]
            })
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cscan",
                    "version": env!("CARGO_PKG_VERSION")
                }
            },
            "results": results
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::analyze;

    #[test]
    fn sarif_output_has_rule_and_location() {
        let source = "void f(char *buf) { gets(buf); }";
        let findings = analyze(source, "src\\test.c").unwrap();
        let sarif = to_sarif(&findings);

        assert_eq!(sarif["version"], "2.1.0");

        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "CWE-242");
        assert_eq!(result["level"], "error");

        let location = &result["locations"][0]["physicalLocation"];
        assert_eq!(location["region"]["startLine"], 1);
        assert_eq!(location["artifactLocation"]["uri"], "src/test.c");
    }
}



