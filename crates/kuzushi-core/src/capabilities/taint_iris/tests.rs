#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::findings::Severity;
    use tempfile::tempdir;

    #[test]
    fn parses_operator_supplied_cwes_from_strings_and_objects() {
        let cwes = parse_taint_cwes_value(&json!("CWE-89, CWE-22")).unwrap();
        assert_eq!(
            cwes.iter().map(|cwe| cwe.id.as_str()).collect::<Vec<_>>(),
            vec!["CWE-89", "CWE-22"]
        );

        let cwes = parse_taint_cwes_value(&json!([
            "CWE-79",
            {"cwe": "CWE-918", "name": "SSRF", "reason": "fetches URLs"}
        ]))
        .unwrap();
        assert_eq!(cwes[0].reason, "operator-supplied");
        assert_eq!(cwes[1].id, "CWE-918");
        assert_eq!(cwes[1].name, "SSRF");
        assert_eq!(cwes[1].reason, "fetches URLs");
    }

    #[test]
    fn normalizes_taint_iris_findings_with_trace_summary() {
        let temp = tempdir().unwrap();
        let raw = json!({
            "findings": [{
                "title": "Request id reaches SQL query",
                "cwe": "CWE-89",
                "severity": "high",
                "filePath": "src/routes.ts",
                "startLine": 7,
                "message": "id is interpolated into SQL",
                "sourceSinkTrace": "req.query.id -> db.query",
                "taintPath": [{
                    "filePath": "src/routes.ts",
                    "line": 7,
                    "message": "sink",
                    "snippet": "db.query(sql)"
                }],
                "confidence": "high",
                "exploitPreconditions": "attacker controls id"
            }]
        });

        let findings = normalize_taint_iris_findings(raw, temp.path(), 10).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "taint-iris");
        assert_eq!(findings[0].rule_id, "taint-iris/cwe-89");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("Source-to-sink trace"));
        assert!(findings[0].message.contains("src/routes.ts:7"));
    }
}
