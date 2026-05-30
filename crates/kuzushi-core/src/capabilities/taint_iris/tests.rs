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

    fn raw_taint_finding_with_path() -> Value {
        json!({
            "findings": [{
                "cwe": "CWE-89",
                "severity": "high",
                "filePath": "src/routes.ts",
                "taintPath": [
                    {"filePath": "src/routes.ts", "line": 3, "message": "source: req.query.id"},
                    {"filePath": "src/db.ts", "line": 7, "message": "sink: db.query"}
                ]
            }]
        })
    }

    #[test]
    fn extracts_structured_taint_flow_parallel_to_findings() {
        let flows = extract_taint_flows(&raw_taint_finding_with_path(), 10);

        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].cwe, "CWE-89");
        assert_eq!(flows[0].severity, "high");
        assert_eq!(flows[0].stages.len(), 2);
        assert_eq!(flows[0].stages[0].file_path, "src/routes.ts");
        assert_eq!(flows[0].stages[0].line, 3);
        assert_eq!(flows[0].stages[0].message, "source: req.query.id");
        assert_eq!(flows[0].stages[1].file_path, "src/db.ts");
    }

    #[test]
    fn flows_skip_findings_without_a_taint_path() {
        let raw = json!({"findings": [{"cwe": "CWE-79", "severity": "medium"}]});
        assert!(extract_taint_flows(&raw, 10).is_empty());
    }

    #[test]
    fn report_serializes_flows_as_camel_case_for_the_tui() {
        let temp = tempdir().unwrap();
        let flows = extract_taint_flows(&raw_taint_finding_with_path(), 10);
        let report = taint_iris_report(temp.path(), Vec::new(), Vec::new(), flows, None, None);

        let value = serde_json::to_value(&report).unwrap();
        let stage = &value["flows"][0]["stages"][0];
        assert_eq!(stage["filePath"], "src/routes.ts");
        assert_eq!(stage["line"], 3);
        assert_eq!(value["flows"][0]["cwe"], "CWE-89");
    }
}
