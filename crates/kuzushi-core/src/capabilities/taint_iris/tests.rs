#[cfg(test)]
mod tests {
    use super::super::*;

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
    fn summarizes_taint_paths_for_taint_iris_next_findings() {
        let item = json!({
            "taintPath": [
                {"filePath": "src/routes.ts", "line": 3, "message": "source: req.query.id"},
                {"filePath": "src/db.ts", "line": 7, "message": "sink: db.query"}
            ]
        });
        let summary = summarize_taint_path(item.as_object().unwrap()).unwrap();
        assert!(summary.contains("src/routes.ts:3"));
        assert!(summary.contains("sink: db.query"));
    }
}
