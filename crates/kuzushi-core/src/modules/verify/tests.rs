#[cfg(test)]
mod tests {
    use super::super::json_fields::parse_json_object_from_agent_text;
    use super::super::*;
    use crate::config::V2Config;
    use crate::findings::FindingStore;
    use crate::workspace::WorkspaceTarget;

    #[test]
    fn normalizes_verification_result_aliases_and_clamps_confidence() {
        let result = normalize_verification_result(
            json!({
                "exploitable": true,
                "poc_payload": "curl /admin",
                "poc_description": "reachable admin action",
                "attack_vector": "HTTP POST",
                "preconditions": [" authenticated "],
                "confidence": 1.5,
                "proof_level": 4,
                "proof_verdict": "exploited",
                "bypass_attempts": ["csrf token replay"],
                "code_citations": [{
                    "file_path": "src/admin.rs",
                    "start_line": 44,
                    "description": "sink"
                }]
            }),
            "fallback-fp",
        )
        .unwrap();

        assert_eq!(result["fingerprint"], "fallback-fp");
        assert_eq!(result["exploitable"], true);
        assert_eq!(result["pocPayload"], "curl /admin");
        assert_eq!(result["attackVector"], "HTTP POST");
        assert_eq!(result["confidence"], 1.0);
        assert_eq!(result["proofLevel"], 4);
        assert_eq!(result["codeCitations"][0]["filePath"], "src/admin.rs");
    }

    #[test]
    fn rejects_non_object_verification_output() {
        let err = normalize_verification_result(json!(["nope"]), "fp")
            .unwrap_err()
            .to_string();

        assert!(err.contains("expected a JSON object"));
    }

    #[test]
    fn builds_prompt_with_template_and_payloads() {
        let finding = Finding::new_tool(
            "semgrep",
            "demo.rule",
            "src/db.rs",
            7,
            None,
            crate::findings::Severity::High,
            "SQL injection",
        );
        let triage = TriageOutcome {
            rationale: "confirmed".to_string(),
            ..Default::default()
        };

        let prompt = build_verify_prompt(&finding, &triage, Some("Custom verify")).unwrap();

        assert!(prompt.starts_with("Custom verify"));
        assert!(prompt.contains("SQL injection"));
        assert!(prompt.contains("confirmed"));
    }

    #[test]
    fn parses_structured_agent_text_through_shared_json_helper() {
        let parsed = parse_json_object_from_agent_text("text {\"exploitable\":false}").unwrap();
        assert_eq!(parsed["exploitable"], false);
    }

    #[test]
    fn run_verify_exploit_reports_missing_finding_without_running_backend() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
        };

        let response = run_verify_exploit(json!({"fingerprint": "missing"}), &ctx).unwrap();

        assert_eq!(response["ok"], json!(false));
        assert!(response["output"]
            .as_str()
            .unwrap()
            .contains("No finding with fingerprint 'missing'"));
    }
}
