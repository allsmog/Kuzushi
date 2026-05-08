#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::config::V2Config;
    use crate::findings::{FindingStore, StaticProofState};
    use crate::workspace::WorkspaceTarget;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn whitebox_triage_response_normalizes_static_schema_fields() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        let mut source = (1..=11)
            .map(|line| format!("// filler {line}"))
            .collect::<Vec<_>>();
        source.push("const q = req.query.q;".to_string());
        source.push("db.query(q);".to_string());
        source.push("return q;".to_string());
        fs::write(
            temp.path().join("src/routes.ts"),
            format!("{}\n", source.join("\n")),
        )
        .unwrap();
        let raw = json!({
            "findings": [{
                "ruleId": "agentic/whitebox-sql",
                "title": "Request input reaches SQL query",
                "verdict": "needs_review",
                "staticProofState": "sanitizer_checked",
                "severity": "high",
                "confidence": "medium",
                "source": {
                    "kind": "attacker_input",
                    "filePath": "src/routes.ts",
                    "startLine": 12,
                    "endLine": 12,
                    "description": "req.query.q is read by the route"
                },
                "sink": {
                    "kind": "sql_query",
                    "filePath": "src/routes.ts",
                    "startLine": 13,
                    "endLine": 13,
                    "description": "db.query receives the interpolated value"
                },
                "path": {
                    "kind": "direct",
                    "explanation": "The local handler passes q into db.query."
                },
                "sanitizerAssessment": {
                    "status": "unknown",
                    "explanation": "No sanitizer appears in the cited snippet."
                },
                "guardAssessment": {
                    "status": "present",
                    "explanation": "requireAuth gates the route."
                },
                "citations": [{
                    "filePath": "src/routes.ts",
                    "startLine": 12,
                    "endLine": 14,
                    "snippet": "const q = req.query.q;\ndb.query(q);\nreturn q;"
                }],
                "assumptions": ["Express route wiring is static."],
                "missingEvidence": ["Runtime reachability is not assessed."],
                "triggerNarrative": "Static trigger path: GET /search reads q.",
                "impactNarrative": "Potential SQL injection if q is unsanitized.",
                "recommendedFix": "Use parameterized queries."
            }]
        });

        let findings = normalize_agentic_sast_findings(raw, temp.path(), 5, true).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "agentic/whitebox-sql");
        assert_eq!(findings[0].file_path, "src/routes.ts");
        assert_eq!(findings[0].start_line, 12);
        assert_eq!(
            findings[0].static_proof_state,
            Some(StaticProofState::SanitizerChecked)
        );
        assert!(findings[0]
            .message
            .contains("Static proof state: sanitizer_checked"));
        assert!(findings[0]
            .message
            .contains("Sanitizer assessment: No sanitizer appears"));
        assert!(findings[0]
            .message
            .contains("Trigger narrative: Static trigger path"));
        assert!(findings[0]
            .message
            .contains("Recommended fix: Use parameterized queries."));
    }

    #[test]
    fn whitebox_citations_downgrade_statically_confirmed_before_persistence() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            "const q = req.query.q;\ndb.query(q);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let raw = json!({
            "findings": [{
                "ruleId": "agentic/whitebox-stale",
                "title": "Request input reaches SQL query",
                "verdict": "true_positive",
                "staticProofState": "statically_confirmed",
                "severity": "high",
                "source": {
                    "kind": "attacker_input",
                    "filePath": "src/routes.ts",
                    "startLine": 1,
                    "endLine": 1,
                    "description": "req.query.q is read"
                },
                "sink": {
                    "kind": "sql_query",
                    "filePath": "src/routes.ts",
                    "startLine": 2,
                    "endLine": 2,
                    "description": "db.query receives q"
                },
                "path": {
                    "kind": "direct",
                    "explanation": "q is passed directly to db.query."
                },
                "sanitizerAssessment": {
                    "status": "absent",
                    "explanation": "No sanitizer appears between source and sink."
                },
                "guardAssessment": {
                    "status": "not_applicable",
                    "explanation": "The claim does not depend on an auth guard."
                },
                "citations": [{
                    "filePath": "src/routes.ts",
                    "startLine": 1,
                    "endLine": 2,
                    "snippet": "const q = req.query.q;\ndb.query(req.body.q);"
                }],
                "assumptions": ["Static route wiring is inferred from source."],
                "missingEvidence": ["Runtime reachability is not assessed."]
            }]
        });

        let findings = normalize_agentic_sast_findings(raw, temp.path(), 5, true).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].static_proof_state,
            Some(StaticProofState::NeedsRuntimeEvidence)
        );
        assert!(findings[0]
            .message
            .contains("Whitebox citation validation: downgraded"));
        assert!(findings[0].message.contains("snippet text does not match"));

        let persisted = persist_agentic_sast_findings(temp.path(), &findings, &ctx)
            .unwrap()
            .unwrap();
        assert!(!persisted.run_id.is_empty());
        let stored = store.list_findings(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].static_proof_state,
            Some(StaticProofState::NeedsRuntimeEvidence)
        );
    }
}
