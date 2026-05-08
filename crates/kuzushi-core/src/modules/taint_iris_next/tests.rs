#[cfg(test)]
mod tests {
    use super::super::*;

    use std::sync::Mutex;

    use crate::config::V2Config;
    use crate::findings::{FindingStore, TriageOutcome};
    use crate::runtime::{AgentQueryRequest, AgentQueryResponse, TriageRequest};
    use crate::workspace::WorkspaceTarget;
    use tempfile::tempdir;

    struct TaintNextRuntime {
        queries: Mutex<Vec<AgentQueryRequest>>,
    }

    impl TaintNextRuntime {
        fn new() -> Self {
            Self {
                queries: Mutex::new(Vec::new()),
            }
        }

        fn queries(&self) -> Vec<AgentQueryRequest> {
            self.queries.lock().unwrap().clone()
        }
    }

    #[test]
    fn deterministic_taint_iris_next_severity_and_priority_cover_known_cwes() {
        assert_eq!(
            deterministic_taint_iris_next_severity("CWE-78"),
            Severity::High
        );
        assert_eq!(
            deterministic_taint_iris_next_severity("CWE-502"),
            Severity::Medium
        );
        assert_eq!(
            deterministic_taint_iris_next_severity("CWE-999"),
            Severity::Low
        );

        assert_eq!(cwe_priority("CWE-89"), 3);
        assert_eq!(cwe_priority("CWE-918"), 2);
        assert_eq!(cwe_priority("CWE-999"), 1);
    }

    impl AgentRuntime for TaintNextRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.queries.lock().unwrap().push(request);
            Ok(AgentQueryResponse {
                text: String::new(),
                structured: Some(json!({
                    "selectedCwes": [{
                        "cwe": "CWE-89",
                        "reason": "raw query receives request data",
                        "catalogSignals": ["sink: query("],
                        "sourceSpec": "request query parameters",
                        "sinkSpec": "database query calls",
                        "sanitizerSpec": "parameterized query APIs",
                        "customCweRationale": ""
                    }],
                    "findings": [{
                        "title": "Request parameter reaches raw SQL query",
                        "cwe": "CWE-89",
                        "severity": "high",
                        "confidence": "medium",
                        "evidenceLevel": "linked",
                        "filePath": "src/routes.ts",
                        "startLine": 1,
                        "message": "The query uses request-controlled data in SQL construction.",
                        "sourceSinkTrace": "req.query.id -> db.query(sql)",
                        "catalogSignals": ["source: req.query", "sink: query("],
                        "customCweRationale": "",
                        "taintPath": [{
                            "filePath": "src/routes.ts",
                            "line": 1,
                            "message": "source and SQL sink",
                            "snippet": "db.query(req.query.id)"
                        }]
                    }],
                    "triage": [{
                        "status": "finding",
                        "cwe": "CWE-89",
                        "evidenceLevel": "linked",
                        "rationale": "request data reaches raw SQL query",
                        "filePath": "src/routes.ts",
                        "line": 1,
                        "catalogSignals": ["sink: query("]
                    }],
                    "notes": []
                })),
                ..Default::default()
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            Ok(TriageOutcome::default())
        }
    }

    fn write_js_taint_fixture(root: &Path) {
        fs::create_dir(root.join("src")).unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"express":"latest","prisma":"latest"}}"#,
        )
        .unwrap();
        fs::write(
            root.join("src/routes.ts"),
            "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
        )
        .unwrap();
    }

    fn evidence_row(cwe: &str, evidence_level: &str) -> TaintIrisNextEvidence {
        TaintIrisNextEvidence {
            cwe: cwe.to_string(),
            taint_class: "injection".to_string(),
            track: "web".to_string(),
            role: "sink".to_string(),
            pattern: "query".to_string(),
            file_path: "src/app.ts".to_string(),
            line: 1,
            snippet: "db.query(input)".to_string(),
            language: "typescript".to_string(),
            confidence: "medium".to_string(),
            catalog_signal: "sink: query".to_string(),
            evidence_level: evidence_level.to_string(),
            source: "test".to_string(),
            candidate_id: format!("{cwe}-{evidence_level}"),
            linked_story_id: None,
        }
    }

    fn evidence_result(evidence: Vec<TaintIrisNextEvidence>) -> TaintIrisNextEvidenceResult {
        TaintIrisNextEvidenceResult {
            backend: "static".to_string(),
            tool: "test".to_string(),
            evidence,
            candidates: Vec::new(),
            linked_stories: Vec::new(),
            labeled_specs: Vec::new(),
            query_count: 0,
            candidate_counts: BTreeMap::new(),
            labeled_spec_counts: BTreeMap::new(),
            linked_story_count: 0,
            backend_path_count: 0,
            structural_engine: "test".to_string(),
            triage_summary: json!({}),
            outcome: "ok".to_string(),
            warnings: Vec::new(),
            artifacts: json!({}),
        }
    }

    #[test]
    fn strongest_taint_iris_next_evidence_level_prefers_path_then_linked() {
        let result = evidence_result(vec![
            evidence_row("CWE-89", "candidate"),
            evidence_row("CWE-89", "linked"),
            evidence_row("CWE-79", "path"),
        ]);
        assert_eq!(
            strongest_taint_iris_next_evidence_level("CWE-89", &result),
            "linked"
        );
        assert_eq!(
            strongest_taint_iris_next_evidence_level("CWE-79", &result),
            "path"
        );
        assert_eq!(
            strongest_taint_iris_next_evidence_level("CWE-22", &result),
            "candidate"
        );
    }

    #[test]
    fn collect_taint_iris_next_cwes_walks_nested_json() {
        let cwes = collect_taint_iris_next_cwes(Some(&json!({
            "title": "CWE-89 and cwe-79",
            "nested": [
                {"message": "also CWE-22"},
                123,
                null
            ]
        })));

        assert!(cwes.contains("CWE-89"));
        assert!(cwes.contains("CWE-79"));
        assert!(cwes.contains("CWE-22"));
    }

    #[test]
    fn plan_mode_is_deterministic_and_does_not_require_runtime() {
        let temp = tempdir().unwrap();
        write_js_taint_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
        };

        let result = run_taint_iris_next_report(
            &json!({"mode": "plan", "maxCatalogEntries": 1}),
            &ctx,
            None,
        )
        .unwrap()
        .to_tool_json();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.pointer("/data/status").and_then(Value::as_str),
            Some("planned")
        );
        assert_eq!(
            result
                .pointer("/data/cweCatalog/0/cwe")
                .and_then(Value::as_str),
            Some("CWE-89")
        );
        assert!(result
            .pointer("/data/agentPrompt")
            .and_then(Value::as_str)
            .is_some_and(|prompt| prompt.contains("CWE Candidate Catalog")));
        assert_eq!(store.list_findings(10).unwrap().len(), 0);
    }

    #[test]
    fn hunt_uses_runtime_and_persists_findings() {
        let temp = tempdir().unwrap();
        write_js_taint_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = TaintNextRuntime::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
        };

        let result = run_taint_iris_next_report(
            &json!({
                "mode": "hunt",
                "maxCatalogEntries": 3,
                "maxAgentFindings": 5,
                "minEvidenceLevel": "candidate"
            }),
            &ctx,
            Some(&runtime),
        )
        .unwrap()
        .to_tool_json();

        assert_eq!(
            result.pointer("/data/status").and_then(Value::as_str),
            Some("hunted")
        );
        assert_eq!(
            result
                .pointer("/data/selectedCwes/0/cwe")
                .and_then(Value::as_str),
            Some("CWE-89")
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("taint-iris-next/cwe-89")
        );
        assert!(result
            .pointer("/data/persisted/runId")
            .and_then(Value::as_str)
            .is_some());
        let stored = store.list_findings(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].tool, "taint-iris-next");
        assert!(stored[0].message.contains("req.query.id -> db.query"));

        let queries = runtime.queries();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].model, "openai:gpt-4.1");
        assert!(queries[0].prompt.contains("Taint IRIS Next"));
        assert!(queries[0].prompt.contains("CWE Candidate Catalog"));
        assert!(queries[0].prompt.contains("src/routes.ts"));
    }

    #[test]
    fn hunt_requires_runtime_and_explicit_model() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            "db.query(req.query.id)\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
        };

        let err = run_taint_iris_next_report(
            &json!({"mode": "hunt", "maxCatalogEntries": 5}),
            &ctx,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("requires the pi-agent-core runtime"));

        let runtime = TaintNextRuntime::new();
        let err = run_taint_iris_next_report(
            &json!({"mode": "hunt", "maxCatalogEntries": 5}),
            &ctx,
            Some(&runtime),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }
}
