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

    /// Cost the test runtime reports for every query — exercises the cost
    /// propagation path through `query_taint_iris_next_agent` and the result
    /// builders so we catch regressions where cost gets dropped on the way to
    /// `TaintIrisNextAgentResult.cost_usd`.
    pub(super) const TAINT_NEXT_TEST_CALL_COST_USD: f64 = 0.00123;

    impl AgentRuntime for TaintNextRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.queries.lock().unwrap().push(request);
            Ok(AgentQueryResponse {
                cost_usd: TAINT_NEXT_TEST_CALL_COST_USD,
                input_tokens: 500,
                output_tokens: 120,
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
        // Regression: cost from `AgentQueryResponse` must reach the report
        // surface. We previously dropped it inside `query_taint_iris_next_agent`
        // and produced `costUsd: 0.0` even after a real model call.
        assert_eq!(
            result.get("costUsd").and_then(Value::as_f64),
            Some(TAINT_NEXT_TEST_CALL_COST_USD)
        );
        assert_eq!(
            result
                .pointer("/data/stats/totalCostUsd")
                .and_then(Value::as_f64),
            Some(TAINT_NEXT_TEST_CALL_COST_USD)
        );
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

    /// rg-backed structural matcher must produce the *same* deterministic
    /// candidate ids as the in-process matcher on the same fixture. This
    /// catches drift between the alias table in `taint_iris_next_line_matches`
    /// and the alias-expansion table in `rg_engine::alias_substrings`, and
    /// regressions where rg's path/line normalisation diverges from the
    /// in-process walker.
    #[test]
    fn rg_and_inproc_structural_backends_produce_same_candidate_ids() {
        if which_rg().is_none() {
            eprintln!("skipping rg parity test: ripgrep not on PATH");
            return;
        }

        let temp = tempdir().unwrap();
        write_js_taint_fixture(temp.path());
        let options =
            TaintIrisNextInput::from_tool_input(&json!({"mode": "plan", "maxCatalogEntries": 5}))
                .unwrap();
        let mut plan = build_taint_iris_next_plan(&temp.path().to_path_buf(), options).unwrap();

        // `auto` resolves to either "rg" or "inproc" depending on PATH; force
        // both modes here so we always exercise both backends regardless of
        // the host environment.
        plan.backend.structural_tool = "rg".to_string();
        let rg_ids: BTreeSet<String> = extract_taint_iris_next_evidence(&plan)
            .unwrap()
            .candidates
            .into_iter()
            .map(|candidate| candidate.id)
            .collect();

        plan.backend.structural_tool = "inproc".to_string();
        let inproc_ids: BTreeSet<String> = extract_taint_iris_next_evidence(&plan)
            .unwrap()
            .candidates
            .into_iter()
            .map(|candidate| candidate.id)
            .collect();

        assert!(
            !rg_ids.is_empty(),
            "rg backend should find at least one candidate in the fixture"
        );
        assert_eq!(
            rg_ids, inproc_ids,
            "rg-derived and in-process candidate ids should match"
        );
    }

    fn which_rg() -> Option<()> {
        std::process::Command::new("rg")
            .arg("--version")
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|_| ())
    }

    /// Stand-in agent that returns valid JSON with `selectedCwes: []` and
    /// `findings: []` plus an explanatory `notes` block — i.e. the case
    /// where the model deliberately rejects all linked-story candidates.
    /// Used to pin the "no fallback override on a clean reject" behavior.
    struct DeliberateEmptyAgent {
        queries: Mutex<Vec<AgentQueryRequest>>,
    }

    impl DeliberateEmptyAgent {
        fn new() -> Self {
            Self {
                queries: Mutex::new(Vec::new()),
            }
        }
    }

    impl AgentRuntime for DeliberateEmptyAgent {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.queries.lock().unwrap().push(request);
            Ok(AgentQueryResponse {
                cost_usd: TAINT_NEXT_TEST_CALL_COST_USD,
                input_tokens: 800,
                output_tokens: 200,
                text: String::new(),
                structured: Some(json!({
                    "selectedCwes": [],
                    "findings": [],
                    "triage": [],
                    "notes": [
                        "All linked stories are in test fixtures or migration scripts with hardcoded SQL.",
                        "No defensible source->sink path meets the linked evidence threshold."
                    ]
                })),
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            Ok(TriageOutcome::default())
        }
    }

    /// Regression: when the agent returns valid JSON with empty selections,
    /// we must NOT substitute a deterministic "no-selection-fallback"
    /// finding. The previous behavior overrode an explicit agent rejection
    /// (e.g. opus-4-7 on a clean Postgres app) with a heuristic guess from
    /// the structural linked-story matcher, surfacing low-confidence noise
    /// the operator already paid the model to dismiss.
    #[test]
    fn deliberate_empty_agent_response_is_respected_without_fallback() {
        let temp = tempdir().unwrap();
        write_js_taint_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let mut config = V2Config::default();
        config.model = Some("anthropic:claude-opus-4-7".to_string());
        let runtime = DeliberateEmptyAgent::new();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
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
            result.pointer("/data/agentStatus").and_then(Value::as_str),
            Some("no-selection"),
            "deliberate empty must surface as no-selection, not no-selection-fallback"
        );
        assert_eq!(
            result
                .pointer("/data/findings")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0),
            "no findings should be persisted when the agent rejected everything"
        );
        assert_eq!(
            result
                .pointer("/data/reviewCandidates")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0),
            "no review candidates should be synthesised on a deliberate empty"
        );
        assert_eq!(
            result.get("costUsd").and_then(Value::as_f64),
            Some(TAINT_NEXT_TEST_CALL_COST_USD),
            "cost from the rejected query must still be reported"
        );
        // Findings DB stays clean — opus's "no" should not register a low-confidence row.
        assert_eq!(store.list_findings(10).unwrap().len(), 0);
        // The "agent selected no CWEs" warning still fires for transparency.
        let warnings: Vec<String> = result
            .pointer("/data/warnings")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            warnings.iter().any(|w| w.contains("agent selected no CWEs")),
            "expected an explanatory warning, got {warnings:?}"
        );
    }

    #[test]
    fn read_bool_option_accepts_json_bool_string_and_int_forms() {
        use crate::modules::taint_iris_next::read_bool_option;
        let raw = json!({
            "yes": true,
            "no": false,
            "trueStr": "true",
            "yesStr": "Yes",
            "onStr": "ON",
            "oneStr": "1",
            "falseStr": "FALSE",
            "offStr": "off",
            "zeroStr": "0",
            "intOne": 1,
            "intZero": 0,
            "intNonZero": 7,
            "garbage": "maybe",
        });
        assert_eq!(read_bool_option(&raw, "yes"), Some(true));
        assert_eq!(read_bool_option(&raw, "no"), Some(false));
        assert_eq!(read_bool_option(&raw, "trueStr"), Some(true));
        assert_eq!(read_bool_option(&raw, "yesStr"), Some(true));
        assert_eq!(read_bool_option(&raw, "onStr"), Some(true));
        assert_eq!(read_bool_option(&raw, "oneStr"), Some(true));
        assert_eq!(read_bool_option(&raw, "falseStr"), Some(false));
        assert_eq!(read_bool_option(&raw, "offStr"), Some(false));
        assert_eq!(read_bool_option(&raw, "zeroStr"), Some(false));
        assert_eq!(read_bool_option(&raw, "intOne"), Some(true));
        assert_eq!(read_bool_option(&raw, "intZero"), Some(false));
        assert_eq!(read_bool_option(&raw, "intNonZero"), Some(true));
        assert_eq!(read_bool_option(&raw, "garbage"), None);
        assert_eq!(read_bool_option(&raw, "missing"), None);
    }

    #[test]
    fn taint_iris_next_hunt_descriptor_lists_all_mcp_options() {
        use crate::modules::carlini_threat_hunt_module::taint_iris_next_module;
        let module = taint_iris_next_module();
        let hunt = module
            .tools
            .iter()
            .find(|t| t.name == "taint-iris-next:hunt")
            .expect("hunt tool should be present");
        let names: Vec<&str> = hunt.options.iter().map(|o| o.name.as_str()).collect();
        for expected in [
            "mcps",
            "joernCpg",
            "joernPerCweTimeoutMs",
            "codeqlPrewarm",
            "codeqlCacheDir",
            "mcpToolTimeoutMs",
            "bridgeVerbose",
            "bridgeLogPath",
        ] {
            assert!(
                names.contains(&expected),
                "expected option {expected} on taint-iris-next:hunt; got {names:?}"
            );
        }
    }
}
