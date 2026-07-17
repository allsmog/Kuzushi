#[cfg(test)]
mod tests {
    use super::super::*;

    use std::sync::{Arc, Mutex};

    use crate::config::V2Config;
    use crate::findings::{FindingStore, TriageOutcome};
    use crate::run_artifacts::{RunTraceStep, TraceHandle, TraceSink};
    use crate::runtime::{AgentQueryRequest, AgentQueryResponse, TriageRequest};
    use crate::workspace::WorkspaceTarget;
    use tempfile::tempdir;

    struct EnvVarGuard {
        name: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(name: &'static str, value: &std::path::Path) -> Self {
            let previous = std::env::var_os(name);
            std::env::set_var(name, value);
            Self { name, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }

    struct TaintNextRuntime {
        queries: Mutex<Vec<AgentQueryRequest>>,
    }

    #[derive(Default)]
    struct VecTraceSink {
        steps: Mutex<Vec<RunTraceStep>>,
    }

    impl TraceSink for VecTraceSink {
        fn record(&self, step: &RunTraceStep) {
            self.steps.lock().unwrap().push(step.clone());
        }
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
    fn cwe_priority_covers_known_classes() {
        assert_eq!(cwe_priority("CWE-89"), 3);
        assert_eq!(cwe_priority("CWE-918"), 2);
        assert_eq!(cwe_priority("CWE-999"), 1);
    }

    #[test]
    fn runtime_options_are_derived_from_canonical_tool_input_not_process_env() {
        let options = taint_iris_next_runtime_options(
            &json!({
                "joernCpg": ".kuzushi/cpg.bin",
                "joernPerCweTimeoutMs": 120000,
                "codeqlPrewarm": true,
                "codeqlCacheDir": ".kuzushi/codeql-cache",
                "mcpToolTimeoutMs": 90000,
                "bridgeVerbose": true,
                "bridgeLogPath": ".kuzushi/bridge.log"
            }),
            "structural",
        )
        .expect("runtime options should be emitted");

        assert_eq!(
            options.mcp_environment["KUZUSHI_JOERN_CPG"],
            ".kuzushi/cpg.bin"
        );
        assert_eq!(
            options.mcp_environment["KUZUSHI_JOERN_PER_CWE_TIMEOUT_MS"],
            "120000"
        );
        assert_eq!(options.mcp_environment["KUZUSHI_CODEQL_PREWARM"], "1");
        assert_eq!(
            options.mcp_environment["KUZUSHI_CODEQL_CACHE_DIR"],
            ".kuzushi/codeql-cache"
        );
        assert_eq!(options.mcp_tool_timeout_ms, Some(90_000));
        assert_eq!(options.bridge_verbose, Some(true));
        assert_eq!(
            options.bridge_log_path.as_deref(),
            Some(".kuzushi/bridge.log")
        );
    }

    #[test]
    fn joern_backend_sets_request_scoped_mcp_timeout_default() {
        let options =
            taint_iris_next_runtime_options(&json!({}), "joern").expect("joern needs timeout");

        assert_eq!(options.mcp_tool_timeout_ms, Some(180_000));
        assert!(options.mcp_environment.is_empty());
    }

    #[test]
    fn explicit_codeql_backend_fails_preflight_when_db_is_missing() {
        let temp = tempdir().unwrap();
        let options = TaintIrisNextInput::from_tool_input(&json!({
            "mode": "plan",
            "backend": "codeql"
        }))
        .unwrap();

        let error = build_taint_iris_next_plan(temp.path(), options)
            .unwrap_err()
            .to_string();

        assert!(error.contains("backend=codeql requested"));
        assert!(error.contains("no existing CodeQL DB was found"));
        assert!(!error.contains("Using structural evidence"));
    }

    #[test]
    fn explicit_joern_backend_fails_preflight_when_cpg_is_missing() {
        let _guard = crate::test_env::joern_env_lock();
        let temp = tempdir().unwrap();
        let missing_cpg = temp.path().join("missing-cpg.bin");
        let _env = EnvVarGuard::set("KUZUSHI_JOERN_CPG", &missing_cpg);
        let options = TaintIrisNextInput::from_tool_input(&json!({
            "mode": "plan",
            "backend": "joern"
        }))
        .unwrap();

        let error = build_taint_iris_next_plan(temp.path(), options)
            .unwrap_err()
            .to_string();

        assert!(error.contains("backend=joern requested"));
        assert!(error.contains("no CPG was found"));
        assert!(error.contains(&missing_cpg.display().to_string()));
        assert!(!error.contains("Using structural evidence"));
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
                cost_usd_reported: true,
                estimated_cost_usd: None,
                input_tokens: 500,
                output_tokens: 120,
                truncated: false,
                stop_reason: None,
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
        stub_taint_iris_next_mcp_artifacts(root);
    }

    /// Place empty CPG + CodeQL DB stubs under the workspace target so
    /// the artifact-aware MCP attachment probe attaches the joern and
    /// codeql servers. The hunt tests don't actually query these MCPs
    /// (the stub runtime stands in for the bridge), but the policy
    /// builder refuses to dispatch without them — see
    /// `build_taint_iris_next_tool_policy` in
    /// `application/run_report.rs`.
    fn stub_taint_iris_next_mcp_artifacts(root: &Path) {
        let kuzushi = root.join(".kuzushi");
        fs::create_dir_all(&kuzushi).unwrap();
        fs::write(kuzushi.join("cpg.bin"), b"CPG\0stub").unwrap();
        let db = kuzushi.join("codeql-db");
        fs::create_dir_all(&db).unwrap();
        fs::write(
            db.join("codeql-database.yml"),
            "primaryLanguage: javascript\n",
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

    fn linked_candidate(id: &str, role: &str, line: u32) -> TaintIrisNextCandidate {
        TaintIrisNextCandidate {
            id: id.to_string(),
            cwe: "CWE-89".to_string(),
            taint_class: "injection".to_string(),
            track: "web".to_string(),
            role: role.to_string(),
            kind: role.to_string(),
            pattern: "query".to_string(),
            file_path: "src/app.ts".to_string(),
            line,
            snippet: "db.query(input)".to_string(),
            language: "typescript".to_string(),
            confidence: "medium".to_string(),
            catalog_signal: format!("{role}: query"),
            source: "test".to_string(),
        }
    }

    fn evidence_with_linked_story() -> TaintIrisNextEvidenceResult {
        let mut result = evidence_result(Vec::new());
        result.candidates = vec![
            linked_candidate("source-1", "source", 1),
            linked_candidate("sink-1", "sink", 2),
        ];
        result.linked_stories = vec![TaintIrisNextLinkedStory {
            id: "story-1".to_string(),
            cwe: "CWE-89".to_string(),
            taint_class: "injection".to_string(),
            track: "web".to_string(),
            evidence_level: "linked".to_string(),
            file_path: "src/app.ts".to_string(),
            language: "typescript".to_string(),
            source_candidate_id: "source-1".to_string(),
            sink_candidate_id: "sink-1".to_string(),
            source_line: 1,
            sink_line: 2,
            shared_tokens: vec!["input".to_string()],
            rationale: "source and sink share request input".to_string(),
            callees: Vec::new(),
        }];
        result.linked_story_count = result.linked_stories.len();
        result
    }

    fn minimal_plan(allow_deterministic_fallback: bool) -> TaintIrisNextPlan {
        TaintIrisNextPlan {
            target: PathBuf::from("."),
            scan_root: PathBuf::from("."),
            repo_root: PathBuf::from("."),
            source_paths: std::sync::Arc::from([]),
            mode: TaintIrisNextMode::Hunt,
            caps: TaintIrisNextCaps {
                max_catalog_entries: 1,
                max_candidates_per_cwe: 10,
                max_evidence_per_cwe: 10,
                max_files_per_query: 10,
                max_specs_per_cwe: 10,
                max_agent_findings: 10,
                codeql_analyze_timeout_ms: 1000,
                min_evidence_level: "candidate".to_string(),
            },
            languages: vec!["typescript".to_string()],
            context_status: TaintIrisNextArtifactStatus {
                ok: true,
                path: None,
                reason: "test".to_string(),
            },
            threat_model_status: TaintIrisNextArtifactStatus {
                ok: true,
                path: None,
                reason: "test".to_string(),
            },
            repo_context: None,
            threat_model: None,
            catalog: Vec::new(),
            structural_queries: Vec::new(),
            prompt_catalog: String::new(),
            backend: TaintIrisNextBackendChoice {
                requested: "structural".to_string(),
                selected: "structural".to_string(),
                codeql_db_path: None,
                corroborate_with_codeql: None,
                structural_tool: "test".to_string(),
                warnings: Vec::new(),
            },
            max_budget_usd: None,
            allow_deterministic_fallback,
            system_prompt: taint_iris_next_system_prompt(),
            cwe_focus: Vec::new(),
            discovered_signals: DiscoveredSignals::default(),
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
    fn invalid_agent_output_does_not_project_deterministic_findings_by_default() {
        let plan = minimal_plan(false);
        let evidence = evidence_with_linked_story();

        let result = invalid_taint_iris_next_agent_result(
            &plan,
            &evidence,
            anyhow::anyhow!("bad json"),
            1,
            RuntimeCostReport::known(RuntimeCost::from_usd(0.25, "test cost").unwrap()),
            None,
        );

        assert!(result.findings.is_empty());
        assert!(result.review_candidates.is_empty());
        assert_eq!(result.cost_usd, 0.25);
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("allowDeterministicFallback=true")));
    }

    #[test]
    fn invalid_agent_output_projects_deterministic_findings_when_operator_opts_in() {
        let plan = minimal_plan(true);
        let evidence = evidence_with_linked_story();

        let result = invalid_taint_iris_next_agent_result(
            &plan,
            &evidence,
            anyhow::anyhow!("bad json"),
            1,
            RuntimeCostReport::known(RuntimeCost::from_usd(0.25, "test cost").unwrap()),
            None,
        );

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.review_candidates.len(), 1);
        assert_eq!(result.cost_usd, 0.25);
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("allowDeterministicFallback=true")));
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
cancellation: None,
authorization: Default::default(),
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
            result.get("status").and_then(Value::as_str),
            Some("completed")
        );
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|summary| summary.starts_with("taint-iris-next:")));
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
    fn plan_mode_streams_planning_and_evidence_steps() {
        let temp = tempdir().unwrap();
        write_js_taint_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let sink = Arc::new(VecTraceSink::default());
        let trace = TraceHandle::new(sink.clone()).for_tool("taint-iris-next:hunt");
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: Some(&trace),
cancellation: None,
authorization: Default::default(),
        };

        run_taint_iris_next_report(
            &json!({"mode": "plan", "maxCatalogEntries": 1}),
            &ctx,
            None,
        )
        .unwrap();

        let steps = sink.steps.lock().unwrap();
        let labels = steps
            .iter()
            .map(|step| step.label.as_str())
            .collect::<Vec<_>>();
        assert!(labels.iter().any(|label| label.contains("plan · load")));
        assert!(labels.iter().any(|label| label.contains("plan ·")));
        assert!(labels
            .iter()
            .any(|label| label.contains("evidence · collect")));
        assert!(labels.iter().any(|label| label.contains("agent · compose")));
        assert!(labels.iter().any(|label| label.contains("planned")));
        let start_step = steps[0].n;
        assert!(steps
            .iter()
            .filter(|step| step.kind == "tool-progress")
            .all(|step| step.parent_step == Some(start_step)));
        assert!(steps
            .iter()
            .all(|step| step.module_id.as_deref() == Some("taint-iris-next")));
    }

    #[test]
    fn dataflow_plan_tool_executes_without_runtime_or_findings_store() {
        use crate::modules::ModuleRegistry;

        let temp = tempdir().unwrap();
        write_js_taint_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let result = ModuleRegistry::with_v2_builtins()
            .execute_tool(
                "taint-iris-next:dataflow-plan",
                json!({"maxCatalogEntries": 1}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("completed")
        );
        assert_eq!(
            result.pointer("/data/status").and_then(Value::as_str),
            Some("planned")
        );
        assert!(result.pointer("/data/evidence").is_some());
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
cancellation: None,
authorization: Default::default(),
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

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("completed")
        );
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|summary| summary.starts_with("taint-iris-next:")));
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
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let err = run_taint_iris_next_report(
            &json!({"mode": "hunt", "maxCatalogEntries": 5}),
            &ctx,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("requires the LangGraph runtime"));

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

    #[test]
    fn merge_extras_replaces_built_in_in_same_lane_and_keeps_others() {
        let built_in = vec![
            TaintIrisNextRankedCatalogEntry {
                cwe: "CWE-79".to_string(),
                name: "Cross-Site Scripting".to_string(),
                taint_class: "xss".to_string(),
                languages: vec!["javascript".to_string()],
                source_signals: vec!["req.query".to_string()],
                sink_signals: vec!["innerHTML".to_string()],
                sanitizer_signals: vec!["escapeHtml".to_string()],
                structural_queries: vec!["innerHTML".to_string()],
                regex_markers: Vec::new(),
                score: 100,
                reasons: vec!["threat-model CWE".to_string()],
            },
            TaintIrisNextRankedCatalogEntry {
                cwe: "CWE-190".to_string(),
                name: "Integer Overflow".to_string(),
                taint_class: "integer-overflow".to_string(),
                languages: vec!["c".to_string()],
                source_signals: vec!["length".to_string()],
                sink_signals: vec!["malloc".to_string()],
                sanitizer_signals: vec!["checked_add".to_string()],
                structural_queries: vec!["checked_add".to_string()],
                regex_markers: Vec::new(),
                score: 50,
                reasons: vec!["language match".to_string()],
            },
        ];
        let extras = vec![TaintIrisNextRankedCatalogEntry {
            cwe: "CWE-190".to_string(),
            name: "Redis stream count overflow (threat-intel)".to_string(),
            taint_class: "integer-overflow".to_string(),
            languages: vec!["c".to_string()],
            source_signals: vec!["RESP count argument".to_string()],
            sink_signals: vec!["zmalloc(count * stride)".to_string()],
            sanitizer_signals: vec!["count bounds check".to_string()],
            structural_queries: vec!["XAUTOCLAIM".to_string()],
            regex_markers: Vec::new(),
            score: 200,
            reasons: vec!["operator-supplied catalog entry (threat-intel)".to_string()],
        }];

        let merged = merge_taint_iris_next_extra_entries(built_in, &extras);

        // CWE-190+integer-overflow lane: only the operator-supplied
        // entry survives.
        let int_overflow: Vec<_> = merged
            .iter()
            .filter(|e| e.cwe == "CWE-190" && e.taint_class == "integer-overflow")
            .collect();
        assert_eq!(
            int_overflow.len(),
            1,
            "operator entry must replace built-in in same lane"
        );
        assert!(int_overflow[0].name.contains("threat-intel"));
        assert_eq!(int_overflow[0].score, 200);

        // CWE-79 lane is untouched.
        assert!(merged.iter().any(|e| e.cwe == "CWE-79"));

        // After merge, highest-scored entry sits first.
        assert_eq!(merged[0].cwe, "CWE-190");
        assert_eq!(merged[0].score, 200);
    }

    #[test]
    fn extra_catalog_entries_parse_from_camel_case_json_input() {
        let input = serde_json::json!({
            "mode": "hunt",
            "extraCatalogEntries": [
                {
                    "cwe": "CWE-416",
                    "name": "Lua client UAF",
                    "taintClass": "use-after-free",
                    "languages": ["c"],
                    "sourceSignals": ["createClient return"],
                    "sinkSignals": ["client deref after freeClient"],
                    "sanitizerSignals": ["client->flags & CLIENT_FREED"],
                    "structuralQueries": ["freeClient", "scriptingRelease"],
                }
            ]
        });
        let parsed = TaintIrisNextInput::from_tool_input(&input).unwrap();
        assert_eq!(parsed.extra_catalog_entries.len(), 1);
        let entry = &parsed.extra_catalog_entries[0];
        assert_eq!(entry.cwe, "CWE-416");
        assert_eq!(entry.name, "Lua client UAF");
        assert_eq!(entry.taint_class, "use-after-free");
        assert_eq!(entry.languages, vec!["c"]);
        assert_eq!(entry.source_signals.len(), 1);
        assert_eq!(entry.sink_signals.len(), 1);
        assert_eq!(entry.score, 200, "operator entries must outrank built-ins");
        assert!(entry
            .reasons
            .iter()
            .any(|r| r.contains("operator-supplied")));
    }

    #[test]
    fn input_preserves_declared_taint_review_prompt() {
        let parsed = TaintIrisNextInput::from_tool_input(&json!({
            "TAINT_IRIS_NEXT_PROMPT": "custom taint review"
        }))
        .unwrap();

        assert_eq!(parsed.system_prompt, "custom taint review");
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
        let mut plan = build_taint_iris_next_plan(temp.path(), options).unwrap();

        // `auto` resolves to either "rg" or "inproc" depending on PATH; force
        // both modes here so we always exercise both backends regardless of
        // the host environment.
        plan.backend.structural_tool = "rg".to_string();
        let rg_ids = structural_candidate_ids(&plan);

        plan.backend.structural_tool = "inproc".to_string();
        let inproc_ids = structural_candidate_ids(&plan);

        assert!(
            !rg_ids.is_empty(),
            "rg backend should find at least one candidate in the fixture"
        );
        assert_eq!(
            rg_ids, inproc_ids,
            "rg-derived and in-process candidate ids should match"
        );
    }

    fn structural_candidate_ids(plan: &TaintIrisNextPlan) -> BTreeSet<String> {
        extract_taint_iris_next_evidence(plan)
            .unwrap()
            .candidates
            .into_iter()
            .filter(|candidate| candidate.source == "structural")
            .map(|candidate| candidate.id)
            .collect()
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
                cost_usd_reported: true,
                estimated_cost_usd: None,
                input_tokens: 800,
                output_tokens: 200,
                truncated: false,
                stop_reason: None,
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
            trace: None,
cancellation: None,
authorization: Default::default(),
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
            warnings
                .iter()
                .any(|w| w.contains("agent selected no CWEs")),
            "expected an explanatory warning, got {warnings:?}"
        );
    }

    #[test]
    fn read_bool_option_accepts_json_bool_string_and_int_forms() {
        use super::super::read_bool_option;
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
        use crate::modules::ModuleRegistry;

        let registry = ModuleRegistry::with_v2_builtins();
        let hunt = registry
            .resolve_tool("taint-iris-next:hunt")
            .expect("hunt tool should be present");
        let names: Vec<&str> = hunt.options.iter().map(|o| o.name.as_str()).collect();
        for expected in [
            "mcps",
            "cweFocus",
            "discoverSignals",
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

    #[test]
    fn taint_iris_next_decomposed_descriptors_split_planning_from_review() {
        use crate::modules::ModuleRegistry;

        let registry = ModuleRegistry::with_v2_builtins();
        let plan = registry
            .resolve_tool("taint-iris-next:dataflow-plan")
            .expect("dataflow plan tool should be present");
        let review = registry
            .resolve_tool("taint-iris-next:finding-review")
            .expect("finding review tool should be present");
        let plan_names: Vec<&str> = plan.options.iter().map(|o| o.name.as_str()).collect();
        let review_names: Vec<&str> = review.options.iter().map(|o| o.name.as_str()).collect();

        assert!(plan_names.contains(&"backend"));
        assert!(plan_names.contains(&"minEvidenceLevel"));
        assert!(!plan_names.contains(&"model"));
        assert!(review_names.contains(&"model"));
        assert!(review_names.contains(&"mcps"));
    }

    #[test]
    fn collect_taint_iris_next_attack_surface_hints_extracts_entrypoints_sinks_and_role_gates() {
        use super::super::collect_taint_iris_next_attack_surface_hints;
        // Realistic shape produced by threat-model:build under the new prompt.
        let doc = json!({
            "attackSurface": {
                "entryPoints": [
                    {"name": "pg_read_server_files", "trustZone": "untrusted-sql", "evidence": "src/backend/utils/adt/genfile.c"},
                    {"name": "dblink_connect", "trustZone": "untrusted-sql"},
                    "raw_string_entry"  // tolerate string-valued entries too
                ],
                "externalSinks": [
                    {"name": "dlopen", "category": "dlopen"},
                    {"name": "system", "category": "exec"}
                ],
                "roleGates": [
                    {"check": "has_privs_of_role", "guarded": "pg_signal_backend"}
                ],
                "trustedCallers": [{"role": "pg_read_server_files", "purpose": "doc"}]
            }
        });
        let hints = collect_taint_iris_next_attack_surface_hints(Some(&doc));
        assert!(hints
            .entry_points
            .contains(&"pg_read_server_files".to_string()));
        assert!(hints.entry_points.contains(&"dblink_connect".to_string()));
        assert!(hints.entry_points.contains(&"raw_string_entry".to_string()));
        assert!(hints.external_sinks.contains(&"dlopen".to_string()));
        assert!(hints.external_sinks.contains(&"system".to_string()));
        assert!(hints.role_gates.contains(&"has_privs_of_role".to_string()));
        assert!(hints.role_gates.contains(&"pg_signal_backend".to_string()));
        assert!(!hints.is_empty());
    }

    #[test]
    fn collect_taint_iris_next_attack_surface_hints_tolerates_missing_or_partial_field() {
        use super::super::collect_taint_iris_next_attack_surface_hints;
        // Threat model exists but no attackSurface key.
        assert!(
            collect_taint_iris_next_attack_surface_hints(Some(&json!({"threats": []}))).is_empty()
        );
        // attackSurface present but no recognised sub-fields.
        assert!(
            collect_taint_iris_next_attack_surface_hints(Some(&json!({"attackSurface": {}})))
                .is_empty()
        );
        // Threat model entirely absent.
        assert!(collect_taint_iris_next_attack_surface_hints(None).is_empty());
        // Partial: only entryPoints populated.
        let hints = collect_taint_iris_next_attack_surface_hints(Some(&json!({
            "attackSurface": {"entryPoints": [{"name": "exec_simple_query"}]}
        })));
        assert_eq!(hints.entry_points, vec!["exec_simple_query".to_string()]);
        assert!(hints.external_sinks.is_empty());
        assert!(hints.role_gates.is_empty());
    }

    #[test]
    fn parse_taint_iris_next_cwe_focus_normalises_separators_and_prefixes() {
        use super::super::parse_taint_iris_next_cwe_focus;

        // Comma-separated string with mixed prefix/no-prefix and case.
        let parsed =
            parse_taint_iris_next_cwe_focus(&json!({"cweFocus": "CWE-78, cwe-94, 426 269"}));
        assert_eq!(parsed, vec!["CWE-269", "CWE-426", "CWE-78", "CWE-94"]);

        // JSON array form.
        let parsed = parse_taint_iris_next_cwe_focus(&json!({
            "cweFocus": ["CWE-22", "CWE-22", "cwe-22"]
        }));
        assert_eq!(parsed, vec!["CWE-22"], "duplicates collapse to one");

        // Snake-case alias still resolves so an operator using
        // `set taint-iris-next:hunt cwe_focus ...` still gets through.
        let parsed = parse_taint_iris_next_cwe_focus(&json!({"cwe_focus": "CWE-78"}));
        assert_eq!(parsed, vec!["CWE-78"]);

        // Empty / missing => empty vec (callers treat as no filter).
        let parsed = parse_taint_iris_next_cwe_focus(&json!({}));
        assert!(parsed.is_empty());
        let parsed = parse_taint_iris_next_cwe_focus(&json!({"cweFocus": ""}));
        assert!(parsed.is_empty());
    }

    /// Stub agent that always returns plain text instead of JSON,
    /// triggering the parse-error path that previously projected
    /// linked stories as findings unconditionally.
    struct InvalidJsonAgent;

    impl AgentRuntime for InvalidJsonAgent {
        fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            Ok(AgentQueryResponse {
                cost_usd: TAINT_NEXT_TEST_CALL_COST_USD,
                cost_usd_reported: true,
                estimated_cost_usd: None,
                input_tokens: 800,
                output_tokens: 200,
                truncated: false,
                stop_reason: None,
                text: "this is not JSON".to_string(),
                structured: None,
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            Ok(TriageOutcome::default())
        }
    }

    #[test]
    fn agent_failure_without_fallback_emits_zero_findings_and_points_to_opt_in() {
        // Contract: agent failure (parse error / 401 / transport
        // failure) yields zero findings by default. The deterministic
        // linked-story projection is only available when the operator
        // explicitly opts in with allowDeterministicFallback.
        let temp = tempdir().unwrap();
        write_js_taint_fixture(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let mut config = V2Config::default();
        config.model = Some("anthropic:claude-opus-4-7".to_string());
        let runtime = InvalidJsonAgent;
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
cancellation: None,
authorization: Default::default(),
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
            Some("invalid-json"),
        );
        assert_eq!(
            result
                .pointer("/data/findings")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0),
            "agent failure must NEVER project linked stories as findings",
        );
        assert_eq!(
            result
                .pointer("/data/reviewCandidates")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0),
        );
        let warnings_str: String = result
            .pointer("/data/warnings")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" | ")
            })
            .unwrap_or_default();
        assert!(
            warnings_str.contains("allowDeterministicFallback=true"),
            "default parse-error path should explain the explicit opt-in, got: {warnings_str}"
        );
        // The warning should still mention linked stories so the
        // operator knows raw evidence is available offline.
        assert!(
            warnings_str.contains("linked stories"),
            "warnings should mention linked stories for offline review, got: {warnings_str}"
        );
    }
}
