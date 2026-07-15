#[cfg(test)]
mod tests {
    use super::super::*;
    use std::sync::Mutex;

    use crate::config::V2Config;
    use crate::findings::{TriageOutcome, TriageVerdict};
    use crate::modules::{ModuleRegistry, ToolExecutionContext};
    use crate::run_artifacts::TraceHandle;
    use crate::runtime::{AgentQueryResponse, TriageRequest};
    use crate::structured_output::parse_json_value_from_agent_text;
    use crate::workspace::WorkspaceTarget;

    #[test]
    fn parses_text_json_with_markdown_fence() {
        let parsed =
            parse_json_value_from_agent_text("```json\n{\"version\":\"2.0\"}\n```").unwrap();
        assert_eq!(parsed.get("version").and_then(Value::as_str), Some("2.0"));
    }

    #[test]
    fn component_kind_to_dfd_type_maps_storage_flows_and_processes() {
        assert_eq!(component_kind_to_dfd_type("database"), "data-store");
        assert_eq!(component_kind_to_dfd_type("session store"), "data-store");
        assert_eq!(component_kind_to_dfd_type("payment flow"), "data-flow");
        assert_eq!(component_kind_to_dfd_type("api service"), "process");
    }

    #[test]
    fn parse_threats_marks_missing_risk_fields_unknown() {
        let s4 = json!({
            "threats": [{
                "id": "T-001",
                "title": "Missing risk fields",
                "stride_category": "spoofing"
            }]
        });

        let threats = parse_threats(s4.as_object().unwrap());

        assert_eq!(threats[0]["impact"], json!("unknown"));
        assert_eq!(threats[0]["likelihood"], json!("unknown"));
        assert_eq!(threats[0]["probability"], Value::Null);
        assert_eq!(
            threats[0]["normalizationWarnings"],
            json!([
                "missing impact; using unknown",
                "missing probability; using unknown likelihood"
            ])
        );
    }

    #[test]
    fn parse_narrative_normalizes_aliases_and_skips_empty_documents() {
        assert!(parse_narrative(&json!({})).is_none());

        let parsed = parse_narrative(&json!({
            "overview": "internet-facing upload flow",
            "inputCategories": {
                "attackerControlled": ["filename"],
                "operator_controlled": ["feature flag"],
                "credentialFlows": ["POST /auth/passkey/register"],
                "authorization_flows": ["POST /teams/invite"],
                "fileIngestFlows": ["POST /customers/import-file"],
                "data_egress_flows": ["GET /reports/download"],
                "callbackFlows": ["POST /auth/redirect"]
            },
            "criticality_buckets": {
                "critical": ["auth"],
                "low": ["marketing"]
            },
            "attackerStories": [{
                "title": "Upload shell",
                "narrative": "Attacker uploads a script.",
                "mitigation": "content-type allowlist",
                "threat_ids": ["T1"]
            }],
            "out_of_scope": ["admin laptops"]
        }))
        .unwrap();

        assert_eq!(parsed["overview"], json!("internet-facing upload flow"));
        assert_eq!(
            parsed["inputCategories"]["attackerControlled"],
            json!(["filename"])
        );
        assert_eq!(
            parsed["inputCategories"]["operatorControlled"],
            json!(["feature flag"])
        );
        assert_eq!(
            parsed["inputCategories"]["credentialFlows"],
            json!(["POST /auth/passkey/register"])
        );
        assert_eq!(
            parsed["inputCategories"]["authorizationFlows"],
            json!(["POST /teams/invite"])
        );
        assert_eq!(
            parsed["inputCategories"]["fileIngestFlows"],
            json!(["POST /customers/import-file"])
        );
        assert_eq!(
            parsed["inputCategories"]["dataEgressFlows"],
            json!(["GET /reports/download"])
        );
        assert_eq!(
            parsed["inputCategories"]["callbackFlows"],
            json!(["POST /auth/redirect"])
        );
        assert_eq!(parsed["criticalityBuckets"]["critical"], json!(["auth"]));
        assert_eq!(parsed["attackerStories"][0]["threatIds"], json!(["T1"]));
        assert_eq!(parsed["outOfScope"], json!(["admin laptops"]));
    }

    struct MockThreatRuntime {
        requests: Mutex<Vec<AgentQueryRequest>>,
        responses: Mutex<Vec<AgentQueryResponse>>,
    }

    impl MockThreatRuntime {
        fn new(response: Value) -> Self {
            Self::responses(vec![AgentQueryResponse {
                text: String::new(),
                structured: Some(response),
                ..Default::default()
            }])
        }

        fn responses(responses: Vec<AgentQueryResponse>) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(responses),
            }
        }

        fn requests(&self) -> Vec<AgentQueryRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl AgentRuntime for MockThreatRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.requests.lock().unwrap().push(request);
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                anyhow::bail!("mock runtime had no queued threat-model response");
            }
            Ok(responses.remove(0))
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            Ok(TriageOutcome {
                verdict: TriageVerdict::NeedsReview,
                confidence: 0.0,
                rationale: "unused".to_string(),
                ..Default::default()
            })
        }
    }

    fn sample_document() -> Value {
        json!({
            "version": "2.0",
            "dfd": {
                "nodes": [
                    {
                        "id": "actor-user",
                        "type": "external-entity",
                        "name": "User",
                        "description": "External user",
                        "trustZone": "external"
                    },
                    {
                        "id": "web",
                        "type": "process",
                        "name": "Web App",
                        "description": "HTTP application",
                        "trustZone": "internal"
                    }
                ],
                "flows": [
                    {
                        "id": "flow-login",
                        "description": "Login request",
                        "sourceId": "actor-user",
                        "targetId": "web",
                        "trustBoundaryIds": ["tb-edge"]
                    }
                ],
                "trustBoundaries": [
                    {
                        "id": "tb-edge",
                        "name": "Internet edge",
                        "innerZone": "internal",
                        "outerZone": "external",
                        "crossingFlowIds": ["flow-login"]
                    }
                ]
            },
            "threats": [
                {
                    "id": "T-001",
                    "targetElementIds": ["web"],
                    "category": "spoofing",
                    "title": "Session spoofing",
                    "description": "Attacker spoofs a session",
                    "attackVector": "stolen token",
                    "preconditions": [],
                    "impact": "high",
                    "likelihood": "medium",
                    "existingMitigations": [],
                    "missingMitigations": ["Bind sessions"],
                    "relatedCwe": ["CWE-287"],
                    "affectedFiles": [{"filePath":"src/auth.ts","startLine":1}]
                }
            ],
            "summary": {
                "total": 1,
                "bySeverity": {"high": 1},
                "byCategory": {"spoofing": 1}
            }
        })
    }

    fn repository_scope_placeholder() -> Value {
        json!({
            "version": "2.0",
            "dfd": {
                "nodes": [{
                    "id": "repository-scope",
                    "type": "process",
                    "name": "empty-target repository scope",
                    "description": "Repository target under analysis",
                    "trustZone": "analysis-scope"
                }],
                "flows": [],
                "trustBoundaries": []
            },
            "threats": [],
            "summary": {
                "total": 0,
                "bySeverity": {},
                "byCategory": {}
            }
        })
    }

    #[test]
    fn dispatches_threat_model_build_through_runtime_and_persists_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockThreatRuntime::new(json!({"document": sample_document()}));
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime(
                "threat-model:build",
                json!({
                    "outputDir": ".kuzushi/tm-artifacts",
                    "methodology": "dread",
                    "emitFindings": true,
                    "preserveUserEdits": false
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_completed_result(
            &result,
            "threat-model:build complete",
            ["normalized threat model", "persistent threat model"],
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("  Saved:    .kuzushi/threat-model.json")));
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/document/methodology")
                .and_then(Value::as_str),
            Some("dread")
        );
        assert_eq!(
            result
                .pointer("/data/document/riskScores/methodology")
                .and_then(Value::as_str),
            Some("dread")
        );
        assert_eq!(
            result
                .pointer("/data/findings/0/threatId")
                .and_then(Value::as_str),
            Some("T-001")
        );
        assert_eq!(
            result.pointer("/data/persisted").and_then(Value::as_bool),
            Some(true)
        );
        assert!(has_artifact_label(&result, "normalized threat model"));
        assert!(persistent_threat_model_path(temp.path()).exists());
        assert!(temp
            .path()
            .join(".kuzushi/tm-artifacts/normalized-threat-model.json")
            .exists());
        let requests = runtime.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].model, "openai:gpt-4.1");
        assert_eq!(
            requests[0]
                .structured_output
                .as_ref()
                .map(|contract| contract.name.as_str()),
            Some("ThreatModelDocument")
        );
        assert!(requests[0].prompt.contains("Repository inventory"));
        assert!(requests[0].prompt.contains("Bootstrap stages"));
        assert!(requests[0].prompt.contains("Evidence raises likelihood"));
        assert!(requests[0].prompt.contains("DREAD-style"));
        assert!(requests[0]
            .prompt
            .contains(DEFAULT_THREAT_MODEL_GUIDANCE));
        assert!(requests[0]
            .prompt
            .contains(r#"<untrusted-source label="context""#));
        assert_eq!(
            result
                .pointer("/data/sources/0/label")
                .and_then(Value::as_str),
            Some("context")
        );
        assert_eq!(
            result
                .pointer("/data/sources/0/status")
                .and_then(Value::as_str),
            Some("loaded")
        );
        assert_eq!(
            result
                .pointer("/data/sources/1/label")
                .and_then(Value::as_str),
            Some("threat-model")
        );
        assert_eq!(
            result
                .pointer("/data/sources/1/status")
                .and_then(Value::as_str),
            Some("skipped")
        );
    }

    #[test]
    fn repository_scope_placeholder_is_a_partial_result_with_target_guidance() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockThreatRuntime::new(json!({
            "document": repository_scope_placeholder()
        }));
        let run_id = "threat-model-placeholder";
        let trace = TraceHandle::jsonl(workspace.root(), run_id);
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: Some(&trace),
            cancellation: None,
            authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("partial")
        );
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        let target = workspace.root().display().to_string();
        let output = result.get("output").and_then(Value::as_str).unwrap();
        assert!(output.contains(&target));
        assert!(output.contains("partial — inadequate evidence"));
        assert!(!output.contains("threat-model:build complete"));
        let trace = fs::read_to_string(crate::run_artifacts::run_dir(
            workspace.root(),
            run_id,
        ).join("trace.jsonl"))
        .unwrap();
        assert!(trace.contains("partial — inadequate evidence"));
        assert!(!trace.contains("threat-model:build complete"));
        assert!(persistent_threat_model_path(workspace.root()).exists());
    }

    #[test]
    fn threat_model_build_feeds_requested_sources_seed_and_design_doc() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("design.md"),
            "Payments design doc: callbacks cross the merchant trust boundary.",
        )
        .unwrap();
        fs::create_dir_all(temp.path().join("x-ray")).unwrap();
        fs::write(
            temp.path().join("x-ray/x-ray.md"),
            "X-Ray: permissionless bridge settlement is critical.",
        )
        .unwrap();
        fs::write(
            temp.path().join("x-ray/entry-points.md"),
            "Entry points: POST /callbacks/settle.",
        )
        .unwrap();
        fs::write(
            temp.path().join("x-ray/invariants.md"),
            "Invariant: settlement amount must match signed invoice.",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockThreatRuntime::new(json!({"document": sample_document()}));
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime(
                "threat-model:build",
                json!({
                    "sources": ["x-ray"],
                    "seed": ["Prior threat model output: callback replay was uncertain."],
                    "designDoc": "design.md",
                    "outputDir": ".kuzushi/tm-artifacts",
                    "preserveUserEdits": false
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        let prompt = runtime.requests()[0].prompt.clone();
        assert!(prompt.contains(r#"<untrusted-source label="x-ray""#));
        assert!(prompt.contains("permissionless bridge settlement"));
        assert!(prompt.contains(r#"<untrusted-source label="designDoc""#));
        assert!(prompt.contains("callbacks cross the merchant trust boundary"));
        assert!(prompt.contains(r#"<untrusted-source label="seed-1""#));
        assert!(prompt.contains("callback replay was uncertain"));
        assert_eq!(
            result
                .pointer("/data/sources")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(3)
        );
    }

    #[test]
    fn threat_model_build_rejects_conflicting_context_off_source() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockThreatRuntime::new(json!({"document": sample_document()}));
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let error = registry
            .execute_tool_with_runtime(
                "threat-model:build",
                json!({
                    "sources": ["context"],
                    "contextMode": "off",
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("contextMode=off conflicts"), "{error}");
    }

    #[test]
    fn threat_model_build_context_off_disables_default_sources() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockThreatRuntime::new(json!({"document": sample_document()}));
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let result = registry
            .execute_tool_with_runtime(
                "threat-model:build",
                json!({"contextMode": "off"}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(
            result
                .pointer("/data/sources")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn threat_model_build_treats_sentence_ending_in_extension_as_inline_seed() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockThreatRuntime::new(json!({"document": sample_document()}));
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        registry
            .execute_tool_with_runtime(
                "threat-model:build",
                json!({
                    "sources": ["none"],
                    "seed": ["Focus on the flow described in design.md"],
                }),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        let prompt = runtime.requests()[0].prompt.clone();
        assert!(prompt.contains(r#"path="inline""#), "{prompt}");
        assert!(prompt.contains("Focus on the flow described in design.md"));
    }

    #[test]
    fn threat_model_build_rejects_unknown_source_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let runtime = MockThreatRuntime::new(json!({"document": sample_document()}));
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let error = registry
            .execute_tool_with_runtime(
                "threat-model:build",
                json!({"sources": ["interview"]}),
                &ctx,
                Some(&runtime),
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsupported value"), "{error}");
    }

    fn run_randori_pasta_with_runtime(root: &Path, runtime: &MockThreatRuntime) -> Result<Value> {
        fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(root).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };
        registry.execute_tool_with_runtime(
            "randori:pasta",
            json!({"outputDir": ".kuzushi/randori"}),
            &ctx,
            Some(runtime),
        )
    }

    #[test]
    fn randori_pasta_succeeds_when_runtime_returns_structured_document() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = MockThreatRuntime::new(sample_document());

        let result = run_randori_pasta_with_runtime(temp.path(), &runtime).unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/document/threats/0/id")
                .and_then(Value::as_str),
            Some("T-001")
        );
        let requests = runtime.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].model, "openai:gpt-4.1");
        assert_eq!(
            requests[0]
                .structured_output
                .as_ref()
                .map(|contract| contract.name.as_str()),
            Some("ThreatModelDocument")
        );
    }

    #[test]
    fn randori_pasta_succeeds_when_runtime_returns_json_text() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = MockThreatRuntime::responses(vec![AgentQueryResponse {
            text: serde_json::to_string(&sample_document()).unwrap(),
            structured: None,
            ..Default::default()
        }]);

        let result = run_randori_pasta_with_runtime(temp.path(), &runtime).unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(runtime.requests().len(), 1);
    }

    #[test]
    fn randori_pasta_repairs_once_after_non_json_then_valid_json() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = MockThreatRuntime::responses(vec![
            AgentQueryResponse {
                text: "I found threats but not as JSON".to_string(),
                structured: None,
                ..Default::default()
            },
            AgentQueryResponse {
                text: serde_json::to_string(&sample_document()).unwrap(),
                structured: None,
                ..Default::default()
            },
        ]);

        let result = run_randori_pasta_with_runtime(temp.path(), &runtime).unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        let requests = runtime.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests
            .iter()
            .all(|request| request.model == "openai:gpt-4.1"));
        assert!(requests.iter().all(|request| request
            .structured_output
            .as_ref()
            .is_some_and(|contract| contract.name == "ThreatModelDocument")));
        assert!(requests[1]
            .prompt
            .contains("Invalid model response (bounded evidence"));
        assert!(requests[1]
            .prompt
            .contains("I found threats but not as JSON"));
    }

    #[test]
    fn randori_pasta_fails_clearly_after_repair_also_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = MockThreatRuntime::responses(vec![
            AgentQueryResponse {
                text: "not json".to_string(),
                structured: None,
                ..Default::default()
            },
            AgentQueryResponse {
                text: "still not json".to_string(),
                structured: None,
                ..Default::default()
            },
        ]);

        let err = run_randori_pasta_with_runtime(temp.path(), &runtime)
            .unwrap_err()
            .to_string();

        assert!(err.contains("randori:pasta"), "{err}");
        assert!(err.contains("ThreatModelDocument"), "{err}");
        assert!(
            err.contains("Initial parse/validation failure (bounded evidence)"),
            "{err}"
        );
        assert!(
            err.contains("Initial model response (bounded evidence)"),
            "{err}"
        );
        assert!(err.contains("not json"), "{err}");
        assert!(err.contains("still not json"), "{err}");
        let requests = runtime.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests
            .iter()
            .all(|request| request.model == "openai:gpt-4.1"));
    }

    #[test]
    fn threat_model_build_degrades_without_runtime_or_explicit_model() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/app.ts"),
            "import express from 'express';\nconst app = express();\napp.use('/admin', requireAuth);\napp.use(csurf());\nconst tenantId = req.user.tenantId;\nconst input = process.argv[2];\napp.post('/login', (req, res) => { db.query(req.body.name); res.send('ok'); });\napp.post('/session', (req, res) => { req.session.user = req.body.user; res.cookie('sid', req.session.id); });\napp.post('/proxy', async (req, res) => { await fetch(req.body.url); res.send('ok'); });\napp.post('/graphql', graphqlHTTP({ schema }));\napp.post('/upload', upload.single('file'), (req, res) => res.send('ok'));\napp.post('/import', (req, res) => JSON.parse(req.body.payload));\napp.post('/run', (req, res) => exec(req.body.cmd));\ncron.schedule('* * * * *', runJob);\nkafka.consumer({ groupId: 'billing' }).run({ eachMessage });\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();
        assert_eq!(degraded.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(degraded.get("status").and_then(Value::as_str), Some("partial"));
        assert_eq!(
            degraded.pointer("/data/provider").and_then(Value::as_str),
            Some("deterministic")
        );
        assert_eq!(
            degraded
                .pointer("/data/degradation/mode")
                .and_then(Value::as_str),
            Some("deterministic-no-runtime")
        );
        assert_eq!(
            degraded
                .pointer("/data/document/methodology")
                .and_then(Value::as_str),
            Some("stride")
        );
        assert!(has_artifact_label(&degraded, "normalized threat model"));
        assert!(
            degraded
                .pointer("/data/document/threats")
                .and_then(Value::as_array)
                .is_some_and(|threats| !threats.is_empty()),
            "{degraded:#?}"
        );
        assert!(document_has_dfd_node(&degraded, "external-service"));
        assert!(document_has_dfd_flow(&degraded, "flow-external-service"));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_has_dfd_node(&degraded, "auth-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-auth-control"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-auth-boundary"));
        assert!(document_has_threat_target(&degraded, "auth-control"));
        assert!(document_has_dfd_node(&degraded, "session-state"));
        assert!(document_has_dfd_flow(&degraded, "flow-session-state"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-session-state"));
        assert!(document_has_threat_target(&degraded, "session-state"));
        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-request-trust"));
        assert!(document_has_threat_target(&degraded, "request-trust-control"));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-tenant-isolation"
        ));
        assert!(document_has_threat_target(
            &degraded,
            "tenant-isolation-control"
        ));
        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-rpc-handler"));
        assert!(document_has_threat_target(&degraded, "rpc-handler"));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_flow(&degraded, "flow-file-upload"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-file-upload"));
        assert!(document_has_threat_target(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_node(&degraded, "parser-boundary"));
        assert!(document_has_dfd_flow(&degraded, "flow-parser-boundary"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-parser-boundary"));
        assert!(document_has_threat_target(&degraded, "parser-boundary"));
        assert!(document_has_dfd_node(&degraded, "cli-entrypoint"));
        assert!(document_has_dfd_flow(&degraded, "flow-cli-entrypoint"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-process-entrypoint"));
        assert!(document_has_threat_target(&degraded, "cli-entrypoint"));
        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_has_related_cwe(&degraded, "CWE-918"));
        assert!(document_has_related_cwe(&degraded, "CWE-287"));
        assert!(document_has_related_cwe(&degraded, "CWE-384"));
        assert!(document_has_related_cwe(&degraded, "CWE-352"));
        assert!(document_has_related_cwe(&degraded, "CWE-639"));
        assert!(document_has_related_cwe(&degraded, "CWE-502"));
        assert!(document_has_related_cwe(&degraded, "CWE-434"));
        assert!(document_has_related_cwe(&degraded, "CWE-78"));
        assert!(document_has_related_cwe(&degraded, "CWE-20"));
        assert!(document_has_related_cwe(&degraded, "CWE-400"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-20"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        assert!(document_threat_target_has_cwe(&degraded, "cli-entrypoint", "CWE-20"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_attacker_story_threat_id(&degraded, "DTM-001"));
        assert!(document_has_narrative_input(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled"
        ));
        assert!(document_has_narrative_input(
            &degraded,
            "/data/document/narrative/inputCategories/externalServices"
        ));
        assert!(document_has_narrative_input(
            &degraded,
            "/data/document/narrative/criticalityBuckets/critical"
        ));
        assert!(document_has_narrative_input(
            &degraded,
            "/data/document/narrative/outOfScope"
        ));
        assert!(!degraded.to_string().contains("validated"));

        let runtime = MockThreatRuntime::new(json!({"document": sample_document()}));
        let degraded_with_runtime = registry
            .execute_tool_with_runtime("threat-model:build", json!({}), &ctx, Some(&runtime))
            .unwrap();
        assert_eq!(
            degraded_with_runtime
                .pointer("/data/provider")
                .and_then(Value::as_str),
            Some("deterministic")
        );
        assert!(runtime.requests().is_empty());
    }

    #[test]
    fn threat_model_no_runtime_allows_auto_prompt_file_default() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let prompt_path =
            crate::options::prompt_override_path(workspace.root(), "threat-model", "build");
        fs::create_dir_all(prompt_path.parent().unwrap()).unwrap();
        fs::write(&prompt_path, "focus callback replay threats\n").unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool("threat-model:build", json!({}), &ctx)
            .unwrap();

        assert_eq!(
            degraded.pointer("/data/provider").and_then(Value::as_str),
            Some("deterministic")
        );
    }

    #[test]
    fn threat_model_no_runtime_allows_reordered_default_sources() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"sources": ["threat-model", "context"]}),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            degraded.pointer("/data/provider").and_then(Value::as_str),
            Some("deterministic")
        );
    }

    #[test]
    fn threat_model_no_runtime_allows_context_mode_off_with_default_sources() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool("threat-model:build", json!({"contextMode": "off"}), &ctx)
            .unwrap();

        assert_eq!(
            degraded.pointer("/data/provider").and_then(Value::as_str),
            Some("deterministic")
        );
    }

    #[test]
    fn threat_model_no_runtime_rejects_source_backed_options() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let error = registry
            .execute_tool(
                "threat-model:build",
                json!({"sources": ["x-ray"], "seed": ["prior threat model"]}),
                &ctx,
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("require a configured model/runtime"), "{error}");
    }

    #[test]
    fn deterministic_threat_model_adds_route_specific_cwes_and_narrative_inputs() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            "import express from 'express';\nconst app = express();\napp.post('/password/reset-token', (req, res) => res.send('ok'));\napp.post('/auth/2fa/verify', (req, res) => res.send('ok'));\napp.post('/auth/totp/enroll', (req, res) => res.send('ok'));\napp.post('/auth/otp/verify', (req, res) => res.send('ok'));\napp.post('/recovery-codes/rotate', (req, res) => res.send('ok'));\napp.post('/backup-codes/regenerate', (req, res) => res.send('ok'));\napp.post('/profile/email-change', (req, res) => res.send('ok'));\napp.post('/settings/change-email', (req, res) => res.send('ok'));\napp.post('/identity/verify-email', (req, res) => res.send('ok'));\napp.post('/auth/passkey/register', (req, res) => res.send('ok'));\napp.post('/webauthn/challenge', (req, res) => res.send('ok'));\napp.post('/credentials/rotate', (req, res) => res.send('ok'));\napp.post('/customers/import-file', (req, res) => res.send('ok'));\napp.post('/customers/export', (req, res) => res.send('ok'));\napp.get('/reports/download', (req, res) => res.send('ok'));\napp.post('/billing/api-key', (req, res) => res.send('ok'));\napp.post('/projects/restore-archive', (req, res) => res.send('ok'));\napp.post('/oauth/callback', (req, res) => res.send('ok'));\napp.post('/webhooks/proxy', (req, res) => res.send('ok'));\napp.post('/auth/redirect', (req, res) => res.send('ok'));\napp.post('/login/return-to', (req, res) => res.send('ok'));\napp.post('/fetch/proxy', (req, res) => res.send('ok'));\napp.post('/admin/users', (req, res) => res.send('ok'));\napp.post('/tenants/:tenantId/members', (req, res) => res.send('ok'));\napp.post('/payments/refund', (req, res) => res.send('ok'));\napp.post('/billing/subscription', (req, res) => res.send('ok'));\napp.post('/teams/invite', (req, res) => res.send('ok'));\napp.post('/roles/permission', (req, res) => res.send('ok'));\napp.post('/oidc/connect', (req, res) => res.send('ok'));\napp.post('/sso/magic-link', (req, res) => res.send('ok'));\napp.post('/scim/users', (req, res) => res.send('ok'));\napp.post('/support/impersonate', (req, res) => res.send('ok'));\napp.post('/federation/return-url', (req, res) => res.send('ok'));\napp.get('/realtime/socket', websocketHandler);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false, "maxThreats": 64}),
                &ctx,
            )
            .unwrap();

        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-640"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-522"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-434"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-601"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-918"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-862"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-863"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-639"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-200"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        assert!(document_has_narrative_input(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows"
        ));
        assert!(document_has_narrative_input(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows"
        ));
        assert!(document_has_narrative_input(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /admin/users"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /tenants/:tenantId/members"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /payments/refund"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /billing/subscription"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/invite"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /roles/permission"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "POST /customers/export"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /reports/download"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "POST /auth/redirect"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "POST /login/return-to"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "POST /fetch/proxy"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "POST /oidc/connect"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "POST /sso/magic-link"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "POST /auth/2fa/verify"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "POST /auth/totp/enroll"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "POST /auth/otp/verify"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "POST /recovery-codes/rotate"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "POST /backup-codes/regenerate"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "POST /profile/email-change"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "POST /settings/change-email"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "POST /identity/verify-email"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "POST /auth/passkey/register"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "POST /webauthn/challenge"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "POST /credentials/rotate"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /scim/users"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /support/impersonate"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "POST /oidc/connect"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "POST /federation/return-url"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_node_current_team_tenant_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import express from 'express';\nconst app = express();\napp.post('/teams/projects', (req, res) => createProject(req));\nconst teamScope = db.projects.where({ teamId: req.user.currentTeam.id });\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Express/TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_nextjs_current_team_tenant_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/app/api/teams/projects")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"next":"14.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/app/api/teams/projects/route.ts"),
            "import { NextRequest } from 'next/server';\nexport async function POST(request: NextRequest) { const teamScope = db.projects.where({ teamId: request.user.currentTeam.id }); return Response.json({ ok: true, teamScope }); }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /api/teams/projects"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Next.js/TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_nestjs_current_team_tenant_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"@nestjs/common":"^10.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/projects.controller.ts"),
            "import { AuthGuard, Controller, Post, UseGuards } from '@nestjs/common';\n@Controller('teams')\nexport class ProjectsController {\n  @UseGuards(AuthGuard('jwt'))\n  @Post('/teams/projects')\n  createProject(req) { const teamScope = this.projects.where({ teamId: req.user.currentTeam.id }); return teamScope; }\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "auth-control"));
        assert!(document_threat_target_has_cwe(&degraded, "auth-control", "CWE-287"));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "NestJS/TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_koa_current_team_tenant_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"koa":"^2.15.0","@koa/router":"^12.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import Koa from 'koa';\nimport Router from '@koa/router';\nconst router = new Router();\nrouter.post('/teams/projects', createProject);\nasync function createProject(ctx) { const teamScope = db.projects.where({ teamId: ctx.state.user.currentTeam.id }); ctx.body = teamScope; }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Koa/TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_fastify_current_team_tenant_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"fastify":"^4.26.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import fastify from 'fastify';\nconst app = fastify();\napp.post('/teams/projects', createProject);\nasync function createProject(request, reply) { const teamScope = db.projects.where({ teamId: request.user.currentTeam.id }); return reply.send(teamScope); }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Fastify/TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_hono_current_team_tenant_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"hono":"^4.3.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import { Hono } from 'hono';\nconst app = new Hono();\napp.post('/teams/projects', createProject);\nasync function createProject(c) { const teamScope = db.projects.where({ teamId: c.get('user').currentTeam.id }); return c.json(teamScope); }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Hono/TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_elysia_current_team_tenant_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"elysia":"^1.1.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import { Elysia } from 'elysia';\nconst app = new Elysia();\napp.post('/teams/projects', createProject);\nasync function createProject({ user }) { const teamScope = db.projects.where({ teamId: user.currentTeam.id }); return teamScope; }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Elysia/TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_node_trpc_procedure_handler() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"@trpc/server":"^10.45.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/projects.router.ts"),
            "export const projectRouter = createTRPCRouter({\n  create: protectedProcedure.mutation(({ ctx }) => db.projects.where({ teamId: ctx.user.currentTeam.id }))\n});\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-rpc-handler"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_socket_io_event_handler() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"socket.io":"^4.7.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/realtime.ts"),
            "io.on('connection', (socket) => {\n  socket.on('project:create', (payload) => db.projects.where({ teamId: socket.user.currentTeam.id }).create(payload));\n});\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-rpc-handler"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_apollo_graphql_server_handler() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"@apollo/server":"^4.10.0","graphql":"^16.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/graphql.ts"),
            "const resolvers = { Mutation: { createProject: (_parent, args, ctx) => db.projects.where({ teamId: ctx.user.currentTeam.id }).create(args.input) } };\nconst server = new ApolloServer({ typeDefs, resolvers });\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-rpc-handler"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_graphql_yoga_handler() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"graphql-yoga":"^5.0.0","graphql":"^16.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/graphql.ts"),
            "const yoga = createYoga({ schema, context: ({ request }) => ({ teamId: request.user.currentTeam.id }) });\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-rpc-handler"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_mercurius_graphql_handler() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"fastify":"^4.0.0","mercurius":"^13.0.0","graphql":"^16.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "fastify.register(mercurius, { schema, resolvers, context: (request) => ({ teamId: request.user.currentTeam.id }) });\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-rpc-handler"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_nestjs_graphql_resolver() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"@nestjs/graphql":"^12.0.0","graphql":"^16.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/projects.resolver.ts"),
            "@Resolver(() => Project)\nexport class ProjectResolver {\n  @Mutation(() => Project)\n  createProject(@Context() ctx) { return db.projects.where({ teamId: ctx.user.currentTeam.id }).create(); }\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-rpc-handler"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_bullmq_worker_consumer() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"bullmq":"^5.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/workers.ts"),
            "const worker = new Worker('tenant-events', async job => processTenantEvent(job.data));\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_nestjs_queue_processor() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"@nestjs/bullmq":"^10.0.0","bullmq":"^5.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/email.processor.ts"),
            "@Processor('email')\nexport class EmailProcessor {\n  @Process('send')\n  async send(job) { return sendEmail(job.data); }\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_python_worker_decorators() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("requirements.txt"),
            "dramatiq\nhuey\ncelery\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/tasks.py"),
            "@dramatiq.actor\ndef sync_account(message): pass\n\n@app.task\ndef send_email(message): pass\n\n@huey.task\ndef compact_logs(): pass\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_python_filestorage_uploads() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(temp.path().join("requirements.txt"), "flask\nwerkzeug\n").unwrap();
        fs::write(
            temp.path().join("svc/uploads.py"),
            "def import_files(request):\n    uploads = request.files.getlist('imports')\n    avatar: FileStorage = uploads[0]\n    return avatar.filename\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_flow(&degraded, "flow-file-upload"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_ruby_worker_definitions() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("app/jobs")).unwrap();
        fs::create_dir_all(temp.path().join("app/workers")).unwrap();
        fs::write(temp.path().join("Gemfile"), "gem 'rails'\ngem 'sidekiq'\n").unwrap();
        fs::write(
            temp.path().join("app/jobs/report_job.rb"),
            "class ReportJob < ApplicationJob\n  def perform(account_id); end\nend\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/workers/invite_worker.rb"),
            "class InviteWorker\n  include Sidekiq::Job\n  def perform(user_id); end\nend\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Ruby"));
    }

    #[test]
    fn deterministic_threat_model_includes_django_urlpattern_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "django\n").unwrap();
        fs::write(
            temp.path().join("urls.py"),
            "from django.urls import path\nurlpatterns = [path('billing/api-keys/', views.keys)]\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("views.py"),
            "from rest_framework.parsers import MultiPartParser\nfrom rest_framework.permissions import IsAuthenticated\n@permission_classes([IsAuthenticated])\n@parser_classes([MultiPartParser])\ndef keys(request): pass\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-522"));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "ANY /billing/api-keys/"
        ));
        assert!(document_has_dfd_node(&degraded, "auth-control"));
        assert!(document_threat_target_has_cwe(&degraded, "auth-control", "CWE-287"));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_flow(&degraded, "flow-file-upload"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_django_as_view_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "django\ndjangorestframework\n").unwrap();
        fs::write(
            temp.path().join("urls.py"),
            "from django.urls import path\nurlpatterns = [path('imports/file/', ImportView.as_view({'post': 'create'}))]\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("views.py"),
            "from rest_framework.parsers import MultiPartParser\n@parser_classes([MultiPartParser])\ndef create(request): pass\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file/"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Django/Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_fastapi_api_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "fastapi\n").unwrap();
        fs::write(
            temp.path().join("main.py"),
            "from fastapi import FastAPI, File, UploadFile\napp = FastAPI()\n@app.api_route('/imports/file', methods=['POST'])\ndef ingest(file: UploadFile = File(...)): pass\n@app.api_route('/saml/callback', methods=['OPTIONS', 'HEAD'])\ndef preflight(): pass\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "OPTIONS,HEAD /saml/callback"
        ));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-601"));
        assert!(document_has_evidence_anchor_description(&degraded, "FastAPI/Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_django_meta_header_trust_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "django\n").unwrap();
        fs::write(
            temp.path().join("urls.py"),
            "from django.urls import path\nurlpatterns = [path('webhooks/signed/', views.signed)]\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("views.py"),
            "def signed(request):\n    signature = request.META.get('HTTP_X_SIGNATURE')\n    return signature\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "ANY /webhooks/signed/"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_django_user_org_tenant_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "django\n").unwrap();
        fs::write(
            temp.path().join("urls.py"),
            "from django.urls import path\nurlpatterns = [path('organizations/projects/', views.create_project)]\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("views.py"),
            "def create_project(request):\n    organization = request.user.organization\n    Project.objects.filter(organization=organization).create(name=request.POST['name'])\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "ANY /organizations/projects/"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Django/Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_fastapi_dependency_auth_guard() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "fastapi\n").unwrap();
        fs::write(
            temp.path().join("main.py"),
            "from fastapi import Depends, FastAPI, File, UploadFile\napp = FastAPI()\n@app.get('/account/api-key')\ndef account(user=Depends(get_current_user)): pass\n@app.post('/import/file')\ndef ingest(file: UploadFile = File(...)): pass\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-522"));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "GET /account/api-key"
        ));
        assert!(document_has_dfd_node(&degraded, "auth-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-auth-control"));
        assert!(document_threat_target_has_cwe(&degraded, "auth-control", "CWE-287"));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_flow(&degraded, "flow-file-upload"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_node_request_files_uploads() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0","express-fileupload":"^1.4.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/uploads.ts"),
            "app.post('/imports/file', (req, res) => {\n  const upload = req.files.import;\n  return res.json({ name: upload.name });\n});\napp.post('/avatars/file', (request, response) => response.json(request.files.avatar));\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_flow(&degraded, "flow-file-upload"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "TypeScript"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_flask_jwt_auth_guard() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "flask\nflask-jwt-extended\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from flask import Flask\nfrom flask_jwt_extended import jwt_required\napp = Flask(__name__)\n@app.route('/admin/api-key', methods=['POST'])\n@jwt_required()\ndef rotate_key(): pass\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-522"));
        assert!(document_has_dfd_node(&degraded, "auth-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-auth-control"));
        assert!(document_threat_target_has_cwe(&degraded, "auth-control", "CWE-287"));
    }

    #[test]
    fn deterministic_threat_model_includes_flask_add_url_rule_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "flask\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from flask import Flask, request\napp = Flask(__name__)\napp.add_url_rule('/imports/file', view_func=upload, methods=['POST'])\ndef upload():\n    return request.files['file'].filename\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Flask/Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_starlette_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "starlette\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from starlette.applications import Starlette\nfrom starlette.datastructures import UploadFile\nfrom starlette.routing import Route\nroutes = [Route('/imports/file', upload, methods=['POST'])]\nasync def upload(request):\n    form = await request.form()\n    uploaded: UploadFile = form['file']\n    return uploaded.filename\napp = Starlette(routes=routes)\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Starlette/Python"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aiohttp_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "aiohttp\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from aiohttp import web\napp = web.Application()\napp.router.add_post('/imports/file', upload)\napp.router.add_route('OPTIONS', '/saml/callback', callback)\nasync def upload(request):\n    reader = await request.multipart()\n    return reader\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "OPTIONS /saml/callback"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "aiohttp/Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_tornado_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "tornado\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "import tornado.web\nclass UploadHandler(tornado.web.RequestHandler):\n    def post(self):\n        upload = self.request.files['file'][0]\n        return upload.filename\napp = tornado.web.Application([\n    (r\"/imports/file\", UploadHandler),\n])\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Tornado/Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_bottle_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "bottle\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from bottle import post, request, route\n@post('/imports/file')\ndef upload():\n    return request.files.get('file').filename\n@route('/webhooks/signed', method='POST')\ndef webhook(): pass\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "POST /webhooks/signed"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Bottle/Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_sanic_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "sanic\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from sanic import Sanic\napp = Sanic('svc')\n@app.post('/imports/file')\nasync def upload(request):\n    return request.files.get('file').name\n@app.route('/webhooks/signed', methods=['POST'])\nasync def webhook(request): pass\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "POST /webhooks/signed"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Sanic/Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_pyramid_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "pyramid\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from pyramid.config import Configurator\nconfig = Configurator()\nconfig.add_route('import_file', '/imports/file', request_method='POST')\ndef upload(request):\n    return request.POST['file'].filename\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Pyramid/Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_falcon_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "falcon\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "import falcon\nclass UploadResource:\n    def on_post(self, req, resp):\n        upload = req.get_param('file')\n        resp.text = upload.filename\napp = falcon.App()\napp.add_route('/imports/file', UploadResource())\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Falcon/Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_litestar_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "litestar\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from litestar import Litestar, UploadFile, post\n@post('/imports/file')\nasync def upload(file: UploadFile) -> str:\n    return file.filename\napp = Litestar(route_handlers=[upload])\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Litestar/Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_starlite_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "starlite\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from starlite import Starlite, UploadFile, post\n@post('/imports/file')\nasync def upload(file: UploadFile) -> str:\n    return file.filename\napp = Starlite(route_handlers=[upload])\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Litestar/Python"));
    }

    #[test]
    fn deterministic_threat_model_includes_flask_header_trust_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "flask\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from flask import Flask, request\napp = Flask(__name__)\n@app.route('/webhooks/signed', methods=['POST'])\ndef signed():\n    signature = request.headers.get('X-Signature')\n    sid = request.cookies.get('sid')\n    return signature or sid\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "POST /webhooks/signed"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_go_and_rust_grpc_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/main.go"),
            "package main\nfunc main() { server := grpc.NewServer(); pb.RegisterGreeterGrpcServer(server, handler) }\nfunc upload(r *http.Request) { r.ParseMultipartForm(32 << 20); r.FormFile(\"import\") }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/server.rs"),
            "async fn serve() { tonic::transport::Server::builder().add_service(GreeterServer::new(handler)); }\nasync fn upload(mut multipart: Multipart) { while let Some(field) = multipart.next_field().await.unwrap() { let _ = field.name(); } }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool("threat-model:build", json!({}), &ctx)
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_dfd_trust_boundary(&degraded, "tb-rpc-handler"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_flow(&degraded, "flow-file-upload"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Go"));
        assert!(document_has_evidence_anchor_description(&degraded, "Rust"));
    }

    #[test]
    fn deterministic_threat_model_includes_go_team_tenant_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module svc\nrequire github.com/gin-gonic/gin v1.9.0\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/main.go"),
            "package main\nfunc main() { r := gin.Default(); r.POST(\"/teams/projects\", createProject) }\nfunc createProject(c *gin.Context) { teamID := claims.TeamID; db.Where(\"team_id = ?\", teamID).Create(&project) }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Go"));
    }

    #[test]
    fn deterministic_threat_model_includes_go_fiber_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module svc\nrequire github.com/gofiber/fiber/v2 v2.52.0\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/main.go"),
            "package main\nimport \"github.com/gofiber/fiber/v2\"\nfunc main() { app := fiber.New(); app.Post(\"/teams/projects\", createProject) }\nfunc createProject(c *fiber.Ctx) { teamID := claims.TeamID; db.Where(\"team_id = ?\", teamID).Create(&project) }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Fiber/Go"));
    }

    #[test]
    fn deterministic_threat_model_includes_go_chi_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module svc\nrequire github.com/go-chi/chi/v5 v5.0.12\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/main.go"),
            "package main\nimport \"github.com/go-chi/chi/v5\"\nfunc main() { r := chi.NewRouter(); r.Post(\"/teams/projects\", createProject) }\nfunc createProject(w http.ResponseWriter, r *http.Request) { teamID := claims.TeamID; db.Where(\"team_id = ?\", teamID).Create(&project) }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Chi/Go"));
    }

    #[test]
    fn deterministic_threat_model_includes_go_echo_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module svc\nrequire github.com/labstack/echo/v4 v4.12.0\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/main.go"),
            "package main\nimport \"github.com/labstack/echo/v4\"\nfunc main() { e := echo.New(); e.POST(\"/teams/projects\", createProject) }\nfunc createProject(c echo.Context) error { teamID := claims.TeamID; db.Where(\"team_id = ?\", teamID).Create(&project); return nil }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Echo/Go"));
    }

    #[test]
    fn deterministic_threat_model_includes_go_worker_registrations() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module svc\nrequire github.com/hibiken/asynq v0.25.0\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/workers.go"),
            "package svc\nfunc register(handleMux *asynq.ServeMux, router *message.Router) {\nhandleMux.HandleFunc(\"email:send\", sendEmail)\nrouter.AddHandler(\"events\", \"tenant.events\", subscriber, \"processed\", publisher, handleEvent)\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Go"));
    }

    #[test]
    fn deterministic_threat_model_includes_rust_team_tenant_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"svc\"\nversion = \"0.1.0\"\n[dependencies]\naxum = \"0.7\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "fn app() -> Router { Router::new().route(\"/teams/projects\", post(create_project)) }\nasync fn create_project(claims: Claims) { let _ = projects.filter(team_id.eq(claims.team_id)); }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "ANY /teams/projects"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Rust"));
    }

    #[test]
    fn deterministic_threat_model_includes_actix_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"svc\"\nversion = \"0.1.0\"\n[dependencies]\nactix-web = \"4\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "use actix_web::{post, HttpResponse};\n#[post(\"/teams/projects\")]\nasync fn create_project(claims: Claims) -> HttpResponse { let _ = projects.filter(team_id.eq(claims.team_id)); HttpResponse::Ok().finish() }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Actix Web/Rust"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_rocket_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"svc\"\nversion = \"0.1.0\"\n[dependencies]\nrocket = \"0.5\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "use rocket::{post, routes};\n#[post(\"/teams/projects\")]\nfn create_project(claims: Claims) -> &'static str { let _ = projects.filter(team_id.eq(claims.team_id)); \"ok\" }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Rocket/Rust"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_warp_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"svc\"\nversion = \"0.1.0\"\n[dependencies]\nwarp = \"0.3\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "fn routes() { let create = warp::path!(\"teams\" / \"projects\").and(warp::post()).and_then(create_project); }\nasync fn create_project(claims: Claims) { let _ = projects.filter(team_id.eq(claims.team_id)); }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Warp/Rust"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_rust_async_nats_subscriptions() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"svc\"\nversion = \"0.1.0\"\n[dependencies]\nasync-nats = \"0.35\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/workers.rs"),
            "async fn workers(client: async_nats::Client, jetstream: JetStream) {\nlet _events = client.subscribe(\"tenant.events\".into()).await.unwrap();\nlet _jobs = jetstream.subscribe(\"jobs.email\").await.unwrap();\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Rust"));
    }

    #[test]
    fn deterministic_threat_model_includes_rails_upload_parser() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("app/controllers")).unwrap();
        fs::create_dir_all(temp.path().join("config")).unwrap();
        fs::write(temp.path().join("Gemfile"), "gem 'rails'\n").unwrap();
        fs::write(
            temp.path().join("config/routes.rb"),
            "Rails.application.routes.draw do\npost '/imports/file', to: 'imports#create'\nend\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/controllers/imports_controller.rb"),
            "class ImportsController < ApplicationController\nhas_one_attached :import_file\ndef create\nuploaded_file = params[:file]\nend\nend\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_flow(&degraded, "flow-file-upload"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Rails/Ruby"));
    }

    #[test]
    fn deterministic_threat_model_includes_rails_match_via_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("app/controllers")).unwrap();
        fs::create_dir_all(temp.path().join("config")).unwrap();
        fs::write(temp.path().join("Gemfile"), "gem 'rails'\n").unwrap();
        fs::write(
            temp.path().join("config/routes.rb"),
            "Rails.application.routes.draw do\nmatch '/imports/file', to: 'imports#create', via: :post\nend\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/controllers/imports_controller.rb"),
            "class ImportsController < ApplicationController\ndef create\nuploaded_file = params[:file]\nend\nend\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Rails/Ruby"));
    }

    #[test]
    fn deterministic_threat_model_includes_rails_header_trust_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("app/controllers")).unwrap();
        fs::create_dir_all(temp.path().join("config")).unwrap();
        fs::write(temp.path().join("Gemfile"), "gem 'rails'\n").unwrap();
        fs::write(
            temp.path().join("config/routes.rb"),
            "Rails.application.routes.draw do\npost '/webhooks/signed', to: 'webhooks#signed'\nend\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/controllers/webhooks_controller.rb"),
            "class WebhooksController < ApplicationController\ndef signed\nsignature = request.headers['X-Signature']\nrender json: { signature: signature }\nend\nend\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "POST /webhooks/signed"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Rails/Ruby"));
    }

    #[test]
    fn deterministic_threat_model_includes_rails_current_account_tenant_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("app/controllers")).unwrap();
        fs::create_dir_all(temp.path().join("config")).unwrap();
        fs::write(temp.path().join("Gemfile"), "gem 'rails'\n").unwrap();
        fs::write(
            temp.path().join("config/routes.rb"),
            "Rails.application.routes.draw do\npost '/accounts/projects', to: 'projects#create'\nend\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/controllers/projects_controller.rb"),
            "class ProjectsController < ApplicationController\ndef create\naccount = current_account\nProject.where(account: account).create!(params[:project])\nend\nend\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /accounts/projects"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Rails/Ruby"));
    }

    #[test]
    fn deterministic_threat_model_includes_laravel_upload_parser() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("routes")).unwrap();
        fs::create_dir_all(temp.path().join("app/Http/Controllers")).unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"laravel/framework":"^10"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("routes/web.php"),
            "<?php\nRoute::post('/imports/file', [ImportController::class, 'store']);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/Http/Controllers/ImportController.php"),
            "<?php\nclass ImportController {\npublic function store(Request $request) {\nif ($request->hasFile('import')) {\n$request->file('import')->store('imports');\n}\n}\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_flow(&degraded, "flow-file-upload"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Laravel/PHP"));
    }

    #[test]
    fn deterministic_threat_model_includes_laravel_match_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("routes")).unwrap();
        fs::create_dir_all(temp.path().join("app/Http/Controllers")).unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"laravel/framework":"^10"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("routes/web.php"),
            "<?php\nRoute::match(['post'], '/imports/file', [ImportController::class, 'store']);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/Http/Controllers/ImportController.php"),
            "<?php\nclass ImportController { public function store(Request $request) { $request->file('import')->store('imports'); } }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Laravel/PHP"));
    }

    #[test]
    fn deterministic_threat_model_includes_symfony_request_file_uploads() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/Controller")).unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"symfony/http-foundation":"^7.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/Controller/ImportController.php"),
            "<?php\nclass ImportController {\npublic function upload(Request $request): Response {\n$archive = $request->files->get('archive');\nreturn new Response($archive->getClientOriginalName());\n}\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_flow(&degraded, "flow-file-upload"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "PHP"));
    }

    #[test]
    fn deterministic_threat_model_includes_laravel_header_trust_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("routes")).unwrap();
        fs::create_dir_all(temp.path().join("app/Http/Controllers")).unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"laravel/framework":"^10"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("routes/web.php"),
            "<?php\nRoute::post('/webhooks/signed', [WebhookController::class, 'signed']);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/Http/Controllers/WebhookController.php"),
            "<?php\nclass WebhookController { public function signed(Request $request) { $signature = $request->header('X-Signature'); return response()->json(['signature' => $signature]); } }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "POST /webhooks/signed"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Laravel/PHP"));
    }

    #[test]
    fn deterministic_threat_model_includes_symfony_messenger_handler() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/MessageHandler")).unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"symfony/messenger":"^7.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/MessageHandler/InvoiceHandler.php"),
            "<?php\n#[AsMessageHandler]\nclass InvoiceHandler implements MessageHandlerInterface {\npublic function __invoke(InvoiceMessage $message): void {}\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "PHP"));
    }

    #[test]
    fn deterministic_threat_model_includes_laravel_current_team_tenant_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("routes")).unwrap();
        fs::create_dir_all(temp.path().join("app/Http/Controllers")).unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"laravel/framework":"^10"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("routes/web.php"),
            "<?php\nRoute::post('/teams/projects', [ProjectController::class, 'store']);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/Http/Controllers/ProjectController.php"),
            "<?php\nclass ProjectController { public function store(Request $request) { $team = $request->user()->currentTeam; Project::where('team_id', $team->id)->create($request->input('project')); } }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /teams/projects"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Laravel/PHP"));
    }

    #[test]
    fn deterministic_threat_model_treats_laravel_request_evidence_as_attacker_controlled() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("app/Http/Controllers")).unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"laravel/framework":"^10"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("app/Http/Controllers/ImportController.php"),
            "<?php\nclass ImportController {\npublic function store(Request $request) {\nif ($request->hasFile('import')) {\n$request->file('import')->store('imports');\n}\n}\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "File upload or multipart parser"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "File upload or multipart parser"
        ));
    }

    #[test]
    fn deterministic_threat_model_treats_go_and_rust_extractors_as_attacker_controlled() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/handler.go"),
            "package svc\nfunc handler(r *http.Request) { json.NewDecoder(r.Body).Decode(&payload) }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/handler.rs"),
            "async fn handler(Json(payload): Json<Value>) { serde_json::from_value::<Payload>(payload); }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "Deserialization or parser boundary"
        ));
    }

    #[test]
    fn deterministic_threat_model_treats_spring_request_body_as_attacker_controlled() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(
            temp.path().join("build.gradle"),
            "plugins { id 'java' }\ndependencies { implementation 'org.springframework.boot:spring-boot-starter-cache' }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ImportController.java"),
            "class ImportController { void importPayload(@RequestBody String body) { objectMapper.readValue(body, Payload.class); } }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "Deserialization or parser boundary"
        ));
    }

    #[test]
    fn deterministic_threat_model_treats_aspnet_request_body_as_attacker_controlled() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("Controllers")).unwrap();
        fs::write(
            temp.path().join("Controllers/ImportController.cs"),
            "using System.Text.Json;\nclass ImportController { void Import() { JsonSerializer.Deserialize<Payload>(Request.Body); } }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "Deserialization or parser boundary"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_treats_aspnet_binding_attributes_as_attacker_controlled() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("Controllers")).unwrap();
        fs::write(
            temp.path().join("Controllers/SearchController.cs"),
            r#"
              using Microsoft.AspNetCore.Mvc;
              class SearchController {
                IActionResult Search([FromQuery] string q, [FromHeader] string team) { return Ok(q); }
                IActionResult Import([FromBody] Payload payload, [FromForm] string mode) { return Ok(payload); }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "Request trust boundary"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "Deserialization or parser boundary"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_antiforgery_request_trust_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("Controllers")).unwrap();
        fs::write(
            temp.path().join("Controllers/CheckoutController.cs"),
            r#"
              using Microsoft.AspNetCore.Mvc;
              [AutoValidateAntiforgeryToken]
              class CheckoutController {
                [ValidateAntiForgeryToken]
                IActionResult Pay(IAntiforgery antiforgery) => Ok();
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_auth_middleware_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              builder.Services.AddAuthentication("Bearer");
              builder.Services.AddAuthorization();
              app.UseAuthentication();
              app.UseAuthorization();
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "auth-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-auth-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "auth-control",
            "CWE-287"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_anonymous_filter_auth_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              app.MapGet("/public/status", Status)
                 .AllowAnonymous();
              [AllowAnonymous]
              class PublicController {}
              class AdminFilter : IAuthorizationFilter {}
              class AdminAuthorizeAttribute : AuthorizeAttribute {}
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "auth-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-auth-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "auth-control",
            "CWE-287"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_endpoint_filter_request_trust_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              app.MapPost("/admin/export", Export)
                 .AddEndpointFilter<AdminAuditFilter>();
              class AdminAuditFilter : IEndpointFilter {}
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_cors_host_request_trust_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              app.MapPost("/admin/export", Export)
                 .RequireCors("AdminCors")
                 .RequireHost("admin.example.com");
              app.MapPost("/public/import", Import)
                 .DisableCors();
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_rate_limiting_request_trust_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              builder.Services.AddRateLimiter(options => {});
              app.UseRateLimiter();
              app.MapPost("/login", Login)
                 .RequireRateLimiting("login");
              app.MapGet("/health", Health)
                 .DisableRateLimiting();
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_forwarded_headers_request_trust_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              app.UseForwardedHeaders();
              builder.Services.Configure<ForwardedHeadersOptions>(options => {
                options.KnownProxies.Add(proxyAddress);
                options.KnownNetworks.Clear();
              });
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_cookie_policy_session_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              app.UseCookiePolicy();
              builder.Services.Configure<CookiePolicyOptions>(options => {
                options.MinimumSameSitePolicy = SameSiteMode.Strict;
                options.HttpOnly = CookieHttpOnlyPolicy.Always;
                options.Secure = CookieSecurePolicy.Always;
              });
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "session-state"));
        assert!(document_has_dfd_flow(&degraded, "flow-session-state"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-session-state"
        ));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "session-state",
            "CWE-384"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_session_middleware_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              builder.Services.AddSession();
              builder.Services.Configure<SessionOptions>(options => {
                options.IdleTimeout = TimeSpan.FromMinutes(20);
              });
              app.UseSession();
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "session-state"));
        assert!(document_has_dfd_flow(&degraded, "flow-session-state"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-session-state"
        ));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "session-state",
            "CWE-384"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_spring_request_header_trust_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/WebhookController.java"),
            "class WebhookController { @PostMapping(\"/webhooks/signed\") void signed(@RequestHeader(\"X-Signature\") String signature) {} }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "POST /webhooks/signed"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_spring_principal_org_tenant_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ProjectController.java"),
            "class ProjectController { @PostMapping(\"/organizations/projects\") void create(ProjectPrincipal principal) { var organizationId = principal.getOrganizationId(); repository.findByOrganizationId(organizationId); } }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/authorizationFlows",
            "POST /organizations/projects"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_tenant_context_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/TenantAccess.java"),
            r#"
              import org.springframework.web.bind.annotation.GetMapping;
              class TenantAccess {
                @GetMapping("/tenants/current")
                void show(TenantContext tenantContext) {
                  TenantResolver tenantResolver;
                  TenantProvider tenantProvider;
                  String currentWorkspace;
                  String organization_id;
                  String account_id;
                  String team_id;
                  principal.getTenantId();
                  jwt.getClaim("tenant_id");
                  authentication.getPrincipal();
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-tenant-isolation"
        ));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_persistence_tenant_isolation_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/TenantPersistence.java"),
            r#"
              import org.springframework.data.domain.AuditorAware;
              class TenantPersistence {
                AuditorAware<String> auditorAware;
                void audit() { auditorAware.getCurrentAuditor(); }
                CurrentTenantIdentifierResolver tenantIdentifierResolver;
                MultiTenantConnectionProvider connectionProvider;
                void filter(Session session) { session.enableFilter("tenant"); }
                @FilterDef(name = "tenantFilter")
                @Filter(name = "tenantFilter")
                TenantLineHandler tenantLineHandler;
                TenantLineInnerInterceptor tenantInterceptor;
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "tenant-isolation-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-tenant-isolation"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-tenant-isolation"
        ));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "tenant-isolation-control",
            "CWE-639"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_security_configuration_auth_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SecurityConfig.java"),
            r#"
              import org.springframework.security.config.annotation.web.builders.HttpSecurity;
              class SecurityConfig {
                SecurityFilterChain api(HttpSecurity http) {
                  http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
                  http.oauth2ResourceServer(oauth -> oauth.jwt());
                  http.oauth2Login();
                  return http.build();
                }
                void reactive(ServerHttpSecurity http) {
                  http.authorizeExchange(exchange -> exchange.anyExchange().authenticated());
                }
                JwtDecoder jwtDecoder() { return decoder; }
                PasswordEncoder passwordEncoder() { return encoder; }
                AuthenticationProvider authenticationProvider() { return provider; }
                AuthenticationManager authenticationManager() { return manager; }
                UserDetailsService userDetailsService() { return users; }
              }
              class TenantFilter extends OncePerRequestFilter {}
              class PasskeyConfig { void enable() { WebAuthn4J webauthn = new WebAuthn4J(); } }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "auth-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-auth-control"));
        assert!(document_has_threat_target(&degraded, "auth-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "auth-control",
            "CWE-287"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_oauth_client_and_token_auth_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/OAuthSecurity.java"),
            r#"
              import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
              import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
              class OAuthSecurity {
                ClientRegistrationRepository clientRegistrationRepository;
                ReactiveClientRegistrationRepository reactiveClientRegistrationRepository;
                OAuth2AuthorizedClientService authorizedClientService;
                OAuth2AuthorizedClientRepository authorizedClientRepository;
                OAuth2AuthorizedClientManager authorizedClientManager;
                ReactiveOAuth2AuthorizedClientManager reactiveAuthorizedClientManager;
                BearerTokenResolver bearerTokenResolver;
                BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter;
                ReactiveJwtDecoder reactiveJwtDecoder;
                void opaque(HttpSecurity http) {
                  http.oauth2ResourceServer(oauth -> oauth.opaqueToken());
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "auth-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-auth-control"));
        assert!(document_has_threat_target(&degraded, "auth-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "auth-control",
            "CWE-287"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_saml_x509_preauth_api_key_auth_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/FederatedSecurity.java"),
            r#"
              import org.springframework.security.config.annotation.web.builders.HttpSecurity;
              class FederatedSecurity {
                void federated(HttpSecurity http) {
                  http.saml2Login();
                  http.saml2Logout();
                  http.saml2Metadata();
                  http.x509();
                }
                RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
                X509AuthenticationFilter x509AuthenticationFilter;
                RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter;
                AbstractPreAuthenticatedProcessingFilter preAuthFilter;
                PreAuthenticatedAuthenticationProvider preAuthProvider;
                ApiKeyAuthenticationFilter apiKeyAuthenticationFilter;
                String apiKeyHeader = "X-API-Key";
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "auth-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-auth-control"));
        assert!(document_has_threat_target(&degraded, "auth-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "auth-control",
            "CWE-287"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_method_security_auth_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/MethodSecurity.java"),
            r#"
              import org.springframework.security.access.prepost.PostAuthorize;
              class MethodSecurity {
                @RolesAllowed("ADMIN")
                void adminOnly() {}
                @DenyAll
                void disabled() {}
                @PermitAll
                void publicEndpoint() {}
                @PostAuthorize("returnObject.owner == authentication.name")
                Account ownedAccount() {}
                void expressionChecks(AccessExpression access) {
                  access.hasRole("ADMIN");
                  access.hasAuthority("SCOPE_billing");
                }
                void principal(@AuthenticationPrincipal User user) {}
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "auth-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-auth-control"));
        assert!(document_has_threat_target(&degraded, "auth-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "auth-control",
            "CWE-287"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_method_security_extension_auth_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/AdvancedMethodSecurity.java"),
            r#"
              import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
              @EnableWebSecurity
              @EnableMethodSecurity
              @EnableReactiveMethodSecurity
              class AdvancedMethodSecurity {
                AuthorizationManager<RequestAuthorizationContext> authorizationManager;
                AuthorizationDecision authorizationDecision;
                PermissionEvaluator permissionEvaluator;
                @PreFilter("filterObject.owner == authentication.name")
                void filterBefore(List<Account> accounts) {}
                @PostFilter("filterObject.owner == authentication.name")
                List<Account> filterAfter() { return accounts; }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "auth-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-auth-control"));
        assert!(document_has_threat_target(&degraded, "auth-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "auth-control",
            "CWE-287"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_session_configuration_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SessionConfig.java"),
            r#"
              import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
              @EnableRedisHttpSession
              class SessionConfig {
                void configure(HttpSecurity http) {
                  http.sessionManagement(session -> session
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .sessionFixation().migrateSession()
                    .maximumSessions(1));
                }
                DefaultCookieSerializer cookieSerializer() { return serializer; }
                CookieWebSessionIdResolver webSessionIdResolver() { return resolver; }
                FindByIndexNameSessionRepository<?> repository() { return repository; }
                void filter(SpringSessionRepositoryFilter<?> filter) {}
                void servlet(SessionCookieConfig config) {}
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "session-state"));
        assert!(document_has_dfd_flow(&degraded, "flow-session-state"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-session-state"
        ));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "session-state",
            "CWE-384"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_cookie_session_access_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SessionAccess.java"),
            r#"
              import org.springframework.web.bind.annotation.GetMapping;
              class SessionAccess {
                @GetMapping("/session")
                String show(@CookieValue("sid") String sid, HttpServletRequest request) {
                  request.getSession(false);
                  request.getCookies();
                  ResponseCookie.from("sid", sid).httpOnly(true).build();
                  serverWebExchange.getSession();
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "session-state"));
        assert!(document_has_dfd_flow(&degraded, "flow-session-state"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-session-state"
        ));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "session-state",
            "CWE-384"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_remember_me_security_context_session_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/RememberMeSessions.java"),
            r#"
              import org.springframework.security.web.authentication.RememberMeServices;
              class RememberMeSessions {
                void configure(HttpSecurity http) {
                  http.rememberMe(remember -> remember.key("tenant-key"));
                  SecurityContextRepository securityContextRepository;
                  securityContextRepository.saveContext(context, request, response);
                  SessionAuthenticationStrategy sessionAuthenticationStrategy;
                  LogoutSuccessHandler logoutSuccessHandler;
                  RememberMeServices rememberMeServices;
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "session-state"));
        assert!(document_has_dfd_flow(&degraded, "flow-session-state"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-session-state"
        ));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "session-state",
            "CWE-384"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_gateway_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/GatewayConfig.java"),
            r#"
              import org.springframework.cloud.gateway.filter.GatewayFilter;
              import org.springframework.cloud.gateway.filter.GlobalFilter;
              import org.springframework.cloud.gateway.handler.RoutePredicateHandlerMapping;
              import org.springframework.cloud.gateway.route.RouteLocator;
              import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
              class GatewayConfig {
                RouteLocator gatewayRoutes(RouteLocatorBuilder routes) {
                  return routes.routes()
                    .route("orders", r -> r.path("/orders/**").filters(f -> f.stripPrefix(1)
                      .rewritePath("/orders/(?<segment>.*)", "/${segment}")
                      .addRequestHeader("X-Gateway", "kuzushi"))
                      .uri("http://orders.internal"))
                    .build();
                }
                GatewayFilter auditGatewayFilter() { return filter; }
                GlobalFilter globalFilter() { return filter; }
                RoutePredicateHandlerMapping handlerMapping;
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "external-service"));
        assert!(document_has_dfd_flow(&degraded, "flow-external-service"));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "external-service",
            "CWE-918"
        ));
        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-request-trust"
        ));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_filter_rate_limit_request_trust() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/RequestTrustConfig.java"),
            r#"
              import org.springframework.web.filter.ForwardedHeaderFilter;
              import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
              class RequestTrustConfig {
                WebFilter auditWebFilter;
                HandlerInterceptor tenantInterceptor;
                ForwardedHeaderFilter forwardedHeaderFilter;
                CorsWebFilter corsWebFilter;
                ExchangeFilterFunction outboundHeaderFilter;
                RateLimiter rateLimiter;
                Bucket4j bucket4j;
                io.github.resilience4j.ratelimiter.RateLimiter resilience4jLimiter;
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-request-trust"
        ));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_cors_csrf_forwarded_header_request_trust() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/TrustConfig.java"),
            r#"
              import org.springframework.web.servlet.config.annotation.CorsRegistry;
              class TrustConfig {
                void addCorsMappings(CorsRegistry registry) {
                  registry.addMapping("/api/**").allowedOrigins("https://app.example");
                  registry.allowedOriginPatterns("https://*.example");
                  registry.allowedMethods("GET", "POST");
                }
                void csrf(HttpSecurity http) {
                  http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
                  ServerCsrfTokenRepository serverRepository;
                }
                ForwardedHeaderTransformer forwardedHeaderTransformer;
                XForwardedHeadersFilter xForwardedHeadersFilter;
                void cookie(DefaultCookieSerializer serializer) { serializer.setCookieDomain("example.com"); }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-request-trust"
        ));
        assert!(document_has_threat_target(&degraded, "request-trust-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_binding_content_negotiation_request_trust() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/BindingTrustConfig.java"),
            r#"
              class BindingTrustConfig {
                @InitBinder
                void initBinder(WebDataBinder binder) {}
                ConfigurableWebBindingInitializer bindingInitializer;
                RequestMappingHandlerAdapter requestMappingHandlerAdapter;
                ContentNegotiationConfigurer contentNegotiationConfigurer;
                void configureContentNegotiation(ContentNegotiationConfigurer configurer) {}
                void favor(ContentNegotiationConfigurer configurer) { configurer.favorParameter(true); }
                void allowedHeaders(CorsRegistration registration) {}
                void exposedHeaders(CorsRegistration registration) {}
                void allowCredentials(CorsRegistration registration) {}
                void setAllowedOrigins(CorsConfiguration config) {}
                void setAllowCredentials(CorsConfiguration config) {}
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-request-trust"
        ));
        assert!(document_has_threat_target(&degraded, "request-trust-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_validation_request_trust() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ValidationConfig.java"),
            r#"
              import org.springframework.validation.annotation.Validated;
              @Validated
              class ValidationConfig {
                void create(@Valid SignupRequest request, BindingResult bindingResult) {}
                ConstraintValidator<TenantId, String> tenantValidator;
                MethodValidationPostProcessor methodValidationPostProcessor;
                void reactive(WebExchangeBindException bindException) {}
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-request-trust"
        ));
        assert!(document_has_threat_target(&degraded, "request-trust-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_request_input_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/RequestInputController.java"),
            r#"
              import org.springframework.web.bind.annotation.PostMapping;
              class RequestInputController {
                @PostMapping("/imports/body")
                void body(@RequestBody ImportRequest body) {}
                void query(@RequestParam String tenant) {}
                void path(@PathVariable String accountId) {}
                void servlet(HttpServletRequest request) {}
                void exchange(ServerWebExchange exchange) {}
                void nativeRequest(NativeWebRequest request) {}
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "request-trust-control"));
        assert!(document_has_dfd_flow(&degraded, "flow-request-trust"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-request-trust"
        ));
        assert!(document_has_threat_target(&degraded, "request-trust-control"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "request-trust-control",
            "CWE-352"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_spring_request_mapping_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ImportController.java"),
            "import org.springframework.web.bind.annotation.RequestMapping;\nclass ImportController {\n@RequestMapping(value = \"/imports/file\", method = RequestMethod.POST)\nvoid importFile(@RequestPart MultipartFile importFile) {}\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_kotlin_spring_request_mapping_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/kotlin/app")).unwrap();
        fs::write(temp.path().join("build.gradle.kts"), "plugins { kotlin(\"jvm\") }\n").unwrap();
        fs::write(
            temp.path().join("src/main/kotlin/app/ImportController.kt"),
            "import org.springframework.web.bind.annotation.RequestMapping\nclass ImportController {\n@RequestMapping(value = [\"/imports/file\"], method = [RequestMethod.POST])\nfun importFile(importFile: MultipartFile) {}\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/fileIngestFlows",
            "POST /imports/file"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Kotlin"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_serializer_parser_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/PayloadParsers.java"),
            r#"
              import org.springframework.web.bind.annotation.PostMapping;
              class PayloadParsers {
                @PostMapping("/imports/payload")
                void parse(String body, InputStream stream) {
                  objectMapper.readTree(body);
                  objectMapper.convertValue(node, Payload.class);
                  xmlMapper.readValue(body, Payload.class);
                  xstream.fromXML(body);
                  JAXBContext.newInstance(Payload.class).createUnmarshaller().unmarshal(stream);
                  new ObjectInputStream(stream).readObject();
                  kryo.readObject(input, Payload.class);
                  kryo.readClassAndObject(input);
                  Payload.parser().parseFrom(bytes);
                  new Jackson2JsonDecoder();
                  yaml.load(body);
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "parser-boundary"));
        assert!(document_has_dfd_flow(&degraded, "flow-parser-boundary"));
        assert!(document_has_threat_target(&degraded, "parser-boundary"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "parser-boundary",
            "CWE-502"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_parser_factory_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ParserFactories.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class ParserFactories {
                void parse(String body, InputStream stream) {
                  DocumentBuilderFactory.newInstance();
                  SAXParserFactory.newInstance();
                  XMLInputFactory.newFactory();
                  XMLInputFactory.newInstance();
                  JsonPath.parse(body);
                  gson.fromJson(body, Payload.class);
                  jsonb.fromJson(body, Payload.class);
                  objectReader.readValue(body);
                  properties.load(stream);
                  properties.loadFromXML(stream);
                  new YAMLMapper();
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "parser-boundary"));
        assert!(document_has_dfd_flow(&degraded, "flow-parser-boundary"));
        assert!(document_has_threat_target(&degraded, "parser-boundary"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "parser-boundary",
            "CWE-502"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_archive_parser_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ArchiveParsers.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class ArchiveParsers {
                void parse(InputStream stream, File file) {
                  new ZipInputStream(stream);
                  new ZipFile(file);
                  new GZIPInputStream(stream);
                  ArchiveInputStream archiveInputStream;
                  new ArchiveStreamFactory().createArchiveInputStream(stream);
                  org.apache.commons.compress.archivers.tar.TarArchiveInputStream tarStream;
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "parser-boundary"));
        assert!(document_has_dfd_flow(&degraded, "flow-parser-boundary"));
        assert!(document_has_threat_target(&degraded, "parser-boundary"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "parser-boundary",
            "CWE-502"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_document_parser_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/DocumentParsers.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class DocumentParsers {
                void parse(InputStream stream, Reader reader, File file) {
                  CSVMapper csvMapper;
                  CSVParser.parse(reader, CSVFormat.DEFAULT);
                  CSVFormat.DEFAULT.parse(reader);
                  WorkbookFactory.create(stream);
                  new XSSFWorkbook(stream);
                  new HSSFWorkbook(stream);
                  AutoDetectParser autoDetectParser;
                  tika.parseToString(file);
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "parser-boundary"));
        assert!(document_has_dfd_flow(&degraded, "flow-parser-boundary"));
        assert!(document_has_threat_target(&degraded, "parser-boundary"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "parser-boundary",
            "CWE-502"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_process_framework_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/CommandRunners.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class CommandRunners {
                void run(String command, List<String> commands) {
                  Runtime.getRuntime().exec(command);
                  Runtime.getRuntime().load(libraryPath);
                  Runtime.getRuntime().loadLibrary(libraryName);
                  new ProcessBuilder(command).start();
                  ProcessBuilder.startPipeline(commands);
                  CommandLine parsed = CommandLine.parse(command);
                  new DefaultExecutor().execute(parsed);
                  new ProcessExecutor().command(command).execute();
                  ProcessUtils.execute(command);
                  ProcessImpl.start(command, env, dir, redirects, false);
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "process-execution"));
        assert!(document_has_dfd_flow(&degraded, "flow-process-exec"));
        assert!(document_has_threat_target(&degraded, "process-execution"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "process-execution",
            "CWE-78"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_client_framework_external_service() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/BillingClients.java"),
            r#"
              import org.springframework.cloud.openfeign.FeignClient;
              @FeignClient(name = "billing", url = "${billing.url}")
              interface BillingFeign {}
              class BillingClients {
                void call(String url) {
                  Feign.builder().target(BillingFeign.class, url);
                  ClientBuilder.newClient();
                  WebTarget target = client.target(url);
                  new Retrofit.Builder().baseUrl(url).build();
                  retrofit.create(BillingApi.class);
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "external-service"));
        assert!(document_has_dfd_flow(&degraded, "flow-external-service"));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "external-service",
            "CWE-918"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_core_http_client_external_service() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/CoreHttpClients.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class CoreHttpClients {
                void call() {
                  HttpClient.newHttpClient();
                  HttpClient.newBuilder().build();
                  URI.create("https://billing.example");
                  new URL("https://billing.example");
                  url.openConnection();
                  HttpURLConnection connection;
                  AsyncHttpClient asyncHttpClient;
                  vertx.createHttpClient();
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "external-service"));
        assert!(document_has_dfd_flow(&degraded, "flow-external-service"));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "external-service",
            "CWE-918"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_apache_http_client_external_service() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ApacheHttpClients.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class ApacheHttpClients {
                CloseableHttpClient closeableHttpClient;
                void call() {
                  HttpClients.createDefault();
                  HttpClients.custom().build();
                  HttpAsyncClients.createDefault();
                  new HttpGet("https://billing.example");
                  new HttpPost("https://billing.example/refund");
                  ClassicRequestBuilder.get("https://billing.example").build();
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "external-service"));
        assert!(document_has_dfd_flow(&degraded, "flow-external-service"));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "external-service",
            "CWE-918"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_okhttp_client_external_service() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/OkHttpClients.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class OkHttpClients {
                OkHttpClient okHttpClient;
                Call.Factory callFactory;
                void call() {
                  new Request.Builder();
                  new Request.Builder().url("https://billing.example").build();
                  okHttpClient.newCall(request).execute();
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "external-service"));
        assert!(document_has_dfd_flow(&degraded, "flow-external-service"));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "external-service",
            "CWE-918"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_grpc_client_external_service() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/GrpcClients.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class GrpcClients {
                void call() {
                  ManagedChannelBuilder.forAddress("billing", 443).useTransportSecurity();
                  ManagedChannel channel;
                  GrpcChannelBuilder grpcChannelBuilder;
                  BillingGrpc.newBlockingStub(channel);
                  BillingGrpc.newFutureStub(channel);
                  BillingGrpc.newStub(channel);
                  stub.useStub(callOptions);
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "external-service"));
        assert!(document_has_dfd_flow(&degraded, "flow-external-service"));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "external-service",
            "CWE-918"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_graphql_client_external_service() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/GraphQlClients.java"),
            r#"
              import org.springframework.graphql.client.HttpGraphQlClient;
              import org.springframework.stereotype.Service;
              @Service
              class GraphQlClients {
                void call() {
                  HttpGraphQlClient.builder(webClient).build();
                  WebSocketGraphQlClient.builder(url, client).build();
                  RSocketGraphQlClient.builder(requester).build();
                  GraphQlClient graphQlClient;
                  GraphQlClient.create(transport);
                  GraphQlClient.builder(transport).build();
                  DgsGraphQLClient dgsGraphQLClient;
                  DgsReactiveGraphQLClient dgsReactiveGraphQLClient;
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "external-service"));
        assert!(document_has_dfd_flow(&degraded, "flow-external-service"));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "external-service",
            "CWE-918"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_soap_client_external_service() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SoapClients.java"),
            r#"
              import org.springframework.stereotype.Service;
              import org.springframework.ws.client.core.WebServiceTemplate;
              @Service
              class SoapClients {
                void call() {
                  WebServiceTemplate template;
                  template.marshalSendAndReceive(request);
                  JaxWsProxyFactoryBean factory;
                  Service.create(wsdlUrl, serviceName);
                  service.getPort(BillingPort.class);
                  SOAPConnectionFactory.newInstance();
                  SOAPConnection soapConnection;
                  soapConnection.call(message, endpoint);
                  Dispatch<SOAPMessage> dispatch;
                  org.apache.cxf.jaxrs.client.WebClient.create(endpoint);
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "external-service"));
        assert!(document_has_dfd_flow(&degraded, "flow-external-service"));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "external-service",
            "CWE-918"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_spring_http_client_external_service() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/HttpClients.java"),
            r#"
              import org.springframework.web.service.annotation.HttpExchange;
              @HttpExchange("/billing")
              interface BillingHttpApi {
                @GetExchange("/accounts/{id}")
                Account account(String id);
                @PostExchange("/accounts")
                Account create(Account account);
              }
              class HttpClients {
                RestClient restClient = RestClient.create(baseUrl);
                WebClient.Builder webClientBuilder;
                WebClient.create(baseUrl);
                HttpServiceProxyFactory.builderFor(adapter).build();
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "external-service"));
        assert!(document_has_dfd_flow(&degraded, "flow-external-service"));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "external-service",
            "CWE-918"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_object_storage_external_service() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ObjectStorageClients.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class ObjectStorageClients {
                S3Client s3Client;
                S3Presigner s3Presigner;
                AmazonS3 amazonS3;
                TransferManager transferManager;
                BlobServiceClient blobServiceClient;
                BlobClient blobClient;
                com.google.cloud.storage.Storage storage = StorageOptions.getDefaultInstance().getService();
                MinioClient minioClient;
                OSSClient ossClient;
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "external-service"));
        assert!(document_has_dfd_flow(&degraded, "flow-external-service"));
        assert!(document_has_dfd_trust_boundary(
            &degraded,
            "tb-outbound-service"
        ));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "external-service",
            "CWE-918"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_actuator_and_openapi_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ObservabilityConfig.java"),
            r#"
              import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
              import org.springdoc.core.models.GroupedOpenApi;
              @Endpoint(id = "tenantDiagnostics")
              class TenantDiagnosticsEndpoint {}
              class ApiDocsConfig {
                OpenAPI api() { return new OpenAPI(); }
                GroupedOpenApi publicApi() { return GroupedOpenApi.builder().group("public").build(); }
                void swagger(SwaggerUiConfigParameters swagger) {}
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        for route in [
            "GET /actuator/tenantDiagnostics",
            "GET /v3/api-docs",
            "GET /swagger-ui/index.html",
        ] {
            assert!(document_has_narrative_item(
                &degraded,
                "/data/document/narrative/inputCategories/attackerControlled",
                route
            ), "missing ASP.NET route narrative item: {route}");
        }
        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_data_framework_data_store() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/BillingStores.java"),
            r#"
              import org.springframework.data.jpa.repository.JpaRepository;
              @Repository
              interface InvoiceRepository extends JpaRepository<Invoice, String> {}
              interface TenantRepository extends CrudRepository<Tenant, String> {}
              class BillingStores {
                @Query("select i from Invoice i")
                List<Invoice> activeInvoices() {}
                void query(EntityManager entityManager, JdbcTemplate jdbcTemplate) {
                  entityManager.createNativeQuery("select * from invoice");
                  entityManager.createQuery("select i from Invoice i");
                  jdbcTemplate.update("update invoice set status = ?", status);
                  namedParameterJdbcTemplate.query(sql, params, mapper);
                  databaseClient.sql(sql).fetch();
                  r2dbcEntityTemplate.select(Invoice.class);
                  sessionFactory.openSession();
                  mongoTemplate.find(query, Invoice.class);
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "data-store"));
        assert!(document_has_dfd_flow(&degraded, "flow-data-store"));
        assert!(document_has_threat_target(&degraded, "data-store"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "data-store",
            "CWE-89"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_direct_jdbc_transaction_data_store() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/DirectJdbcStores.java"),
            r#"
              import org.springframework.jdbc.core.simple.JdbcClient;
              class DirectJdbcStores {
                JdbcClient jdbcClient;
                SimpleJdbcInsert simpleJdbcInsert;
                SimpleJdbcCall simpleJdbcCall;
                TransactionTemplate transactionTemplate;
                void query(DataSource dataSource, Connection connection) {
                  JdbcClient.create(dataSource);
                  jdbcClient.sql("select * from invoice").query(Invoice.class);
                  dataSource.getConnection();
                  connection.prepareStatement("select * from invoice where id = ?");
                  transactionTemplate.execute(status -> jdbcTemplate.update(sql));
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "data-store"));
        assert!(document_has_dfd_flow(&degraded, "flow-data-store"));
        assert!(document_has_threat_target(&degraded, "data-store"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "data-store",
            "CWE-89"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_spring_data_store_clients() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SearchStores.java"),
            r#"
              import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
              import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;
              import org.springframework.data.neo4j.core.Neo4jClient;
              import org.springframework.data.neo4j.repository.Neo4jRepository;
              @DynamoDBTable(tableName = "tenant_records")
              class TenantRecord {}
              interface SearchRepository extends ElasticsearchRepository<SearchDoc, String> {}
              interface GraphRepository extends Neo4jRepository<Node, String> {}
              interface AccountRepository extends CassandraRepository<Account, String> {}
              interface AuditRepository extends MongoRepository<Audit, String> {}
              interface SessionRepository extends RedisRepository<Session, String> {}
              class SearchStores {
                ElasticsearchOperations elasticsearchOperations;
                Neo4jClient neo4jClient;
                Neo4jTemplate neo4jTemplate;
                CassandraOperations cassandraOperations;
                ReactiveCassandraOperations reactiveCassandraOperations;
                ReactiveMongoTemplate reactiveMongoTemplate;
                DynamoDBMapper dynamoDbMapper;
                DynamoDbTemplate dynamoDbTemplate;
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "data-store"));
        assert!(document_has_dfd_flow(&degraded, "flow-data-store"));
        assert!(document_has_threat_target(&degraded, "data-store"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "data-store",
            "CWE-89"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_sql_mapper_and_dsl_data_store() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SqlDslStores.java"),
            r#"
              import org.springframework.stereotype.Repository;
              @Repository
              interface InvoiceMapper {
                @Select("select * from invoice")
                Invoice find(String id);
              }
              interface InvoiceRepository extends QuerydslPredicateExecutor<Invoice> {}
              class SqlDslStores {
                DSLContext dslContext;
                SqlSession sqlSession;
                Jdbi jdbi;
                MyBatis mapper;
                void query() {
                  dslContext.selectFrom(INVOICE).fetch();
                  sqlSession.selectList("Invoice.find");
                  jdbi.withHandle(handle -> handle.createQuery(sql).mapTo(Invoice.class).list());
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "data-store"));
        assert!(document_has_dfd_flow(&degraded, "flow-data-store"));
        assert!(document_has_threat_target(&degraded, "data-store"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "data-store",
            "CWE-89"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_cache_framework_data_store() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(
            temp.path().join("build.gradle"),
            "plugins { id 'java' }\ndependencies { implementation 'org.springframework.boot:spring-boot-starter-cache' }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main/java/app/CacheStores.java"),
            r#"
              import org.springframework.cache.annotation.Cacheable;
              import org.springframework.cache.annotation.EnableCaching;
              @EnableCaching
              class CacheStores {
                @Cacheable("tenantProfiles")
                Profile cachedProfile(String tenantId) {}
                @CachePut("tenantProfiles")
                Profile updateProfile(Profile profile) {}
                @CacheEvict("tenantProfiles")
                void evictProfile(String tenantId) {}
                RedisTemplate<String, Profile> redisTemplate;
                ReactiveRedisTemplate<String, Profile> reactiveRedisTemplate;
                StringRedisTemplate stringRedisTemplate;
                CacheManager cacheManager;
                HazelcastInstance hazelcastInstance;
                void caffeine() { Caffeine.newBuilder().maximumSize(1000); }
                void ehcache(Ehcache tenantCache) {}
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "data-store"));
        assert!(document_has_dfd_flow(&degraded, "flow-data-store"));
        assert!(document_has_threat_target(&degraded, "data-store"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "data-store",
            "CWE-89"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_distributed_cache_data_store() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(
            temp.path().join("build.gradle"),
            "plugins { id 'java' }\ndependencies { implementation 'org.springframework.boot:spring-boot-starter-cache' }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main/java/app/DistributedCaches.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class DistributedCaches {
                IgniteCache<String, Profile> igniteCache;
                IgniteClient igniteClient;
                RemoteCacheManager remoteCacheManager;
                org.infinispan.Cache<String, Profile> infinispanCache;
                MemcachedClient memcachedClient;
                Cache2kBuilder.of(String.class, Profile.class).build();
                CacheBuilder.newBuilder().maximumSize(1000).build();
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "data-store"));
        assert!(document_has_dfd_flow(&degraded, "flow-data-store"));
        assert!(document_has_threat_target(&degraded, "data-store"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "data-store",
            "CWE-89"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_rpc_framework_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/RealtimeApis.java"),
            r#"
              import org.springframework.graphql.data.method.annotation.QueryMapping;
              class GraphQlApi {
                @QueryMapping
                Account account() {}
                @MutationMapping
                Account updateAccount() {}
                @SubscriptionMapping
                Publisher<Account> accountEvents() {}
                @SchemaMapping(typeName = "Account")
                Team team(Account account) {}
              }
              class MessagingApi implements WebSocketConfigurer {
                @MessageMapping("/billing")
                @SendTo("/topic/billing")
                BillingEvent billing(BillingCommand command) {}
                void register(StompEndpointRegistry registry) {}
                void configure(WebSocketHandlerRegistry registry) {}
                void publish(SimpMessagingTemplate template) {}
                void rsocket(RSocketMessageHandler handler) {}
              }
              @GrpcService
              class BillingGrpc extends BillingGrpc.BillingImplBase {
                ServerServiceDefinition bindService() { return super.bindService(); }
                void intercept() { ServerInterceptors.intercept(service, interceptor); }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_threat_target(&degraded, "rpc-handler"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "rpc-handler",
            "CWE-20"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_plain_grpc_server_rpc_handler() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/PlainGrpcServer.java"),
            r#"
              class PlainGrpcServer {
                BindableService billingService;
                ServerServiceDefinition serviceDefinition;
                void start() {
                  ServerBuilder.forPort(8443);
                  NettyServerBuilder.forPort(9443);
                  grpc.server.Server server;
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_threat_target(&degraded, "rpc-handler"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "rpc-handler",
            "CWE-20"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_rsocket_and_stomp_broker_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/RSocketBroker.java"),
            r#"
              import org.springframework.messaging.simp.config.MessageBrokerRegistry;
              import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
              @EnableWebSocketMessageBroker
              class BrokerConfig extends AbstractWebSocketMessageBrokerConfigurer {
                void configureMessageBroker(MessageBrokerRegistry registry) {}
                void registerStompEndpoints(StompEndpointRegistry registry) {}
              }
              interface AccountRSocket {
                @RSocketExchange("accounts.find")
                Account find(AccountRequest request);
                @ConnectMapping("accounts.connect")
                void connect(AccountSession session) {}
              }
              class RSocketClients {
                RSocketRequester requester;
                RSocketServiceProxyFactory proxyFactory;
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_threat_target(&degraded, "rpc-handler"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "rpc-handler",
            "CWE-20"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_service_rpc_framework_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ServiceRpcHandlers.java"),
            r#"
              import org.apache.dubbo.config.annotation.DubboService;
              @DubboService
              class BillingDubboService {}
              class ServiceRpcHandlers {
                TProcessor processor;
                TServer server;
                TServlet servlet;
                void thrift() { new TThreadPoolServer(args).serve(); }
                void avro() { AvroIPC.startServer(protocol, responder); }
                void dubbo() { registry.add("dubbo.protocol.name", "dubbo"); }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_threat_target(&degraded, "rpc-handler"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "rpc-handler",
            "CWE-20"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_streaming_response_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/StreamingController.java"),
            r#"
              import org.springframework.web.bind.annotation.GetMapping;
              class StreamingController {
                @GetMapping("/events/sse")
                SseEmitter sse() { return emitter; }
                @GetMapping("/events/server")
                Flux<ServerSentEvent<AccountEvent>> serverEvents() { return events; }
                @GetMapping("/events/body")
                StreamingResponseBody body() { return output -> {}; }
                @GetMapping("/events/emitter")
                ResponseBodyEmitter emitter() { return emitter; }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_threat_target(&degraded, "rpc-handler"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "rpc-handler",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /events/sse"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_spring_functional_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/FunctionalRoutes.java"),
            r#"
              import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
              import org.springframework.web.reactive.function.server.RouterFunctions;
              class FunctionalRoutes {
                void routes(AccountHandler handler) {
                  RouterFunctions.route(GET("/imports/file"), handler::importFile);
                  RouterFunctions.route().POST("/accounts/recovery", handler::recover).build();
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /imports/file"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_jaxrs_resource_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("pom.xml"), "<project></project>\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/AccountResource.java"),
            r#"
              import jakarta.ws.rs.GET;
              import jakarta.ws.rs.POST;
              import jakarta.ws.rs.Path;
              @Path("/accounts")
              class AccountResource {
                @GET
                public Account list() { return account; }
                @POST
                @Path("recovery")
                public Account recover(AccountRecovery recovery) { return account; }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /accounts/recovery"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "JAX-RS/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_webservlet_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/AccountServlets.java"),
            r#"
              import jakarta.servlet.annotation.WebServlet;
              @WebServlet("/accounts/*")
              class AccountServlet {}
              @WebServlet(urlPatterns = "/accounts/recovery")
              class RecoveryServlet {}
              @WebServlet(urlPatterns = {"/accounts/admin", "/accounts/settings"})
              class AdminServlet {}
              @WebServlet(name = "IgnoredName", value = {"/accounts/audit"})
              class AuditServlet {}
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /accounts/recovery"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /accounts/settings"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /accounts/audit"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Servlet/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_serverendpoint_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/AccountSocket.java"),
            r#"
              import jakarta.websocket.OnMessage;
              import jakarta.websocket.server.ServerEndpoint;
              @ServerEndpoint("/accounts/{id}/stream")
              class AccountSocket {
                @OnMessage
                void onMessage(String body) {}
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /accounts/{id}/stream"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "WebSocket/Java"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_micronaut_controller_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/AccountController.java"),
            r#"
              import io.micronaut.http.annotation.Controller;
              import io.micronaut.http.annotation.Get;
              import io.micronaut.http.annotation.Post;
              @Controller("/accounts")
              class AccountController {
                @Get
                Account list() { return account; }
                @Get("/{id}")
                Account show(String id) { return account; }
                @Post("/recovery")
                Account recover(AccountRecovery recovery) { return account; }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /accounts"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /accounts/recovery"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Micronaut/Java"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_ktor_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/kotlin/app")).unwrap();
        fs::write(temp.path().join("build.gradle.kts"), "plugins { kotlin(\"jvm\") }\n").unwrap();
        fs::write(
            temp.path().join("src/main/kotlin/app/Routing.kt"),
            r#"
              import io.ktor.server.routing.routing
              import io.ktor.server.routing.route
              import io.ktor.server.routing.get
              import io.ktor.server.routing.post
              fun Application.routes() {
                routing {
                  route("/accounts") {
                    get { call.respond(accounts) }
                    get("/{id}") { call.respond(account) }
                    post("/recovery") { call.respond(recovered) }
                    head("/status") { call.respond(status) }
                    options("/preflight") { call.respond(options) }
                  }
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /accounts"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /accounts/recovery"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "HEAD /accounts/status"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "OPTIONS /accounts/preflight"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Ktor/Kotlin"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_javalin_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/JavalinRoutes.java"),
            r#"
              import io.javalin.Javalin;
              import static io.javalin.apibuilder.ApiBuilder.*;
              class JavalinRoutes {
                void routes() {
                  var app = Javalin.create();
                  app.get("/accounts/{id}", ctx -> ctx.result("ok"));
                  app.post("/accounts/recovery", ctx -> ctx.result("ok"));
                  app.head("/accounts/status", ctx -> ctx.result("ok"));
                  app.options("/accounts/preflight", ctx -> ctx.result("ok"));
                  app.routes(() -> path("teams", () -> {
                    get("/{id}", ctx -> ctx.result("ok"));
                    post("/invite", ctx -> ctx.result("ok"));
                  }));
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /teams/invite"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /accounts/recovery"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "HEAD /accounts/status"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "OPTIONS /accounts/preflight"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Javalin/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_spark_java_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SparkRoutes.java"),
            r#"
              import spark.Spark;
              import static spark.Spark.*;
              class SparkRoutes {
                void routes() {
                  Spark.get("/accounts/:id", (request, response) -> "ok");
                  Spark.post("/accounts/recovery", (request, response) -> "ok");
                  Spark.head("/accounts/status", (request, response) -> "");
                  Spark.before("/admin/*", (request, response) -> {});
                  get("/teams/invite", (request, response) -> "ok");
                  head("/teams/status", (request, response) -> "");
                  after("/audit/*", (request, response) -> {});
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /accounts/recovery"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "HEAD /accounts/status"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /teams/invite"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "HEAD /teams/status"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /admin/*"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /audit/*"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Spark Java/Java"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_jooby_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/JoobyRoutes.java"),
            r#"
              import io.jooby.Jooby;
              class JoobyRoutes extends Jooby {
                {
                  path("/accounts", () -> {
                    get("/{id}", ctx -> "ok");
                    post("/recovery", ctx -> "ok");
                    head("/status", ctx -> "ok");
                    options("/preflight", ctx -> "ok");
                    all("/audit", ctx -> "ok");
                  });
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /accounts/recovery"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "HEAD /accounts/status"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "OPTIONS /accounts/preflight"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /accounts/audit"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Jooby/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_vertx_web_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/VertxRoutes.java"),
            r#"
              import io.vertx.ext.web.Router;
              class VertxRoutes {
                void routes(Vertx vertx) {
                  Router router = Router.router(vertx);
                  router.get("/accounts/:id").handler(ctx -> ctx.response().end("ok"));
                  router.post("/accounts/recovery").handler(ctx -> ctx.response().end("ok"));
                  router.head("/accounts/status").handler(ctx -> ctx.response().end("ok"));
                  router.route("/accounts").handler(ctx -> ctx.response().end("ok"));
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /accounts/recovery"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "HEAD /accounts/status"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /accounts"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Vert.x/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_vertx_http_method_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/VertxHttpMethodRoutes.java"),
            r#"
              import io.vertx.core.http.HttpMethod;
              import io.vertx.ext.web.Router;
              class VertxHttpMethodRoutes {
                void routes(Vertx vertx) {
                  Router router = Router.router(vertx);
                  router.route(HttpMethod.GET, "/accounts/:id").handler(this::show);
                  router.route(HttpMethod.POST, "/accounts/recovery").handler(this::recover);
                  router.route(HttpMethod.HEAD, "/accounts/status").handler(this::status);
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /accounts/recovery"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "HEAD /accounts/status"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Vert.x/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_armeria_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ArmeriaRoutes.java"),
            r#"
              import com.linecorp.armeria.server.Server;
              class ArmeriaRoutes {
                void routes() {
                  var server = Server.builder();
                  server.service("/accounts/{id}", accountService);
                  server.serviceUnder("/accounts/recovery", recoveryService);
                  server.annotatedService("/admin", adminService);
                  server.route().get("/accounts", accountListService);
                  server.route().post("/accounts/import", accountImportService);
                  server.route().head("/accounts/status", accountStatusService);
                  server.route().path("/accounts/audit").build(accountAuditService);
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /accounts/import"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /accounts/recovery"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "HEAD /accounts/status"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /accounts/audit"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Armeria/Java"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_helidon_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/HelidonRoutes.java"),
            r#"
              import io.helidon.webserver.WebServer;
              import io.helidon.webserver.Routing;
              class HelidonRoutes {
                void routes() {
                  var routing = Routing.builder();
                  routing.register("/accounts", rules -> {
                    rules.get("/{id}", this::show);
                    rules.post("/recovery", this::recover);
                    rules.head("/status", this::status);
                    rules.any("/audit", this::audit);
                  });
                  WebServer.builder().routing(routing).build();
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /accounts/recovery"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "HEAD /accounts/status"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /accounts/audit"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Helidon/Java"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_ratpack_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/RatpackRoutes.java"),
            r#"
              import ratpack.server.RatpackServer;
              class RatpackRoutes {
                void routes() throws Exception {
                  RatpackServer.start(server -> server.handlers(chain -> {
                    chain.prefix("accounts", account -> {
                      account.get(":id", ctx -> ctx.render("ok"));
                      account.post("recovery", ctx -> ctx.render("ok"));
                      account.head("status", ctx -> ctx.render("ok"));
                      account.options("preflight", ctx -> ctx.render("ok"));
                      account.all("audit", ctx -> ctx.render("ok"));
                    });
                  }));
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /accounts/recovery"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "HEAD /accounts/status"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "OPTIONS /accounts/preflight"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /accounts/audit"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Ratpack/Java"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_undertow_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/UndertowRoutes.java"),
            r#"
              import io.undertow.Handlers;
              import io.undertow.Undertow;
              class UndertowRoutes {
                void routes() {
                  var paths = Handlers.path();
                  paths.addExactPath("/accounts/{id}", accountHandler);
                  paths.addPrefixPath("/accounts/recovery", recoveryHandler);
                  var routes = Handlers.routing();
                  routes.get("/accounts", listHandler);
                  routes.post("/accounts/import", importHandler);
                  routes.head("/accounts/status", statusHandler);
                  routes.options("/accounts/preflight", optionsHandler);
                  Undertow.builder().setHandler(paths).build();
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "http-route"));
        assert!(document_has_dfd_flow(&degraded, "flow-http-route"));
        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /accounts/import"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /accounts/recovery"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "HEAD /accounts/status"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "OPTIONS /accounts/preflight"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Undertow/Java"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_servlet_and_webflux_upload_parsers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/UploadParsers.java"),
            r#"
              import org.springframework.web.bind.annotation.PostMapping;
              class UploadParsers {
                @PostMapping(path = "/imports/reactive", consumes = "multipart/form-data")
                void reactive(FilePart filePart, Flux<PartEvent> partEvents) {}
                void servlet(jakarta.servlet.http.Part servletPart) {}
                void legacy(javax.servlet.http.Part servletPart) {}
                void outbound(MultipartBodyBuilder multipartBodyBuilder) {}
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_flow(&degraded, "flow-file-upload"));
        assert!(document_has_threat_target(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_multipart_configuration_upload_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/MultipartConfig.java"),
            r#"
              import org.springframework.web.multipart.support.StandardServletMultipartResolver;
              @MultipartConfig(fileSizeThreshold = 1024)
              class MultipartConfig {
                CommonsMultipartResolver commonsMultipartResolver;
                StandardServletMultipartResolver standardServletMultipartResolver;
                MultipartConfigElement multipartConfigElement;
                MultipartConfigFactory multipartConfigFactory;
                void limits(Object resolver, Object factory) {
                  resolver.setMaxUploadSize(1048576);
                  factory.setMaxFileSize(DataSize.ofMegabytes(10));
                  factory.setMaxRequestSize(DataSize.ofMegabytes(20));
                  factory.setFileSizeThreshold(DataSize.ofKilobytes(512));
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_flow(&degraded, "flow-file-upload"));
        assert!(document_has_threat_target(&degraded, "file-upload-parser"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_async_event_workers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/WorkerHandlers.java"),
            r#"
              class WorkerHandlers {
                @Async
                void sendEmail(EmailCommand command) {}
                @EventListener
                void onTenantEvent(TenantEvent event) {}
                @JmsListener(destination = "invoice-events")
                void consumeInvoice(String message) {}
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_messaging_batch_and_scheduler_jobs() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/JobConfig.java"),
            r#"
              import org.springframework.batch.core.configuration.annotation.EnableBatchProcessing;
              import org.springframework.scheduling.annotation.Scheduled;
              @EnableBatchProcessing
              class JobConfig {
                @Scheduled(cron = "0 0 * * * *")
                void hourlyDigest() {}
                void launch(JobLauncher jobLauncher, Job job) { jobLauncher.run(job, params); }
                void publish(KafkaTemplate<String, Event> kafkaTemplate) { kafkaTemplate.send("events", event); }
                void queue(RabbitTemplate rabbitTemplate) { rabbitTemplate.convertAndSend("jobs", job); }
                void notify(SqsAsyncClient sqsAsyncClient) { sqsAsyncClient.sendMessage(request); }
                TaskExecutor taskExecutor;
              }
              class NightlyQuartzJob extends QuartzJobBean {}
              class BillingQuartzJob implements Job {}
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_batch_step_and_item_jobs() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/BatchStepJobs.java"),
            r#"
              import org.springframework.batch.core.job.builder.JobBuilder;
              class BatchStepJobs {
                Tasklet cleanupTasklet;
                ItemReader<Customer> itemReader;
                ItemProcessor<Customer, Customer> itemProcessor;
                ItemWriter<Customer> itemWriter;
                RepositoryItemReader<Customer> repositoryItemReader;
                JdbcPagingItemReader<Customer> jdbcPagingItemReader;
                void build(JobRepository jobRepository, PlatformTransactionManager tx) {
                  new JobBuilder("billingImport", jobRepository);
                  new StepBuilder("loadCustomers", jobRepository);
                  stepBuilder.chunk(100, tx);
                  stepBuilder.tasklet(cleanupTasklet, tx);
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_scheduler_infrastructure_jobs() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SchedulerConfig.java"),
            r#"
              import org.springframework.scheduling.annotation.EnableScheduling;
              @EnableScheduling
              class SchedulerConfig implements SchedulingConfigurer {
                TaskScheduler taskScheduler;
                ThreadPoolTaskScheduler threadPoolTaskScheduler;
                ScheduledTaskRegistrar taskRegistrar;
                ScheduledExecutorService executorService;
                void configureTasks(ScheduledTaskRegistrar registrar) {
                  registrar.setTaskScheduler(taskScheduler);
                  Executors.newScheduledThreadPool(4);
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_cloud_event_and_pulsar_jobs() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/CloudEventJobs.java"),
            r#"
              import org.springframework.pulsar.annotation.PulsarListener;
              class CloudEventJobs {
                @PulsarListener(topics = "tenant-events")
                void onPulsar(Event event) {}
                void publish(
                    SnsClient snsClient,
                    SnsAsyncClient snsAsyncClient,
                    EventBridgeClient eventBridgeClient,
                    EventBridgeAsyncClient eventBridgeAsyncClient,
                    KinesisClient kinesisClient,
                    KinesisAsyncClient kinesisAsyncClient,
                    PulsarClient pulsarClient,
                    SnsTemplate snsTemplate,
                    PulsarTemplate<Event> pulsarTemplate
                ) {}
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_jvm_integration_handler_jobs() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/IntegrationHandlers.java"),
            r#"
              import org.springframework.integration.annotation.InboundChannelAdapter;
              import org.springframework.integration.annotation.ServiceActivator;
              import org.springframework.integration.annotation.Transformer;
              import org.springframework.integration.dsl.IntegrationFlow;
              import org.springframework.kafka.annotation.KafkaHandler;
              import org.springframework.kafka.annotation.RetryableTopic;
              class IntegrationHandlers {
                @KafkaHandler
                void onKafka(Event event) {}
                @RabbitHandler
                void onRabbit(Event event) {}
                @JmsHandler
                void onJms(Event event) {}
                @StreamListener("orders")
                void onStream(Event event) {}
                @ServiceActivator(inputChannel = "orders")
                void activate(Event event) {}
                @Transformer(inputChannel = "orders")
                Event transform(Event event) { return event; }
                @InboundChannelAdapter(channel = "polling")
                MessageSource<?> poll() { return source; }
                @RetryableTopic
                void retry(Event event) {}
                IntegrationFlow inboundFlow;
                MessageHandler deadLetterHandler;
                Pollers.fixedRate(5000);
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
    }

    #[test]
    fn deterministic_threat_model_includes_dotnet_background_workers() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddHostedService<ReportWorker>();\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("ReportWorker.cs"),
            "class ReportWorker : BackgroundService { protected override Task ExecuteAsync(CancellationToken token) => Task.CompletedTask; }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_dotnet_message_consumers() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("BillingConsumer.cs"),
            "class BillingConsumer : IConsumer<BillingEvent> { public Task Consume(ConsumeContext<BillingEvent> context) => Task.CompletedTask; }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_dotnet_quartz_scheduled_jobs() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddQuartz(q => {});\nbuilder.Services.AddQuartzHostedService(options => {});\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("NightlyJob.cs"),
            "class NightlyJob : IJob {\npublic Task Execute(IJobExecutionContext context) => Task.CompletedTask;\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "background-job"));
        assert!(document_has_dfd_flow(&degraded, "flow-background-job"));
        assert!(document_has_threat_target(&degraded, "background-job"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "background-job",
            "CWE-400"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_dotnet_data_external_and_process_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("AdminTasks.cs"),
            r#"
              class AdminTasks {
                void Run() {
                  using var cmd = new SqlCommand("select * from users", connection);
                  var response = new HttpClient().GetAsync(remoteUrl);
                  Process.Start(new ProcessStartInfo("sh", "-c " + input));
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "data-store"));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_has_threat_target(&degraded, "process-execution"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "data-store",
            "CWE-89"
        ));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "external-service",
            "CWE-918"
        ));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "process-execution",
            "CWE-78"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_dotnet_process_start_configuration() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("ShellRunner.cs"),
            r#"
              class ShellRunner {
                void Run(string input) {
                  var startInfo = new ProcessStartInfo();
                  startInfo.FileName = "cmd.exe";
                  startInfo.Arguments = "/c " + input;
                  startInfo.UseShellExecute = false;
                  startInfo.RedirectStandardOutput = true;
                  startInfo.RedirectStandardError = true;
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "process-execution"));
        assert!(document_has_dfd_flow(&degraded, "flow-process-exec"));
        assert!(document_has_threat_target(&degraded, "process-execution"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "process-execution",
            "CWE-78"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_dotnet_grpc_client_external_service() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddGrpcClient<Billing.BillingClient>(options => options.Address = billingUri);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("BillingClient.cs"),
            "var channel = GrpcChannel.ForAddress(remoteUrl, new GrpcChannelOptions { HttpClient = httpClient });\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "external-service"));
        assert!(document_has_dfd_flow(&degraded, "flow-external-service"));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "external-service",
            "CWE-918"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_dotnet_legacy_rest_client_external_service() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("LegacyClients.cs"),
            r#"
              class LegacyClients {
                void Fetch() {
                  using var web = new WebClient();
                  var body = web.DownloadString(remoteUrl);
                  var request = WebRequest.Create(remoteUrl);
                  var typed = (HttpWebRequest)WebRequest.Create(apiUrl);
                  var client = new RestClient(remoteUrl);
                  var restRequest = new RestRequest("/invoices");
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "external-service"));
        assert!(document_has_dfd_flow(&degraded, "flow-external-service"));
        assert!(document_has_threat_target(&degraded, "external-service"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "external-service",
            "CWE-918"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_dotnet_cache_data_store_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("CacheStore.cs"),
            "class CacheStore { private readonly IDistributedCache cache; private readonly IMemoryCache memory; }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "data-store"));
        assert!(document_has_dfd_flow(&degraded, "flow-data-store"));
        assert!(document_has_threat_target(&degraded, "data-store"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "data-store",
            "CWE-89"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_dotnet_output_cache_data_store_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              builder.Services.AddOutputCache();
              builder.Services.AddResponseCaching();
              app.UseOutputCache();
              app.UseResponseCaching();
              app.MapGet("/reports", Reports).CacheOutput();
              [OutputCache]
              [ResponseCache(Duration = 60)]
              class ReportsController {}
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "data-store"));
        assert!(document_has_dfd_flow(&degraded, "flow-data-store"));
        assert!(document_has_threat_target(&degraded, "data-store"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "data-store",
            "CWE-89"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_dotnet_ef_core_data_store_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlServer(connectionString));
              builder.Services.AddDbContextPool<AuditDbContext>(options => options.UseNpgsql(auditConnection));
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("AppDbContext.cs"),
            r#"
              class AppDbContext : DbContext {
                AppDbContext(DbContextOptions<AppDbContext> options) : base(options) {}
                DbSet<User> Users { get; set; }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "data-store"));
        assert!(document_has_dfd_flow(&degraded, "flow-data-store"));
        assert!(document_has_threat_target(&degraded, "data-store"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "data-store",
            "CWE-89"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_treats_rails_and_laravel_params_as_attacker_controlled() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("app/controllers")).unwrap();
        fs::write(
            temp.path().join("app/controllers/imports_controller.rb"),
            "class ImportsController\ndef create\nYAML.load(params[:payload])\nend\nend\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/controllers/ImportController.php"),
            "<?php\nclass ImportController { public function store(Request $request) { json_decode($request->input('payload')); } }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "Deserialization or parser boundary"
        ));
    }

    #[test]
    fn deterministic_threat_model_treats_rails_cookies_as_attacker_controlled() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("app/controllers")).unwrap();
        fs::write(
            temp.path().join("app/controllers/session_controller.rb"),
            "class SessionController\ndef show\ntoken = cookies.signed[:session_token]\nend\nend\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "Session state boundary"
        ));
    }

    #[test]
    fn deterministic_threat_model_treats_go_and_rust_cookies_as_attacker_controlled() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/session.go"),
            "package svc\nfunc handler(r *http.Request) { sessionCookie, _ := r.Cookie(\"session\"); _ = sessionCookie }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/session.rs"),
            "async fn handler(cookies: CookieJar) { let sid = cookies.get(\"sid\"); }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "Session state boundary"
        ));
    }

    #[test]
    fn deterministic_threat_model_treats_aspnet_cookies_as_attacker_controlled() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("Controllers")).unwrap();
        fs::write(
            temp.path().join("Controllers/SessionController.cs"),
            "class SessionController { string Show() { var sid = Request.Cookies[\"sid\"]; return sid; } }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "Session state boundary"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_treats_go_and_rust_headers_as_attacker_controlled() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/webhook.go"),
            "package svc\nfunc handler(r *http.Request) { signature := r.Header.Get(\"X-Signature\"); verify(signature) }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/webhook.rs"),
            "async fn handler(headers: HeaderMap) { let signature = headers.get(\"x-signature\"); }\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "Request trust boundary"
        ));
    }

    #[test]
    fn deterministic_threat_model_treats_python_request_body_as_attacker_controlled() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/views.py"),
            "import yaml\ndef import_view(request):\n    payload = yaml.load(request.body)\n    filters = request.query_params.get('filter')\n    return payload, filters\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "Deserialization or parser boundary"
        ));
    }

    #[test]
    fn deterministic_threat_model_preserves_backend_route_framework_context() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::create_dir_all(temp.path().join("src/app/api/session")).unwrap();
        fs::create_dir_all(temp.path().join("Controllers")).unwrap();
        fs::create_dir_all(temp.path().join("config")).unwrap();
        fs::create_dir_all(temp.path().join("routes")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"next":"14.0.0"}}"#,
        )
        .unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(temp.path().join("Gemfile"), "gem 'rails'\n").unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"laravel/framework":"^10"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main/java/app/AdminController.java"),
            "@PostMapping(\"/admin/invite\")\nvoid invite() {}\n@PostMapping(\"/admin/import-file\")\nvoid upload(@RequestPart MultipartFile file) {}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("config/routes.rb"),
            "Rails.application.routes.draw do\npost '/admin/invite', to: 'admin#invite'\nend\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("routes/web.php"),
            "<?php\nRoute::post('/admin/invite', [AdminController::class, 'invite']);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/app/api/session/route.ts"),
            "import { NextRequest, NextResponse } from 'next/server';\nexport async function POST(request: NextRequest) { const sid = request.cookies.get('sid'); return NextResponse.json({ sid }); }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Controllers/AdminController.cs"),
            "using Microsoft.AspNetCore.Mvc;\n[Route(\"api/admin\")]\nclass AdminController {\n[Route(\"invite\")]\n[HttpPost]\npublic IActionResult Invite() => Ok();\n}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\napp.MapHealthChecks(\"/health/live\");\napp.MapOpenApi();\napp.MapOpenApi(\"/internal/openapi/{documentName}.json\");\napp.MapSwagger();\napp.UseSwagger(\"docs/{documentName}/swagger.json\");\napp.MapGraphQL();\napp.UseGraphQL(\"/query\");\napp.MapOptions(\"/saml/callback\", CallbackOptions);\napp.MapFallback(\"/{*path:nonfile}\", SpaFallback);\napp.MapFallbackToFile(\"index.html\");\napp.MapFallbackToPage(\"/_Host\");\napp.MapMethods(\"/imports/batch\", new[] { \"POST\" }, BatchUpload);\napp.MapHub<AdminHub>(\"/hubs/admin\");\napp.MapBlazorHub();\napp.MapBlazorHub(\"/live/blazor\");\napp.MapRazorPages();\napp.MapGrpcService<GreeterService>();\napp.MapControllerRoute(name: \"default\", pattern: \"mvc/{controller}/{action}\");\napp.MapAreaControllerRoute(name: \"admin-area\", areaName: \"Admin\", pattern: \"admin/{controller}/{action}\");\napp.MapDefaultControllerRoute();\napp.MapGroup(\"/api/direct\").MapPost(\"invite\", Invite);\napp.MapGroup(\"/api/direct\").MapMethods(\"audit\", new[] { \"POST\" }, Audit);\nvar admin = app.MapGroup(\"/api/admin\");\nadmin.MapPost(\"bulk-invite\", BulkInvite);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_evidence_anchor_description(&degraded, "Spring/Java"));
        assert!(document_has_evidence_anchor_description(&degraded, "Rails/Ruby"));
        assert!(document_has_evidence_anchor_description(&degraded, "Laravel/PHP"));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "Next.js/TypeScript"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_flow(&degraded, "flow-file-upload"));
        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "rpc-handler",
            "CWE-20"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "OPTIONS /saml/callback"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /{*path:nonfile}"
        ));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_health_and_fallback_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapHealthChecks(\"/health/live\");\napp.MapOpenApi();\napp.MapOpenApi(\"/internal/openapi/{documentName}.json\");\napp.MapSwagger();\napp.UseSwagger(\"docs/{documentName}/swagger.json\");\napp.MapFallback(\"/{*path:nonfile}\", SpaFallback);\napp.MapFallbackToFile(\"index.html\");\napp.MapFallbackToPage(\"/_Host\");\napp.MapMethods(\"/imports/constants\", new[] { HttpMethods.Put, HttpMethods.Patch }, Constants);\napp.MapMethods(\"/imports/tunnel\", new[] { \"TRACE\", HttpMethods.Connect }, Tunnel);\nvar admin = app.MapGroup(\"/api/admin\");\nadmin.MapHead(\"group-status\", Status);\nadmin.MapOptions(\"preflight\", Options);\nadmin.MapPut(\"roles/{id}\", PutRole);\nadmin.MapPatch(\"profile/{id}\", PatchProfile);\nadmin.MapDelete(\"sessions/{id}\", DeleteSession);\nadmin.MapMethods(\"audit\", new[] { \"POST\", \"DELETE\" }, Audit);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        for route in [
            "GET /health/live",
            "GET /openapi/{documentName}.json",
            "GET /internal/openapi/{documentName}.json",
            "GET /swagger/{documentName}/swagger.json",
            "GET /docs/{documentName}/swagger.json",
            "ANY /{*path:nonfile}",
            "ANY *",
            "PUT /imports/constants",
            "PATCH /imports/constants",
            "TRACE /imports/tunnel",
            "CONNECT /imports/tunnel",
            "HEAD /api/admin/group-status",
            "OPTIONS /api/admin/preflight",
            "PUT /api/admin/roles/{id}",
            "PATCH /api/admin/profile/{id}",
            "DELETE /api/admin/sessions/{id}",
            "POST /api/admin/audit",
            "DELETE /api/admin/audit",
        ] {
            assert!(
                document_has_narrative_item(
                    &degraded,
                    "/data/document/narrative/inputCategories/attackerControlled",
                    route
                ),
                "missing ASP.NET route narrative item: {route}"
            );
        }
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_grouped_health_check_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapHealthChecks(\"/health/live\");\napp.MapGroup(\"/ops\").MapHealthChecks(\"live\");\napp.MapGroup(\"/internal\").MapGroup(\"ops\").MapHealthChecks(\"ready\");\nvar assignedOps = app.MapGroup(\"/assigned\").MapGroup(\"ops\");\nassignedOps.MapHealthChecks(\"startup\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        for route in [
            "GET /health/live",
            "GET /ops/live",
            "GET /internal/ops/ready",
            "GET /assigned/ops/startup",
        ] {
            assert!(
                document_has_narrative_item(
                    &degraded,
                    "/data/document/narrative/inputCategories/attackerControlled",
                    route
                ),
                "missing grouped health-check route narrative item: {route}"
            );
        }
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_grouped_fallback_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapFallback(\"/{*path:nonfile}\", SpaFallback);\napp.MapGroup(\"/spa\").MapFallback(\"{*path:nonfile}\", SpaFallback);\napp.MapGroup(\"/spa\").MapFallbackToFile(\"index.html\");\napp.MapGroup(\"/tenant\").MapGroup(\"spa\").MapFallbackToPage(\"/_Host\");\nvar assignedSpa = app.MapGroup(\"/assigned\").MapGroup(\"spa\");\nassignedSpa.MapFallback(\"{*path:nonfile}\", AssignedFallback);\nassignedSpa.MapFallbackToFile(\"index.html\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        for route in [
            "ANY /{*path:nonfile}",
            "ANY /spa/{*path:nonfile}",
            "ANY /spa/*",
            "ANY /tenant/spa/*",
            "ANY /assigned/spa/{*path:nonfile}",
            "ANY /assigned/spa/*",
        ] {
            assert!(
                document_has_narrative_item(
                    &degraded,
                    "/data/document/narrative/inputCategories/attackerControlled",
                    route
                ),
                "missing grouped fallback route narrative item: {route}"
            );
        }
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_nested_route_groups() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\nvar api = app.MapGroup(\"/api\");\nvar admin = api.MapGroup(\"admin\");\nadmin.MapGet(\"settings\", Settings);\napp.MapGroup(\"/api/chained\").MapGroup(\"admin\").MapGet(\"settings\", ChainedSettings);\nvar assigned = app.MapGroup(\"/api/assigned\").MapGroup(\"admin\");\nassigned.MapGet(\"settings\", AssignedSettings);\nvar assignedMethods = app.MapGroup(\"/api/assigned-methods\").MapGroup(\"admin\");\nassignedMethods.MapMethods(\"audit\", new[] { \"POST\", \"DELETE\" }, AssignedAudit);\nvar assignedConstants = app.MapGroup(\"/api/assigned-constants\").MapGroup(\"admin\");\nassignedConstants.MapMethods(\"flags\", new[] { HttpMethods.Put, HttpMethods.Patch }, AssignedFlags);\nvar assignedTunnel = app.MapGroup(\"/api/assigned-tunnel\").MapGroup(\"admin\");\nassignedTunnel.MapMethods(\"proxy\", new[] { \"TRACE\", HttpMethods.Connect }, AssignedTunnel);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /api/admin/settings"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /api/chained/admin/settings"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /api/assigned/admin/settings"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /api/assigned-methods/admin/audit"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "DELETE /api/assigned-methods/admin/audit"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "PUT /api/assigned-constants/admin/flags"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "PATCH /api/assigned-constants/admin/flags"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "TRACE /api/assigned-tunnel/admin/proxy"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "CONNECT /api/assigned-tunnel/admin/proxy"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_chained_nested_map_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapGroup(\"/api\").MapGroup(\"put\").MapGroup(\"admin\").MapMethods(\"audit\", new[] { \"DELETE\" }, DeleteAudit);\napp.MapGroup(\"/api\").MapGroup(\"trace\").MapGroup(\"tunnel\").MapMethods(\"proxy\", new[] { HttpMethods.Connect }, Tunnel);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "DELETE /api/put/admin/audit"
        ));
        assert!(!document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "PUT /api/put/admin/audit"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "CONNECT /api/trace/tunnel/proxy"
        ));
        assert!(!document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "TRACE /api/trace/tunnel/proxy"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_chained_grouped_routes_after_metadata() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapGroup(\"/api\").WithTags(\"admin\").MapGet(\"settings\", Settings);\napp.MapGroup(\"/api\").MapGroup(\"v1\").WithName(\"ignored-name\").MapPost(\"users\", Users);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /api/settings"
        ));
        assert!(!document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /api/admin"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /api/v1/users"
        ));
        assert!(!document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /api/v1/ignored-name"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_razor_pages_route() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapRazorPages();\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /{page}"
        ));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-20"));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_graphql_route() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapGraphQL();\napp.UseGraphQL(\"/query\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_chained_grouped_default_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapGroup(\"/docs\").MapOpenApi();\napp.MapGroup(\"/docs\").MapOpenApi(\"custom/{documentName}.json\");\napp.MapGroup(\"/docs\").MapSwagger();\napp.MapGroup(\"/docs\").MapSwagger(\"custom/{documentName}/swagger.json\");\napp.MapGroup(\"/api\").MapGraphQL();\napp.MapGroup(\"/api\").MapGraphQL(\"query\");\napp.MapGroup(\"/internal\").MapGroup(\"docs\").MapOpenApi();\napp.MapGroup(\"/internal\").MapGroup(\"api\").MapGraphQL(\"query\");\nvar assignedDocs = app.MapGroup(\"/assigned\").MapGroup(\"docs\");\nassignedDocs.MapOpenApi();\nassignedDocs.MapOpenApi(\"custom/{documentName}.json\");\nvar assignedApi = app.MapGroup(\"/assigned\").MapGroup(\"api\");\nassignedApi.MapGraphQL(\"query\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /docs/openapi/{documentName}.json"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /docs/custom/{documentName}.json"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /docs/swagger/{documentName}/swagger.json"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /docs/custom/{documentName}/swagger.json"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /api/graphql"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /api/query"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /internal/docs/openapi/{documentName}.json"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /internal/api/query"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /assigned/docs/openapi/{documentName}.json"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /assigned/docs/custom/{documentName}.json"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /assigned/api/query"
        ));
        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_chained_grouped_ui_defaults() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapGroup(\"/admin\").MapRazorPages();\napp.MapGroup(\"/live\").MapBlazorHub();\napp.MapGroup(\"/live\").MapBlazorHub(\"custom-blazor\");\napp.MapGroup(\"/tenant\").MapRazorComponents<App>();\napp.MapGroup(\"/tenant\").MapRazorComponents<App>(\"ui/{**page}\");\napp.MapGroup(\"/internal\").MapGroup(\"live\").MapBlazorHub();\napp.MapGroup(\"/internal\").MapGroup(\"tenant\").MapRazorComponents<App>(\"ui/{**page}\");\nvar assignedLive = app.MapGroup(\"/assigned\").MapGroup(\"live\");\nassignedLive.MapBlazorHub();\nvar assignedTenant = app.MapGroup(\"/assigned\").MapGroup(\"tenant\");\nassignedTenant.MapRazorComponents<App>(\"ui/{**page}\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /admin/{page}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /live/_blazor"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /live/custom-blazor"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /tenant/{component}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /tenant/ui/{**page}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /internal/live/_blazor"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /internal/tenant/ui/{**page}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /assigned/live/_blazor"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /assigned/tenant/ui/{**page}"
        ));
        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_graphql_service_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Graphql.cs"),
            r#"
              builder.Services.AddGraphQLServer();
              builder.Services.AddGraphQL(options => {});
              builder.Services.AddGraphQLServer().AddQueryType<Query>();
              builder.Services.AddGraphQLServer().AddMutationType<Mutation>();
              [ExtendObjectType("Query")]
              class UserQueries {}
              class UserType : ObjectType<User> {}
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_has_threat_target(&degraded, "rpc-handler"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "rpc-handler",
            "CWE-20"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_identity_api_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\nvar account = app.MapGroup(\"/account\");\naccount.MapIdentityApi<AppUser>();\nvar nestedAccount = app.MapGroup(\"/api\").MapGroup(\"account\");\nnestedAccount.MapIdentityApi<AppUser>();\napp.MapGroup(\"/chained-account\").MapIdentityApi<AppUser>();\napp.MapGroup(\"/chained\").MapGroup(\"account\").MapIdentityApi<AppUser>();\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-640"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "ANY /account"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "ANY /api/account"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "ANY /chained-account"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/credentialFlows",
            "ANY /chained/account"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_metrics_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapMetrics();\napp.MapPrometheusScrapingEndpoint(\"/internal/metrics\");\nvar observability = app.MapGroup(\"/ops\");\nobservability.MapMetrics();\nobservability.MapPrometheusScrapingEndpoint(\"prometheus\");\napp.MapGroup(\"/chained-ops\").MapMetrics();\napp.MapGroup(\"/chained-prom\").MapPrometheusScrapingEndpoint();\napp.MapGroup(\"/chained-prom\").MapPrometheusScrapingEndpoint(\"custom-prometheus\");\napp.MapGroup(\"/internal\").MapGroup(\"ops\").MapMetrics();\nvar assignedOps = app.MapGroup(\"/assigned\").MapGroup(\"ops\");\nassignedOps.MapMetrics();\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-200"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /metrics"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /ops/metrics"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /ops/prometheus"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /chained-ops/metrics"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /chained-prom/metrics"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /chained-prom/custom-prometheus"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /internal/ops/metrics"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /assigned/ops/metrics"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_static_asset_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapStaticAssets();\nvar publicAssets = app.MapGroup(\"/public\");\npublicAssets.MapStaticAssets();\npublicAssets.MapStaticAssets(\"files/{**path}\");\napp.MapGroup(\"/chained-public\").MapStaticAssets();\napp.MapGroup(\"/chained-public\").MapStaticAssets(\"assets/{**path}\");\napp.MapGroup(\"/internal\").MapGroup(\"public\").MapStaticAssets();\nvar assignedPublic = app.MapGroup(\"/assigned\").MapGroup(\"public\");\nassignedPublic.MapStaticAssets();\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-200"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /{staticAsset}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /public/{staticAsset}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /chained-public/{staticAsset}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /chained-public/assets/{**path}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /internal/public/{staticAsset}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /assigned/public/{staticAsset}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/dataEgressFlows",
            "GET /public/files/{**path}"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_reverse_proxy_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapReverseProxy();\nvar gateway = app.MapGroup(\"/gateway\");\ngateway.MapReverseProxy();\ngateway.MapReverseProxy(\"proxy/{**catchAll}\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-918"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "ANY /{**proxy}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "ANY /gateway/{**proxy}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "ANY /gateway/proxy/{**catchAll}"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_forwarder_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapForwarder(\"/proxy/{**catchAll}\", \"https://backend.internal\");\nvar gateway = app.MapGroup(\"/gateway\");\ngateway.MapForwarder(\"proxy/{**catchAll}\", \"https://backend.internal\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-918"));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "ANY /proxy/{**catchAll}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "ANY /gateway/proxy/{**catchAll}"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_fallback_controller_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapFallbackToController(\"proxy/{**path}\", \"Proxy\", \"Gateway\");\nvar gateway = app.MapGroup(\"/gateway\");\ngateway.MapFallbackToController(\"proxy/{**path}\", \"Proxy\", \"Gateway\");\ngateway.MapFallbackToAreaController(\"spa/{*path:nonfile}\", \"Index\", \"Spa\", \"Public\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "http-route",
            "CWE-918"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "ANY /proxy/{**path}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/callbackFlows",
            "ANY /gateway/proxy/{**path}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /gateway/spa/{*path:nonfile}"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_razor_components_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapRazorComponents<App>();\nvar tenantUi = app.MapGroup(\"/tenant\");\ntenantUi.MapRazorComponents<App>();\ntenantUi.MapRazorComponents<App>(\"ui/{**page}\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-20"));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /{component}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /tenant/{component}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /tenant/ui/{**page}"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_page_route_conventions() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapAreaPageRoute(\"Admin\", \"/Audit\", \"admin/audit/{**path}\");\nvar docs = app.MapGroup(\"/docs\");\ndocs.MapPageRoute(\"/Guide\", \"guide/{id?}\");\ndocs.MapAreaPageRoute(\"Admin\", \"/Audit\", \"admin/audit/{**path}\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-862"));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /admin/audit/{**path}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /docs/guide/{id?}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /docs/admin/audit/{**path}"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_dynamic_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapDynamicControllerRoute<SlugTransformer>(\"{**slug}\");\nvar dynamic = app.MapGroup(\"/dynamic\");\ndynamic.MapDynamicControllerRoute<SlugTransformer>(\"{**slug}\");\ndynamic.MapDynamicPageRoute<PageTransformer>(\"cms/{**path}\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-20"));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /{**slug}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /dynamic/{**slug}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /dynamic/cms/{**path}"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_map_controllers_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapControllers();\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-20"));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /{controller}/{action}"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_positional_controller_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapAreaControllerRoute(\"admin\", \"Admin\", \"admin/{controller}/{action}\");\napp.MapGroup(\"/tenant\").MapControllerRoute(\"catalog\", \"catalog/{controller}/{action}\");\napp.MapGroup(\"/tenant\").MapAreaControllerRoute(\"admin\", \"Admin\", \"admin/{controller}/{action}\");\napp.MapGroup(\"/named\").MapControllerRoute(name: \"catalog\", pattern: \"catalog/{controller}/{action}\");\napp.MapGroup(\"/named\").MapAreaControllerRoute(name: \"admin\", pattern: \"admin/{controller}/{action}\", areaName: \"Admin\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-862"));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /admin/{controller}/{action}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /tenant/catalog/{controller}/{action}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /tenant/admin/{controller}/{action}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /named/catalog/{controller}/{action}"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /named/admin/{controller}/{action}"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_accept_verbs_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("AdminController.cs"),
            "using Microsoft.AspNetCore.Mvc;\n[Route(\"api\")]\nclass AdminController {\n[AcceptVerbs(\"POST\", HttpMethods.Patch, \"DELETE\", Route = \"admin/export\")]\npublic IActionResult Export() => Ok();\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-862"));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /api/admin/export"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "DELETE /api/admin/export"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "PATCH /api/admin/export"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_ignores_aspnet_http_attribute_name_metadata() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("AdminController.cs"),
            "using Microsoft.AspNetCore.Mvc;\n[Route(\"api/admin\")]\nclass AdminController {\n[HttpGet(Name = \"GetAdmin\")]\npublic IActionResult Index() => Ok();\n[HttpPost(Template = \"reports/export\")]\npublic IActionResult Export() => Ok();\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-862"));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /api/admin/reports/export"
        ));
        assert!(!document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /api/admin/GetAdmin"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_ignores_aspnet_route_attribute_name_metadata() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("AdminController.cs"),
            "using Microsoft.AspNetCore.Mvc;\n[Route(Name = \"AdminRoot\")]\nclass AdminController {\n[HttpGet(\"status\")]\npublic IActionResult Status() => Ok();\n[Route(Template = \"reports/export\")]\n[HttpPost]\npublic IActionResult Export() => Ok();\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "POST /reports/export"
        ));
        assert!(!document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /AdminRoot/status"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_normalizes_aspnet_route_tokens() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("AdminController.cs"),
            "using Microsoft.AspNetCore.Mvc;\n[Route(\"admin/[area]/[controller]\")]\nclass AdminController {\n[HttpGet(\"[action]\")]\npublic IActionResult Status() => Ok();\n}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-862"));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "GET /admin/{area}/{controller}/{action}"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_short_circuit_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapShortCircuit(404, \"robots.txt\");\napp.MapGroup(\"/static\").MapShortCircuit(404, \"robots.txt\");\napp.MapGroup(\"/internal\").MapGroup(\"static\").MapShortCircuit(404, \"favicon.ico\");\nvar assignedStatic = app.MapGroup(\"/assigned\").MapGroup(\"static\");\nassignedStatic.MapShortCircuit(404, \"health.txt\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_threat_target(&degraded, "http-route"));
        assert!(document_threat_target_has_cwe(&degraded, "http-route", "CWE-20"));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /robots.txt"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /static/robots.txt"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /internal/static/favicon.ico"
        ));
        assert!(document_has_narrative_item(
            &degraded,
            "/data/document/narrative/inputCategories/attackerControlled",
            "ANY /assigned/static/health.txt"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_websocket_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "app.UseWebSockets();\nvar socket = await context.WebSockets.AcceptWebSocketAsync();\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_signalr_service_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddSignalR();\nclass AdminHub : Hub {}\nclass ChatHub : Hub<IChatClient> {}\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_grouped_signalr_hub_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapHub<AdminHub>(\"/hubs/admin\");\napp.MapGroup(\"/realtime\").MapHub<AdminHub>(\"admin\");\napp.MapGroup(\"/internal\").MapGroup(\"realtime\").MapHub<AuditHub>(\"audit\");\nvar assignedRealtime = app.MapGroup(\"/assigned\").MapGroup(\"realtime\");\nassignedRealtime.MapHub<ChatHub>(\"chat\");\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        for route in [
            "ANY /hubs/admin",
            "ANY /realtime/admin",
            "ANY /internal/realtime/audit",
            "ANY /assigned/realtime/chat",
        ] {
            assert!(
                document_has_narrative_item(
                    &degraded,
                    "/data/document/narrative/inputCategories/attackerControlled",
                    route
                ),
                "missing grouped SignalR hub route narrative item: {route}"
            );
        }
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_grpc_web_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddGrpc();\napp.UseGrpcWeb();\napp.MapGrpcService<GreeterService>().EnableGrpcWeb();\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_grouped_grpc_service_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddGrpc();\nvar app = WebApplication.CreateBuilder(args).Build();\napp.MapGrpcService<GreeterService>();\napp.MapGroup(\"/grpc\").MapGrpcService<GreeterService>();\napp.MapGroup(\"/internal\").MapGroup(\"grpc\").MapGrpcService<AdminService>();\nvar assignedGrpc = app.MapGroup(\"/assigned\").MapGroup(\"grpc\");\nassignedGrpc.MapGrpcService<AuditService>();\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "rpc-handler"));
        assert!(document_has_dfd_flow(&degraded, "flow-rpc-handler"));
        assert!(document_threat_target_has_cwe(&degraded, "rpc-handler", "CWE-20"));
        for route in [
            "ANY /grpc",
            "ANY /internal/grpc",
            "ANY /assigned/grpc",
        ] {
            assert!(
                document_has_narrative_item(
                    &degraded,
                    "/data/document/narrative/inputCategories/attackerControlled",
                    route
                ),
                "missing grouped gRPC service route narrative item: {route}"
            );
        }
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_upload_limit_file_upload_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("UploadController.cs"),
            r#"
              [RequestSizeLimit(10485760)]
              [RequestFormLimits(MultipartBodyLengthLimit = 10485760)]
              [DisableRequestSizeLimit]
              class UploadController {
                void Import(IFormFile file) {}
              }
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.Configure<FormOptions>(options => options.MultipartBodyLengthLimit = 10485760);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "file-upload-parser"));
        assert!(document_has_dfd_flow(&degraded, "flow-file-upload"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "file-upload-parser",
            "CWE-434"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_aspnet_request_decompression_parser_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              builder.Services.AddRequestDecompression();
              builder.Services.Configure<RequestDecompressionOptions>(options => {});
              options.DecompressionProviders.Add("br", new RequestDecompressionProvider());
              app.UseRequestDecompression();
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "parser-boundary"));
        assert!(document_has_dfd_flow(&degraded, "flow-parser-boundary"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "parser-boundary",
            "CWE-502"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn deterministic_threat_model_includes_dotnet_serializer_parser_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Parsers.cs"),
            r#"
              class Parsers {
                void Parse() {
                  var binary = new BinaryFormatter().Deserialize(stream);
                  var xml = new XmlSerializer(typeof(Payload)).Deserialize(reader);
                  var data = new DataContractSerializer(typeof(Payload)).ReadObject(stream);
                  var msg = MessagePackSerializer.Deserialize<Payload>(bytes);
                  var proto = ProtoBuf.Serializer.Deserialize<Payload>(stream);
                  var yaml = new Deserializer().Deserialize<Payload>(text);
                }
              }
            "#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let degraded = registry
            .execute_tool(
                "threat-model:build",
                json!({"preserveUserEdits": false}),
                &ctx,
            )
            .unwrap();

        assert!(document_has_dfd_node(&degraded, "parser-boundary"));
        assert!(document_has_dfd_flow(&degraded, "flow-parser-boundary"));
        assert!(document_has_threat_target(&degraded, "parser-boundary"));
        assert!(document_threat_target_has_cwe(
            &degraded,
            "parser-boundary",
            "CWE-502"
        ));
        assert!(document_has_evidence_anchor_description(
            &degraded,
            "ASP.NET Core/C#"
        ));
    }

    #[test]
    fn reads_randori_pasta_artifacts_and_applies_methodology_overlay() {
        let temp = tempfile::tempdir().unwrap();
        let output_dir = BuildFlavor::ThreatModel.default_output_dir(temp.path(), "run-1");
        let artifact_dir = temp.path().join(&output_dir);
        fs::create_dir_all(&artifact_dir).unwrap();
        fs::write(
            artifact_dir.join("pasta-s2.json"),
            r#"{
              "actors": [{"id":"actor-user","name":"User","type":"external-user","description":"External user"}],
              "services": [{"id":"web","name":"Web App","description":"HTTP service"}],
              "data_flows": [{"id":"flow-login","source":"actor-user","destination":"web","data":"credentials","crosses":["tb-edge"]}]
            }"#,
        )
        .unwrap();
        fs::write(
            artifact_dir.join("pasta-s3.json"),
            r#"{
              "trust_boundaries": [{"id":"tb-edge","name":"Internet edge","crossing_flow_ids":["flow-login"]}]
            }"#,
        )
        .unwrap();
        fs::write(
            artifact_dir.join("pasta-s4.json"),
            r#"{
              "threats": [{
                "id": "T-001",
                "title": "Spoof login",
                "stride_category": "spoofing",
                "target_assets": ["web"],
                "probability": 0.8,
                "impact": "high",
                "attack_scenario": "Attacker steals a token",
                "recommended_mitigations": ["Bind sessions"],
                "evidence_anchors": [{"file_path":"src/auth.ts","start_line":7,"description":"login handler"}]
              }]
            }"#,
        )
        .unwrap();

        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let result = registry
            .execute_tool(
                "threat-model:read",
                json!({
                    "outputDir": output_dir,
                    "methodology": "dread"
                }),
                &ctx,
            )
            .unwrap();

        assert_completed_result(&result, "Loaded DREAD threat model", []);
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/document/dfd/nodes")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            result
                .pointer("/data/document/dfd/flows")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            result
                .pointer("/data/document/threats/0/id")
                .and_then(Value::as_str),
            Some("T-001")
        );
        assert_eq!(
            result
                .pointer("/data/document/riskScores/methodology")
                .and_then(Value::as_str),
            Some("dread")
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("Loaded DREAD threat model")));
    }

    #[test]
    fn randori_threat_model_reads_same_artifact_adapter() {
        let temp = tempfile::tempdir().unwrap();
        let artifact_dir = temp.path().join("randori-output");
        fs::create_dir_all(&artifact_dir).unwrap();
        fs::write(
            artifact_dir.join("normalized-threat-model.json"),
            serde_json::to_string_pretty(&sample_document()).unwrap(),
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let result = registry
            .execute_tool(
                "randori:threat-model",
                json!({"outputDir": "randori-output"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/document/threats/0/title")
                .and_then(Value::as_str),
            Some("Session spoofing")
        );
    }

    #[test]
    fn threat_model_read_rejections_use_failed_envelopes() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };

        let missing_dir =
            read_threat_model(json!({}), &ctx, ReadFlavor::ThreatModel).unwrap();
        assert_failed_result(&missing_dir, "missing-output-dir");

        let missing_artifacts = registry
            .execute_tool(
                "threat-model:read",
                json!({"outputDir": ".kuzushi/missing-threat-model"}),
                &ctx,
            )
            .unwrap_err();
        assert!(
            format!("{missing_artifacts:#}").contains("could not be resolved inside workspace")
        );
    }

    #[test]
    fn threat_model_methodologies_is_static_and_headless() {
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        };
        let result = registry
            .execute_tool("threat-model:methodologies", json!({}), &ctx)
            .unwrap();
        assert_completed_result(&result, "Selectable threat model methodologies", []);
        assert_eq!(
            result
                .pointer("/data/methodologies")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(3)
        );
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("pasta")));
    }

    #[test]
    fn threat_model_dag_descriptors_remain_registered_for_scan_ordering() {
        let registry = ModuleRegistry::with_v2_builtins();
        let threat_model = registry
            .all_modules()
            .find(|module| module.metadata().id == "threat-model")
            .unwrap();
        assert!(threat_model.dag_nodes().iter().any(|node| {
            node.id == "threat-model:build"
                && node.output_kind == "threat-model"
                && node.depends_on == ["context:build"]
        }));

        let randori = registry
            .all_modules()
            .find(|module| module.metadata().id == "randori")
            .unwrap();
        assert!(randori
            .dag_nodes()
            .iter()
            .any(|node| node.id == "randori:threat-model" && node.output_kind == "threat-model"));
    }

    fn has_artifact_label(value: &Value, label: &str) -> bool {
        value
            .get("artifacts")
            .and_then(Value::as_array)
            .is_some_and(|artifacts| {
                artifacts
                    .iter()
                    .any(|artifact| artifact.get("label").and_then(Value::as_str) == Some(label))
            })
    }

    fn assert_completed_result<'a>(
        value: &Value,
        summary_prefix: &str,
        artifact_labels: impl IntoIterator<Item = &'a str>,
    ) {
        assert_eq!(value.get("status").and_then(Value::as_str), Some("completed"));
        assert!(value.get("errors").and_then(Value::as_array).is_some_and(Vec::is_empty));
        assert!(value
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|summary| summary.starts_with(summary_prefix)));
        for label in artifact_labels {
            assert!(has_artifact_label(value, label));
        }
    }

    fn assert_failed_result(value: &Value, reason: &str) {
        assert_eq!(value.get("ok").and_then(Value::as_bool), Some(false));
        assert_eq!(value.get("status").and_then(Value::as_str), Some("failed"));
        assert_eq!(
            value.pointer("/data/reason").and_then(Value::as_str),
            Some(reason)
        );
        assert!(value
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(|errors| !errors.is_empty()));
    }

    fn document_has_dfd_node(value: &Value, id: &str) -> bool {
        document_array(value, "/data/document/dfd/nodes")
            .iter()
            .any(|node| node.get("id").and_then(Value::as_str) == Some(id))
    }

    fn document_has_dfd_flow(value: &Value, id: &str) -> bool {
        document_array(value, "/data/document/dfd/flows")
            .iter()
            .any(|flow| flow.get("id").and_then(Value::as_str) == Some(id))
    }

    fn document_has_dfd_trust_boundary(value: &Value, id: &str) -> bool {
        document_array(value, "/data/document/dfd/trustBoundaries")
            .iter()
            .any(|boundary| boundary.get("id").and_then(Value::as_str) == Some(id))
    }

    fn document_has_related_cwe(value: &Value, cwe: &str) -> bool {
        document_array(value, "/data/document/threats")
            .iter()
            .any(|threat| json_array_contains_str(threat.get("relatedCwe"), cwe))
    }

    fn document_threat_target_has_cwe(value: &Value, target_id: &str, cwe: &str) -> bool {
        document_array(value, "/data/document/threats")
            .iter()
            .any(|threat| {
                json_array_contains_str(threat.get("targetElementIds"), target_id)
                    && json_array_contains_str(threat.get("relatedCwe"), cwe)
            })
    }

    fn document_has_threat_target(value: &Value, target_id: &str) -> bool {
        document_array(value, "/data/document/threats")
            .iter()
            .any(|threat| json_array_contains_str(threat.get("targetElementIds"), target_id))
    }

    fn document_has_attacker_story_threat_id(value: &Value, threat_id: &str) -> bool {
        document_array(value, "/data/document/narrative/attackerStories")
            .iter()
            .any(|story| json_array_contains_str(story.get("threatIds"), threat_id))
    }

    fn document_has_narrative_input(value: &Value, pointer: &str) -> bool {
        value
            .pointer(pointer)
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
    }

    fn document_has_narrative_item(value: &Value, pointer: &str, item: &str) -> bool {
        value
            .pointer(pointer)
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(|value| value.as_str() == Some(item)))
    }

    fn document_has_evidence_anchor_description(value: &Value, needle: &str) -> bool {
        document_array(value, "/data/document/threats")
            .iter()
            .flat_map(|threat| document_nested_array(threat, "evidenceAnchors"))
            .any(|anchor| {
                anchor
                    .get("description")
                    .and_then(Value::as_str)
                    .is_some_and(|description| description.contains(needle))
            })
    }

    fn document_nested_array(value: &Value, key: &str) -> Vec<Value> {
        value
            .get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    fn document_array(value: &Value, pointer: &str) -> Vec<Value> {
        value
            .pointer(pointer)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    fn json_array_contains_str(value: Option<&Value>, needle: &str) -> bool {
        value.and_then(Value::as_array).is_some_and(|items| {
            items
                .iter()
                .any(|item| item.as_str() == Some(needle))
        })
    }
}
