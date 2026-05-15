#[cfg(test)]
mod tests {
    use super::super::*;
    use std::sync::Mutex;

    use crate::config::V2Config;
    use crate::findings::{TriageOutcome, TriageVerdict};
    use crate::modules::{ModuleRegistry, ToolExecutionContext};
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
    fn parse_narrative_normalizes_aliases_and_skips_empty_documents() {
        assert!(parse_narrative(&json!({})).is_none());

        let parsed = parse_narrative(&json!({
            "overview": "internet-facing upload flow",
            "inputCategories": {
                "attackerControlled": ["filename"],
                "operator_controlled": ["feature flag"]
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
        assert!(temp.path().join(".kuzushi/threat-model.json").exists());
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
        assert!(requests[1].prompt.contains("Raw invalid model response"));
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
        assert!(err.contains("Initial parse/validation failure"), "{err}");
        assert!(err.contains("Raw initial model response"), "{err}");
        assert!(err.contains("not json"), "{err}");
        assert!(err.contains("still not json"), "{err}");
        let requests = runtime.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests
            .iter()
            .all(|request| request.model == "openai:gpt-4.1"));
    }

    #[test]
    fn threat_model_build_degrades_without_runtime_and_requires_explicit_model_for_runtime() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/app.ts"),
            "import express from 'express';\nconst app = express();\napp.use('/admin', requireAuth);\napp.use(csurf());\nconst tenantId = req.user.tenantId;\napp.post('/login', (req, res) => { db.query(req.body.name); res.send('ok'); });\napp.post('/session', (req, res) => { req.session.user = req.body.user; res.cookie('sid', req.session.id); });\napp.post('/proxy', async (req, res) => { await fetch(req.body.url); res.send('ok'); });\n",
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
        assert!(document_has_related_cwe(&degraded, "CWE-918"));
        assert!(document_has_related_cwe(&degraded, "CWE-287"));
        assert!(document_has_related_cwe(&degraded, "CWE-384"));
        assert!(document_has_related_cwe(&degraded, "CWE-352"));
        assert!(document_has_related_cwe(&degraded, "CWE-639"));
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
        let err = registry
            .execute_tool_with_runtime("threat-model:build", json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn reads_randori_pasta_artifacts_and_applies_methodology_overlay() {
        let temp = tempfile::tempdir().unwrap();
        let artifact_dir = temp.path().join(".kuzushi/runs/run-1/threat-model-output");
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
        };

        let result = registry
            .execute_tool(
                "threat-model:read",
                json!({
                    "outputDir": ".kuzushi/runs/run-1/threat-model-output",
                    "methodology": "dread"
                }),
                &ctx,
            )
            .unwrap();

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
    fn threat_model_methodologies_is_static_and_headless() {
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
        };
        let result = registry
            .execute_tool("threat-model:methodologies", json!({}), &ctx)
            .unwrap();
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
