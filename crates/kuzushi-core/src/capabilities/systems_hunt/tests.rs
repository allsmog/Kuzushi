#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::config::V2Config;
    use crate::findings::FindingStore;
    use crate::runtime::{AgentQueryResponse, TriageRequest};
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct FakeRuntime {
        queries: Mutex<Vec<AgentQueryRequest>>,
        report_systems_cost: bool,
    }

    impl FakeRuntime {
        fn new() -> Self {
            Self {
                queries: Mutex::new(Vec::new()),
                report_systems_cost: true,
            }
        }

        fn unpriced() -> Self {
            Self {
                queries: Mutex::new(Vec::new()),
                report_systems_cost: false,
            }
        }
    }

    impl AgentRuntime for FakeRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            let system_prompt = request.system_prompt.clone();
            self.queries.lock().unwrap().push(request);
            if system_prompt == SYSTEMS_INVARIANT_SYSTEM_PROMPT {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "invariants": [{
                            "id": "inv-1",
                            "surfaceId": "surface",
                            "kind": "length-buffer-coupling",
                            "summary": "length must fit the stack buffer",
                            "statement": "packet length is checked before copy",
                            "rationale": "copy uses attacker length",
                            "evidence": ["memcpy"],
                            "attackerControlledFields": ["len"],
                            "cheapVerifiable": true
                        }]
                    })),
                    cost_usd: if self.report_systems_cost { 0.01 } else { 0.0 },
                    ..Default::default()
                });
            }
            if system_prompt == SYSTEMS_TRIGGER_SYSTEM_PROMPT {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "triggers": [{
                            "id": "trig-1",
                            "surfaceId": "surface",
                            "orderedSteps": ["send oversized packet"],
                            "boundaryAssignments": {"len": "4096"},
                            "statePreconditions": ["connected"],
                            "attackerControlledFields": ["len"],
                            "expectedPrimitive": "stack overwrite",
                            "cheapVerifiable": true,
                            "rationale": "length reaches memcpy"
                        }]
                    })),
                    cost_usd: if self.report_systems_cost { 0.02 } else { 0.0 },
                    ..Default::default()
                });
            }
            if system_prompt == SYSTEMS_HUNT_SYSTEM_PROMPT {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "findings": [{
                            "title": "Oversized packet length reaches fixed buffer",
                            "cwe": "CWE-787",
                            "severity": "ERROR",
                            "filePath": "src/parser.c",
                            "startLine": 3,
                            "message": "packet len is copied into a 64-byte stack buffer",
                            "reasoning": "len comes from packet header",
                            "triggerHypothesisIds": ["trig-1"],
                            "violatedInvariantIds": ["inv-1"],
                            "triggerSequence": ["send len=4096"],
                            "attackerControlledFields": ["len"],
                            "memoryPrimitive": "stack overwrite",
                            "cheapVerifiable": true
                        }]
                    })),
                    cost_usd: 0.03,
                    ..Default::default()
                });
            }
            if system_prompt == DEEP_SEMANTIC_CWE_SYSTEM_PROMPT {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "cwes": [{
                            "id": "CWE-787",
                            "name": "Out-of-bounds Write",
                            "reason": "native memcpy appears in parser code"
                        }]
                    })),
                    ..Default::default()
                });
            }
            if system_prompt == DEEP_SEMANTIC_HUNT_SYSTEM_PROMPT {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "findings": [{
                            "title": "Packet length reaches fixed buffer",
                            "cwe": "CWE-787",
                            "severity": "high",
                            "filePath": "src/parser.c",
                            "startLine": 3,
                            "message": "memcpy uses packet-controlled length for a 64-byte stack buffer",
                            "reasoningChain": "packet length is attacker-controlled and no bound check is visible",
                            "analysisPath": ["inspect parser", "compare len with buffer size"]
                        }]
                    })),
                    ..Default::default()
                });
            }
            anyhow::bail!("unexpected prompt {system_prompt}")
        }

        fn triage_finding_blocking(
            &self,
            _request: TriageRequest,
        ) -> Result<crate::findings::TriageOutcome> {
            unreachable!("systems-hunt tests do not triage")
        }
    }

    #[test]
    fn systems_hunt_unknown_severity_stays_unknown() {
        assert_eq!(
            parse_severity("unsupported scanner label".to_string()),
            crate::findings::Severity::Unknown
        );
        assert_eq!(
            parse_severity("ERROR".to_string()),
            crate::findings::Severity::High
        );
    }

    #[test]
    fn gathers_ranked_systems_surfaces() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/parser.c"),
            "void parse(char *packet, uint16_t len) {\n  char buf[64];\n  memcpy(buf, packet, len);\n}\n",
        )
        .unwrap();

        let output = gather_systems_context(
            temp.path(),
            &SystemsHuntInput::from_tool_input(&json!({})).unwrap(),
        )
        .unwrap();

        assert_eq!(output.surfaces.len(), 1);
        assert_eq!(output.surfaces[0].file_path, "src/parser.c");
        assert!(output.surfaces[0]
            .domains
            .iter()
            .any(|domain| domain == "unsafe-memory"));
    }

    #[test]
    fn systems_context_skips_non_production_dirs_by_default() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("examples")).unwrap();
        fs::create_dir_all(temp.path().join("lib")).unwrap();
        fs::write(
            temp.path().join("examples/parser.c"),
            "void ex(char *packet, unsigned len) { char buf[8]; memcpy(buf, packet, len); }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("lib/parser.c"),
            "void prod(char *packet, unsigned len) { char buf[8]; memcpy(buf, packet, len); }\n",
        )
        .unwrap();

        let output = gather_systems_context(
            temp.path(),
            &SystemsHuntInput::from_tool_input(&json!({"maxSurfaces": 10})).unwrap(),
        )
        .unwrap();

        assert_eq!(output.surfaces.len(), 1);
        assert_eq!(output.surfaces[0].file_path, "lib/parser.c");
    }

    #[test]
    fn systems_context_can_include_non_production_dirs() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("examples")).unwrap();
        fs::write(
            temp.path().join("examples/parser.c"),
            "void ex(char *packet, unsigned len) { char buf[8]; memcpy(buf, packet, len); }\n",
        )
        .unwrap();

        let output = gather_systems_context(
            temp.path(),
            &SystemsHuntInput::from_tool_input(&json!({
                "includeNonProduction": true,
                "maxSurfaces": 10
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(output.surfaces.len(), 1);
        assert_eq!(output.surfaces[0].file_path, "examples/parser.c");
    }

    #[test]
    fn inventory_skips_test_sources_for_production_hunts() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/testing")).unwrap();
        fs::write(
            temp.path().join("src/parser.cc"),
            "void Parse(char *packet, size_t len) { memcpy(packet, packet, len); }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/parser_unittest.cc"),
            "void Test() { char frame[64]; memcpy(frame, frame, sizeof(frame)); }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/parser_unittest_2_autogen.h"),
            "void TestAutogen() { char frame[64]; memcpy(frame, frame, sizeof(frame)); }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/parser_test_util_common.h"),
            "void TestUtil() { char frame[64]; memcpy(frame, frame, sizeof(frame)); }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/parser_tests.cc"),
            "void Tests() { char frame[64]; memcpy(frame, frame, sizeof(frame)); }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/test_shared_image_interface.cc"),
            "void TestShared() { char frame[64]; memcpy(frame, frame, sizeof(frame)); }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/testing/helper.cc"),
            "void Helper() { char frame[64]; memcpy(frame, frame, sizeof(frame)); }\n",
        )
        .unwrap();

        let output = gather_systems_context(
            temp.path(),
            &SystemsHuntInput::from_tool_input(&json!({"maxSurfaces": 10})).unwrap(),
        )
        .unwrap();
        let files = output
            .surfaces
            .iter()
            .map(|surface| surface.file_path.as_str())
            .collect::<Vec<_>>();

        assert_eq!(files, vec!["src/parser.cc"]);
    }

    #[test]
    fn prompt_context_keeps_high_surface_runs_compact() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        for index in 0..80 {
            fs::write(
                temp.path().join(format!("src/parser_{index}.cc")),
                "void Parse(char *packet, size_t len) {\n  char frame[64];\n  memcpy(frame, packet, len);\n  CHECK(len < sizeof(frame));\n}\n",
            )
            .unwrap();
        }

        let output = gather_systems_context(
            temp.path(),
            &SystemsHuntInput::from_tool_input(&json!({
                "maxSurfaces": 80,
                "maxFiles": 200,
                "headBytes": 4096,
            }))
            .unwrap(),
        )
        .unwrap();
        let prompt_context = format_context_for_prompt(&output).unwrap();

        assert_eq!(output.surfaces.len(), 80);
        assert!(prompt_context.len() < 200_000);
        assert!(!prompt_context.contains("\n  \"surfaces\""));
    }

    #[test]
    fn runs_systems_hunt_through_runtime_and_writes_artifact() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/parser.c"),
            "void parse(char *packet, uint16_t len) {\n  char buf[64];\n  memcpy(buf, packet, len);\n}\n",
        )
        .unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let runtime = FakeRuntime::new();

        let report =
            run_systems_hunt_report(&json!({"maxFindings": 5}), &ctx, Some(&runtime)).unwrap();

        assert_eq!(report.count, 1);
        assert_eq!(report.findings[0].tool, "systems-hunt");
        assert_eq!(report.findings[0].rule_id, "systems-hunt/cwe-787");
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
        assert_eq!(report.artifacts.len(), 1);
        assert!(temp.path().join(&report.artifacts[0]).exists());
        assert!((report.cost_usd - 0.06).abs() < 1e-9);
    }

    #[test]
    fn execute_systems_hunt_tool_routes_context_and_unknown_names() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/parser.c"),
            "void parse(char *packet, unsigned len) { memcpy(packet, packet, len); }\n",
        )
        .unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let output = execute_systems_hunt_tool(
            "systems-hunt:systems-context-gatherer",
            json!({}),
            &ctx,
            None,
        )
        .unwrap();
        assert_eq!(output["ok"], json!(true));
        assert_eq!(output["status"], json!("completed"));
        assert!(output["summary"]
            .as_str()
            .is_some_and(|summary| summary.contains("systems-hunt context")));
        assert!(output["output"].as_str().unwrap().contains("context"));
        assert!(execute_systems_hunt_tool("systems-hunt:nope", json!({}), &ctx, None).is_err());
    }

    #[test]
    fn systems_invariant_extract_returns_empty_without_runtime_for_empty_context() {
        let temp = tempdir().unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let output =
            run_systems_invariant_extract(&json!({"context": empty_context()}), &ctx, None)
                .unwrap();

        assert!(output.invariants.is_empty());
        let err = match required_systems_runtime(None, "systems-hunt:test") {
            Ok(_) => panic!("runtime should be required"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("systems-hunt:test requires"));
    }

    #[test]
    fn runs_systems_trigger_synth_from_supplied_context_and_invariants() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/parser.c"),
            "void parse(char *packet, uint16_t len) {\n  char buf[64];\n  memcpy(buf, packet, len);\n}\n",
        )
        .unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let runtime = FakeRuntime::new();
        let context = gather_systems_context(
            temp.path(),
            &SystemsHuntInput::from_tool_input(&json!({})).unwrap(),
        )
        .unwrap();

        let output = run_systems_trigger_synth(
            &json!({
                "context": context,
                "invariants": [{
                    "id": "inv-1",
                    "surfaceId": "surface",
                    "kind": "length-buffer-coupling",
                    "summary": "length must fit buffer",
                    "statement": "len is checked",
                    "rationale": "memcpy uses len",
                    "evidence": ["memcpy"],
                    "attackerControlledFields": ["len"],
                    "cheapVerifiable": true
                }]
            }),
            &ctx,
            Some(&runtime),
        )
        .unwrap();

        assert_eq!(output.triggers.len(), 1);
        assert_eq!(output.triggers[0].id, "trig-1");
    }

    #[test]
    fn standalone_trigger_synth_reports_exact_provider_cost() {
        let temp = tempdir().unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let output =
            execute_trigger_synth(&trigger_synth_input(), &ctx, Some(&FakeRuntime::new())).unwrap();

        assert_eq!(output["costUsd"], json!(0.02));
        assert_eq!(output["data"]["costUsd"], json!(0.02));
    }

    #[test]
    fn standalone_trigger_synth_preserves_unpriced_provider_state() {
        let temp = tempdir().unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let output =
            execute_trigger_synth(&trigger_synth_input(), &ctx, Some(&FakeRuntime::unpriced()))
                .unwrap();

        assert!(output.get("costUsd").is_none());
        assert_eq!(output["observedCostUsd"], json!(0.0));
        assert_eq!(output["providerSpendUnresolved"], json!(true));
        assert_eq!(output["data"]["observedCostUsd"], json!(0.0));
    }

    #[test]
    fn systems_hunt_report_uses_one_canonical_incomplete_cost_claim() {
        let report = SystemsHuntReport {
            target: "/repo".to_string(),
            count: 0,
            findings: Vec::new(),
            persisted: None,
            artifacts: Vec::new(),
            cost_usd: 0.125,
            cost_usd_exact: false,
        };

        let output = report.to_tool_json();

        for value in [&output, &output["data"]] {
            assert!(value.get("costUsd").is_none());
            assert_eq!(value["observedCostUsd"], json!(0.125));
            assert_eq!(value["providerSpendUnresolved"], json!(true));
        }
        let cost = crate::run_artifacts::tool_run_output_cost_report(&output).unwrap();
        assert_eq!(cost.observed_usd(), 0.125);
        assert!(!cost.is_complete());
        assert!(!cost.is_unavailable());
    }

    #[test]
    fn standalone_invariant_extract_reports_exact_provider_cost() {
        let temp = tempdir().unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let input = json!({"context": ctx_with(vec![surface("src/parser.c", "unsafe-region")])});

        let output = execute_systems_hunt_tool(
            "systems-hunt:systems-invariant-extract",
            input,
            &ctx,
            Some(&FakeRuntime::new()),
        )
        .unwrap();

        assert_eq!(output["costUsd"], json!(0.01));
        assert_eq!(output["data"]["costUsd"], json!(0.01));
    }

    fn trigger_synth_input() -> Value {
        json!({
            "context": ctx_with(vec![surface("src/parser.c", "unsafe-region")]),
            "invariants": [{
                "id": "inv-1",
                "surfaceId": "surface",
                "kind": "length-buffer-coupling",
                "summary": "length must fit buffer",
                "statement": "len is checked",
                "rationale": "memcpy uses len",
                "evidence": ["memcpy"],
                "attackerControlledFields": ["len"],
                "cheapVerifiable": true
            }]
        })
    }

    #[test]
    fn runs_deep_semantic_cwe_select_through_runtime() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/parser.c"),
            "void parse(char *packet, uint16_t len) { memcpy(packet, packet, len); }\n",
        )
        .unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let runtime = FakeRuntime::new();

        let output = run_deep_semantic_cwe_select(&json!({}), &ctx, Some(&runtime)).unwrap();

        assert_eq!(output.cwes.len(), 1);
        assert_eq!(output.cwes[0].id, "CWE-787");
    }

    #[test]
    fn runs_deep_semantic_hunt_through_runtime_and_persists() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/parser.c"),
            "void parse(char *packet, uint16_t len) {\n  char buf[64];\n  memcpy(buf, packet, len);\n}\n",
        )
        .unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let runtime = FakeRuntime::new();

        let report = run_deep_semantic_hunt_report(
            &json!({
                "maxFindings": 1,
                "cwes": [{
                    "id": "CWE-787",
                    "name": "Out-of-bounds Write",
                    "reason": "operator selected"
                }]
            }),
            &ctx,
            Some(&runtime),
        )
        .unwrap();

        assert_eq!(report.count, 1);
        assert_eq!(report.findings[0].tool, "deep-semantic-hunt");
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
        assert_eq!(report.artifacts.len(), 1);
    }

    #[test]
    fn systems_hunt_requires_explicit_model_without_fallback() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/parser.c"),
            "void parse(char *packet, uint16_t len) { memcpy(packet, packet, len); }\n",
        )
        .unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let runtime = FakeRuntime::new();

        let err = run_systems_hunt_report(&json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();

        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
    }

    #[test]
    fn first_line_field_accepts_scalar_array_string_and_range_shapes() {
        let parse = |value: Value| {
            let object = value.as_object().unwrap().clone();
            first_line_field(&object, &["startLine", "lines", "lineRange", "line"])
        };

        assert_eq!(parse(json!({"startLine": 123})), 123);
        assert_eq!(parse(json!({"lines": [456, 458]})), 456);
        assert_eq!(parse(json!({"lineRange": "125-138"})), 125);
        assert_eq!(parse(json!({"lineRange": "200:215"})), 200);
        assert_eq!(parse(json!({"lineRange": "300\u{2013}310"})), 300);
        assert_eq!(parse(json!({"line": "  789  "})), 789);
        assert_eq!(parse(json!({"startLine": 0, "lines": [42]})), 42);
        assert_eq!(parse(json!({"lineRange": "unknown"})), 1);
    }

    #[test]
    fn normalize_systems_hunt_findings_preserves_rich_model_fields() {
        let temp = tempdir().unwrap();
        let artifact_root = temp.path().join(".kuzushi/systems-hunt");
        let context = ctx_with(vec![surface("src/parser.c", "unsafe-region")]);
        let raw = json!({
            "findings": [{
                "name": "OAuth packet length reaches MariaDB buffer",
                "cwes": ["CWE-787", "CWE-190"],
                "severity": "high",
                "path": "src/parser.c",
                "lineRange": "125-138",
                "root_cause": "The OAuth packet length is trusted when copying into the MariaDB handshake buffer.",
                "functionName": "parse_oauth_packet",
                "domains": "oauth",
                "evidence": [{"text": "len comes from packet header"}, "memcpy uses len"],
                "impact": "remote memory corruption before authentication",
                "recommendations": [{"description": "bound len to the destination buffer"}],
                "attackerInputs": "packet length",
                "reasoning": "the same unchecked length controls allocation and copy"
            }]
        });

        let (findings, artifacts) =
            normalize_systems_hunt_findings(raw, temp.path(), &context, &artifact_root, 5).unwrap();

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.rule_id, "systems-hunt/cwe-787");
        assert_eq!(finding.file_path, "src/parser.c");
        assert_eq!(finding.start_line, 125);
        assert!(finding.message.contains("Function: parse_oauth_packet"));
        assert!(finding
            .message
            .contains("Evidence:\n  - len comes from packet header"));
        assert!(finding
            .message
            .contains("Recommendation:\n  - bound len to the destination buffer"));
        assert_eq!(artifacts.len(), 1);

        let artifact: Value =
            serde_json::from_str(&fs::read_to_string(temp.path().join(&artifacts[0])).unwrap())
                .unwrap();
        assert_eq!(
            artifact["description"],
            "The OAuth packet length is trusted when copying into the MariaDB handshake buffer."
        );
        assert_eq!(artifact["function"], "parse_oauth_packet");
        assert_eq!(artifact["domain"], json!(["oauth"]));
        assert_eq!(
            artifact["attackerControlledFields"],
            json!(["packet length"])
        );
        assert_eq!(
            artifact["recommendation"],
            json!(["bound len to the destination buffer"])
        );
    }

    #[test]
    fn normalize_systems_hunt_findings_rejects_under_evidenced_candidates() {
        let temp = tempdir().unwrap();
        let artifact_root = temp.path().join(".kuzushi/systems-hunt");
        let context = ctx_with(vec![surface("src/http.c", "unsafe-region")]);
        let raw = json!({
            "findings": [{
                "title": "NUL byte header candidate",
                "cwe": "CWE-170",
                "severity": "high",
                "filePath": "src/http.c",
                "startLine": 42,
                "message": "model suspects a string truncation issue",
                "evidence": [],
                "violatedInvariantIds": [],
                "triggerHypothesisIds": [],
                "triggerSequence": [],
                "cheapVerifiable": false
            }]
        });

        let (findings, artifacts) =
            normalize_systems_hunt_findings(raw, temp.path(), &context, &artifact_root, 5).unwrap();

        assert!(findings.is_empty());
        assert_eq!(artifacts.len(), 1);
        let artifact: Value =
            serde_json::from_str(&fs::read_to_string(temp.path().join(&artifacts[0])).unwrap())
                .unwrap();
        assert_eq!(artifact["rejected"], json!(true));
        assert!(artifact["rejectionReason"]
            .as_str()
            .unwrap()
            .contains("under-evidenced"));
    }

    #[cfg(unix)]
    #[test]
    fn systems_hunt_artifacts_do_not_follow_workspace_symlink() {
        use std::os::unix::fs::symlink;

        let workspace = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::create_dir(workspace.path().join(".kuzushi")).unwrap();
        symlink(
            outside.path(),
            workspace.path().join(".kuzushi/systems-hunt"),
        )
        .unwrap();
        let raw = json!({
            "findings": [{
                "title": "Rejected candidate",
                "filePath": "src/main.c",
                "message": "unverified candidate"
            }]
        });

        assert!(normalize_systems_hunt_findings(
            raw,
            workspace.path(),
            &ctx_with(Vec::new()),
            &workspace.path().join(".kuzushi/systems-hunt"),
            5,
        )
        .is_err());
        assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn systems_context_rejects_symlinked_codeql_database() {
        use std::os::unix::fs::symlink;

        let workspace = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::create_dir(workspace.path().join(".kuzushi")).unwrap();
        symlink(outside.path(), workspace.path().join(".kuzushi/codeql-db")).unwrap();

        let error = resolve_codeql_db_path(workspace.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("symbolic link"), "{error}");
    }

    #[test]
    fn systems_context_rejects_malformed_codeql_provenance() {
        let workspace = tempdir().unwrap();
        let database = crate::workspace::workspace_codeql_db_path(workspace.path());
        fs::create_dir_all(database.join("db-cpp")).unwrap();
        fs::write(
            database.join("codeql-database.yml"),
            "primaryLanguage: cpp\n",
        )
        .unwrap();
        fs::write(database.join(".kuzushi-provenance.json"), "{not-json\n").unwrap();

        let error = gather_systems_context(
            workspace.path(),
            &SystemsHuntInput::from_tool_input(&json!({})).unwrap(),
        )
        .unwrap_err();
        let error = format!("{error:#}");

        assert!(error.contains("invalid CodeQL provenance"), "{error}");
        assert!(error.contains("run `codeql:create-db` again"), "{error}");
    }

    #[test]
    fn systems_context_treats_only_missing_codeql_database_as_absent() {
        let workspace = tempdir().unwrap();

        assert_eq!(resolve_codeql_db_path(workspace.path()).unwrap(), None);
    }

    // ----- pick_role_for_invariants --------------------------------

    fn surface(file: &str, kind: &str) -> RankedSystemsSurface {
        RankedSystemsSurface {
            id: "test".to_string(),
            file_path: file.to_string(),
            start_line: 1,
            display_name: "test".to_string(),
            kind: kind.to_string(),
            score: 0,
            domains: Vec::new(),
            reasons: Vec::new(),
            attacker_controlled_fields: Vec::new(),
            hardening_signals: Vec::new(),
            evidence: Vec::new(),
        }
    }

    fn ctx_with(surfaces: Vec<RankedSystemsSurface>) -> SystemsContextOutput {
        SystemsContextOutput {
            surfaces,
            surface_packs: Vec::new(),
            metadata: SystemsContextMetadata {
                codeql_available: false,
                codeql_db_path: None,
                bash_probing_used: false,
            },
        }
    }

    #[test]
    fn role_unsafe_block_for_rust_unsafe_region() {
        let ctx = ctx_with(vec![surface("crates/foo/src/lib.rs", "unsafe-region")]);
        assert_eq!(
            pick_role_for_invariants(&ctx),
            SubagentRole::UnsafeBlockReasoner
        );
    }

    #[test]
    fn role_ffi_for_ffi_boundary_kind() {
        let ctx = ctx_with(vec![surface("src/foo.c", "ffi-boundary")]);
        assert_eq!(
            pick_role_for_invariants(&ctx),
            SubagentRole::FfiBoundaryReasoner
        );
    }

    #[test]
    fn role_ffi_for_ffi_domain_label() {
        let mut s = surface("src/foo.c", "other-kind");
        s.domains.push("ffi".to_string());
        let ctx = ctx_with(vec![s]);
        assert_eq!(
            pick_role_for_invariants(&ctx),
            SubagentRole::FfiBoundaryReasoner
        );
    }

    #[test]
    fn role_lifetime_for_rust_resource_provenance() {
        let ctx = ctx_with(vec![surface(
            "crates/foo/src/lib.rs",
            "resource-provenance",
        )]);
        assert_eq!(
            pick_role_for_invariants(&ctx),
            SubagentRole::LifetimeAliasingReasoner
        );
    }

    #[test]
    fn role_generic_for_c_unsafe_region() {
        // C "unsafe" regions don't get the Rust UnsafeBlockReasoner —
        // they're a generic surface from the role-routing perspective.
        let ctx = ctx_with(vec![surface("src/parser.c", "unsafe-region")]);
        assert_eq!(pick_role_for_invariants(&ctx), SubagentRole::Generic);
    }

    #[test]
    fn role_generic_for_empty_context() {
        let ctx = ctx_with(Vec::new());
        assert_eq!(pick_role_for_invariants(&ctx), SubagentRole::Generic);
    }

    #[test]
    fn role_unsafe_takes_priority_over_ffi() {
        // When both kinds appear, Rust unsafe-region wins because it's
        // checked first in the cascade.
        let mut ffi = surface("src/foo.c", "ffi-boundary");
        ffi.domains.push("ffi".to_string());
        let ctx = ctx_with(vec![surface("crates/x/src/lib.rs", "unsafe-region"), ffi]);
        assert_eq!(
            pick_role_for_invariants(&ctx),
            SubagentRole::UnsafeBlockReasoner
        );
    }

    // ----- try_augment_with_index ----------------------------------

    #[tokio::test]
    async fn augment_with_index_returns_input_unchanged_when_no_backend_live() {
        // Sandbox has no joern; the augmenter must short-circuit.
        let surfaces = vec![surface("crates/foo/src/lib.rs", "unsafe-region")];
        let augmented = try_augment_with_index(surfaces.clone()).await;
        assert_eq!(augmented.len(), 1);
        assert_eq!(augmented[0].file_path, surfaces[0].file_path);
        // No new "codeindex:" reason should have been added.
        assert!(!augmented[0]
            .reasons
            .iter()
            .any(|r| r.starts_with("codeindex:")));
    }

    #[tokio::test]
    async fn augment_with_index_handles_empty_surface_list() {
        let augmented = try_augment_with_index(Vec::new()).await;
        assert!(augmented.is_empty());
    }

    // ----- walker scaling defaults --------------------------------

    #[test]
    fn input_default_max_files_scaled_to_5000() {
        let parsed = SystemsHuntInput::from_tool_input(&serde_json::json!({})).unwrap();
        assert_eq!(parsed.max_files, 5000);
    }

    #[test]
    fn input_default_head_bytes_scaled_to_16k() {
        let parsed = SystemsHuntInput::from_tool_input(&serde_json::json!({})).unwrap();
        assert_eq!(parsed.head_bytes, 16384);
    }

    #[test]
    fn input_default_max_surfaces_widened_to_50() {
        let parsed = SystemsHuntInput::from_tool_input(&serde_json::json!({})).unwrap();
        assert_eq!(parsed.max_surfaces, 50);
    }

    #[test]
    fn input_walker_caps_are_overridable() {
        let parsed = SystemsHuntInput::from_tool_input(&serde_json::json!({
            "maxFiles": 100,
            "headBytes": 2048,
            "maxSurfaces": 5,
        }))
        .unwrap();
        assert_eq!(parsed.max_files, 100);
        assert_eq!(parsed.head_bytes, 2048);
        assert_eq!(parsed.max_surfaces, 5);
    }

    #[test]
    fn input_walker_caps_reject_zero() {
        // positive_usize rejects 0 — these caps must never be 0.
        let err = SystemsHuntInput::from_tool_input(&serde_json::json!({
            "maxFiles": 0,
        }));
        assert!(err.is_err());
        let err = SystemsHuntInput::from_tool_input(&serde_json::json!({
            "headBytes": 0,
        }));
        assert!(err.is_err());
    }

    #[test]
    fn input_preserves_each_declared_system_prompt_role() {
        let parsed = SystemsHuntInput::from_tool_input(&serde_json::json!({
            "SYSTEMS_INVARIANT_PROMPT": "custom invariant",
            "SYSTEMS_TRIGGER_PROMPT": "custom trigger",
            "SYSTEMS_HUNT_PROMPT": "custom hunt",
            "SYSTEMS_DEEP_CWE_PROMPT": "custom deep cwe",
            "SYSTEMS_DEEP_HUNT_PROMPT": "custom deep hunt",
        }))
        .unwrap();

        assert_eq!(parsed.invariant_system_prompt, "custom invariant");
        assert_eq!(parsed.trigger_system_prompt, "custom trigger");
        assert_eq!(parsed.hunt_system_prompt, "custom hunt");
        assert_eq!(parsed.deep_semantic_cwe_system_prompt, "custom deep cwe");
        assert_eq!(parsed.deep_semantic_hunt_system_prompt, "custom deep hunt");
    }

    // ----- score_with_index degradation contract --------------------

    #[tokio::test]
    async fn score_with_index_returns_unchanged_without_backend() {
        let surfaces = vec![
            surface("src/x.c", "unsafe-region"),
            surface("src/y.rs", "unsafe-region"),
        ];
        let scored = score_with_index(surfaces.clone()).await;
        assert_eq!(scored.len(), surfaces.len());
        for (left, right) in scored.iter().zip(surfaces.iter()) {
            assert_eq!(left.score, right.score);
            // No "codeindex:" reasons added when no backend live.
            assert!(left.reasons.iter().all(|r| !r.starts_with("codeindex:")));
        }
    }
}
