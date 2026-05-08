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
    }

    impl FakeRuntime {
        fn new() -> Self {
            Self {
                queries: Mutex::new(Vec::new()),
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
        };

        let output = execute_systems_hunt_tool(
            "systems-hunt:systems-context-gatherer",
            json!({}),
            &ctx,
            None,
        )
        .unwrap();
        assert_eq!(output["ok"], json!(true));
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
        };
        let runtime = FakeRuntime::new();

        let err = run_systems_hunt_report(&json!({}), &ctx, Some(&runtime))
            .unwrap_err()
            .to_string();

        assert!(err.contains("requires an explicit model"));
        assert!(err.contains("will not choose a fallback model"));
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
