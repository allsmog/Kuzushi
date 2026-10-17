use crate::findings::FindingStore;
use crate::modules::full_mode_tool_input::full_mode_config_from_input;
use crate::modules::{phase_result_phase, ModuleMaturity, ModuleRegistry, PreparedToolInput};
use crate::{ToolExecutionContext, V2Config, WorkspaceTarget};
use anyhow::Result;
use serde_json::{json, Value};
mod standard_controls;

struct Fixture {
    _root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    store: FindingStore,
    config: V2Config,
    registry: ModuleRegistry,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("owned.c"),
            "// Owned inert metadata. Never executed.\n".repeat(800),
        )
        .unwrap();
        std::fs::write(
            root.path().join("other.c"),
            "// Other owned inert metadata. Never executed.\n".repeat(800),
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        Self {
            _root: root,
            workspace,
            store,
            config: V2Config::default(),
            registry: ModuleRegistry::with_v2_builtins(),
        }
    }

    fn context(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: Some(&self.store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    fn prepare(&self, tool: &str, mut input: Value) -> Result<PreparedToolInput> {
        if tool == "agentic-sast:scan" {
            input["strategy"] = json!("chunked");
        }
        self.registry
            .prepare_dispatch_input(tool, input, &self.context(), None)
    }
}

#[test]
fn retry_arrays_and_legacy_csv_reach_both_prepared_executors() {
    let fixture = Fixture::new();
    for tool in ["full-mode:hunt", "agentic-sast:scan"] {
        for value in [json!("0, 1, 1"), json!([1, "0", 1])] {
            let prepared = fixture
                .prepare(
                    tool,
                    json!({"failedChunkIds":value, "reuseCachedChunks":false}),
                )
                .unwrap();
            let cfg = full_mode_config_from_input(prepared.value(), &fixture.context()).unwrap();
            assert_eq!(cfg.failed_chunk_ids, Some(vec![0, 1]));
            assert!(!cfg.reuse_cached_chunks);
        }
    }
}

#[test]
fn empty_and_invalid_retry_selections_fail_instead_of_expanding_work() {
    let fixture = Fixture::new();
    for value in [
        json!([]),
        json!(""),
        json!([null]),
        json!([-1]),
        json!([4294967296_u64]),
    ] {
        let prepared = fixture
            .prepare("full-mode:hunt", json!({"failedChunkIds":value}))
            .unwrap();
        assert!(full_mode_config_from_input(prepared.value(), &fixture.context()).is_err());
    }
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[test]
fn compatibility_default_retains_cache_reuse_and_explicit_override_is_canonical() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare("full-mode:hunt", json!({})).unwrap();
    assert_eq!(prepared.value()["reuseCachedChunks"], true);
    let cfg = full_mode_config_from_input(prepared.value(), &fixture.context()).unwrap();
    assert!(cfg.reuse_cached_chunks);
    assert!(fixture
        .prepare("full-mode:hunt", json!({"ownedUnknownOption":true}))
        .is_err());
}

#[test]
fn chunked_refuses_scope_context_focus_and_multiple_passes_before_runtime_work() {
    let fixture = Fixture::new();
    for field in [
        "scanScopeRef",
        "scan_scope_ref",
        "scanContextRef",
        "scan_context_ref",
        "threatModelRef",
        "threatModelDigestRef",
    ] {
        let error = fixture
            .prepare("agentic-sast:scan", json!({field:{}}))
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("strategy=standard"),
            "{field}: {error:#}"
        );
    }
    for input in [
        json!({"passes":2}),
        json!({"passes":0}),
        json!({"focus":"owned review question"}),
    ] {
        assert!(fixture.prepare("agentic-sast:scan", input).is_err());
    }
    fixture
        .prepare(
            "agentic-sast:scan",
            json!({"scanScopeRef":null,"scanContextRef":null,"threatModelRef":null,"passes":1}),
        )
        .unwrap();
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[test]
fn standard_strategy_keeps_its_scope_contract_and_refuses_unused_cache_control() {
    let fixture = Fixture::new();
    let prepare = |input| {
        fixture.registry.prepare_dispatch_input(
            "agentic-sast:scan",
            input,
            &fixture.context(),
            None,
        )
    };
    assert!(prepare(json!({"reuseCachedChunks":false})).is_err());
    let prepared = prepare(json!({"scanScopeRef":{},"scanContextRef":{}})).unwrap();
    assert_eq!(prepared.value()["strategy"], "standard");
    assert_eq!(prepared.value()["scanScopeRef"], json!({}));
}

#[test]
fn standard_discovery_rejects_chunked_planning_scope_and_spending_controls() {
    let fixture = Fixture::new();
    for (field, value) in [
        ("language", json!("c")),
        ("maxTokensPerChunk", json!(1000)),
        ("depositUsdPerChunk", json!(0.01)),
        ("dryRun", json!(true)),
        ("scopeFile", json!("owned.c")),
        ("failedChunkIds", json!([0])),
        ("reuseCachedChunks", json!(false)),
        ("budgetUsd", json!(0.01)),
        ("autoTriage", json!(false)),
        ("autoTriageMaxSteps", json!(1)),
        ("autoTriageDepositUsd", json!(0.01)),
    ] {
        let error = fixture
            .registry
            .prepare_dispatch_input(
                "agentic-sast:scan",
                json!({field:value}),
                &fixture.context(),
                None,
            )
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(field), "{message}");
        assert!(message.contains("requires strategy=chunked"), "{message}");
        assert!(message.contains("No model request started"), "{message}");
    }
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[test]
fn direct_dispatch_cannot_treat_standard_dry_run_as_discovery() {
    let fixture = Fixture::new();
    let error = fixture
        .registry
        .execute_tool(
            "agentic-sast:scan",
            json!({"dryRun":true}),
            &fixture.context(),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("option dryRun requires strategy=chunked"));
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
    assert!(!fixture.workspace.root().join(".kuzushi/v3/runs").exists());
}

#[test]
fn stored_chunk_settings_require_explicit_strategy_or_removal() {
    use crate::options::{OptionScope, OptionTarget, ToolOptionStore};
    let fixture = Fixture::new();
    let mut options = ToolOptionStore::new();
    let target = OptionTarget::Tool("agentic-sast:scan".to_string());
    options.set_value(OptionScope::Global, target.clone(), "dryRun", json!(true));
    let prepare = |input, store: &ToolOptionStore| {
        fixture.registry.prepare_dispatch_input(
            "agentic-sast:scan",
            input,
            &fixture.context(),
            Some(store),
        )
    };
    assert!(prepare(json!({}), &options).is_err());
    let prepared = prepare(json!({"strategy":"chunked"}), &options).unwrap();
    assert_eq!(prepared.value()["strategy"], "chunked");
    assert_eq!(prepared.value()["dryRun"], true);
    assert!(options.unset_value(OptionScope::Global, &target, "dryRun"));
    let prepared = prepare(json!({}), &options).unwrap();
    assert_eq!(prepared.value()["strategy"], "standard");
    assert!(prepared.value().get("dryRun").is_none());
}

#[test]
fn selected_chunk_planning_reports_exact_selection_without_scanning_or_approval() {
    let fixture = Fixture::new();
    let result = fixture.registry.execute_tool("full-mode:hunt", json!({"dryRun":true,"maxTokensPerChunk":1000,"failedChunkIds":[1],"reuseCachedChunks":false}), &fixture.context()).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["selection"]["chunkIds"], json!([1]));
    assert_eq!(result["data"]["selection"]["chunks"], 1);
    assert!(result["data"]["plan"]["chunks"].as_array().unwrap().len() > 1);
    assert_eq!(result["data"]["chunksDispatched"], 0);
    assert_eq!(result["data"]["scanExecuted"], false);
    assert_eq!(result["data"]["strictDollarCeiling"], false);
    assert!(result["output"].as_str().unwrap().contains("Planning only"));
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[test]
fn unknown_chunk_ids_and_nonpositive_grouping_limits_are_refused() {
    let fixture = Fixture::new();
    let error = fixture
        .registry
        .execute_tool(
            "full-mode:hunt",
            json!({"dryRun":true,"failedChunkIds":[999]}),
            &fixture.context(),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("absent from this plan"));
    for tool in ["full-mode:hunt", "agentic-sast:scan"] {
        assert!(fixture
            .prepare(tool, json!({"maxTokensPerChunk":0}))
            .is_err());
    }
}

#[test]
fn hidden_compatibility_alias_does_not_claim_a_primary_scan_result() {
    let fixture = Fixture::new();
    let module = fixture
        .registry
        .all_modules()
        .find(|module| module.metadata().id == "full-mode")
        .unwrap();
    assert_eq!(module.maturity(), ModuleMaturity::Compatibility);
    assert_eq!(
        phase_result_phase(fixture.registry.resolve_tool("full-mode:hunt").unwrap()),
        None
    );
    assert!(fixture.registry.resolve_tool("agentic-sast:scan").is_some());
}

#[test]
fn explicit_empty_scope_and_missing_since_name_never_fall_back_to_whole_repository() {
    let fixture = Fixture::new();
    std::fs::write(fixture.workspace.root().join("empty-scope.txt"), "\n").unwrap();
    for scope in ["empty-scope.txt", "since.txt"] {
        let result = fixture.registry.execute_tool(
            "full-mode:hunt",
            json!({"dryRun":true,"scopeFile":scope}),
            &fixture.context(),
        );
        assert!(result.is_err(), "{scope} widened to whole repository");
    }
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}
