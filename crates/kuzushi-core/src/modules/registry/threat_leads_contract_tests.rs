use super::*;

struct Fixture {
    root: tempfile::TempDir,
    workspace: crate::WorkspaceTarget,
    registry: ModuleRegistry,
    config: crate::V2Config,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
        std::fs::write(
            root.path().join("owned.rs"),
            "// Owned parser response size limits. Never executed.\n",
        )
        .unwrap();
        workspace.ensure_state_dir().unwrap();
        std::fs::write(
            crate::capabilities::persistent_threat_model_path(root.path()),
            json!({"threats":[{"id":"T1","title":"Owned parser resource limits"}],"dfd":{}})
                .to_string(),
        )
        .unwrap();
        Self {
            root,
            workspace,
            registry: ModuleRegistry::with_v2_builtins_without_optional_adapters(),
            config: Default::default(),
        }
    }
    fn dispatch(
        &self,
        tool: &str,
        cancellation: Option<&crate::scan::ScanCancellation>,
    ) -> Result<Value> {
        self.dispatch_input(tool, json!({}), cancellation)
    }
    fn dispatch_input(
        &self,
        tool: &str,
        input: Value,
        cancellation: Option<&crate::scan::ScanCancellation>,
    ) -> Result<Value> {
        let ctx = ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace: None,
            cancellation,
            authorization: Default::default(),
        };
        let prepared = self
            .registry
            .prepare_dispatch_input(tool, input, &ctx, None)?
            .authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
    }
    fn artifact(&self) -> std::path::PathBuf {
        crate::workspace::workspace_state_root(self.root.path()).join("threat-leads.json")
    }
}

#[test]
fn threat_lead_actions_are_auxiliary_labs_and_runtime_free() {
    let f = Fixture::new();
    let module = f
        .registry
        .all_modules()
        .find(|m| m.metadata().id == "threat-leads")
        .unwrap();
    assert!(module.is_hidden());
    assert_eq!(module.maturity(), ModuleMaturity::Labs);
    for name in ["threat-leads:build", "threat-leads:read"] {
        let tool = f.registry.resolve_tool(name).unwrap();
        assert!(!tool.phase_result);
        assert_eq!(tool.runtime_requirement, RuntimeRequirement::Never);
        assert!(!f.registry.tool_is_discoverable(name));
    }
}

#[test]
fn built_lead_artifacts_reach_the_reader_without_mutating_context_or_source() {
    let f = Fixture::new();
    let source = std::fs::read(f.root.path().join("owned.rs")).unwrap();
    let model_path = crate::capabilities::persistent_threat_model_path(f.root.path());
    let model = std::fs::read(&model_path).unwrap();
    let built = f.dispatch("threat-leads:build", None).unwrap();
    assert_eq!(built["data"]["leadCount"], 1);
    assert_eq!(built["data"]["sources"]["xRay"], json!([]));
    assert_eq!(
        built["data"]["sources"]["threatModelSha256"],
        crate::run_lifecycle::sha256_content_digest(&model)
    );
    let saved: Value = serde_json::from_slice(&std::fs::read(f.artifact()).unwrap()).unwrap();
    assert_eq!(saved, built["data"]);
    let read = f.dispatch("threat-leads:read", None).unwrap();
    assert_eq!(read["data"], built["data"]);
    assert!(read["output"]
        .as_str()
        .unwrap()
        .contains("No accepted Map, scan jobs or findings"));
    assert_eq!(std::fs::read(&model_path).unwrap(), model);
    assert_eq!(
        std::fs::read(f.root.path().join("owned.rs")).unwrap(),
        source
    );
    assert!(!f.workspace.state_dir().join("campaigns").exists());
}

#[test]
fn canceled_lead_build_preserves_prior_artifacts() {
    let f = Fixture::new();
    std::fs::write(f.artifact(), "prior-artifact").unwrap();
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    assert!(f
        .dispatch("threat-leads:build", Some(&cancellation))
        .is_err());
    assert_eq!(
        std::fs::read_to_string(f.artifact()).unwrap(),
        "prior-artifact"
    );
}

#[test]
fn missing_or_invalid_model_does_not_replace_saved_cards() {
    let f = Fixture::new();
    std::fs::write(f.artifact(), "prior-artifact").unwrap();
    let path = crate::capabilities::persistent_threat_model_path(f.root.path());
    for contents in ["not JSON", "{}"] {
        std::fs::write(&path, contents).unwrap();
        assert!(f.dispatch("threat-leads:build", None).is_err());
        assert_eq!(
            std::fs::read_to_string(f.artifact()).unwrap(),
            "prior-artifact"
        );
    }
    std::fs::remove_file(path).unwrap();
    assert!(f.dispatch("threat-leads:build", None).is_err());
}

#[test]
fn legacy_cards_are_read_as_partial_with_unknown_inspection() {
    let f = Fixture::new();
    std::fs::write(f.artifact(), json!({"leadCount":0,"leads":[]}).to_string()).unwrap();
    let result = f.dispatch("threat-leads:read", None).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(
        result["data"]["sourceCoverage"]["status"],
        "legacy-unverified"
    );
    assert!(result["output"].as_str().unwrap().contains("unrecorded"));
    assert_eq!(result["artifacts"].as_array().unwrap().len(), 1);
}

#[test]
fn malformed_or_inconsistent_cards_are_not_successful_empty_reads() {
    let f = Fixture::new();
    for value in [json!({}), json!({"leadCount":3,"leads":[]})] {
        std::fs::write(f.artifact(), value.to_string()).unwrap();
        assert!(f.dispatch("threat-leads:read", None).is_err());
    }
}

#[test]
fn excessive_threats_are_bounded_and_keep_the_original_context() {
    let f = Fixture::new();
    let path = crate::capabilities::persistent_threat_model_path(f.root.path());
    let model=json!({"threats":(0..257).map(|i|json!({"id":format!("T{i}"),"title":"Owned parser resource limits"})).collect::<Vec<_>>()}).to_string();
    std::fs::write(&path, &model).unwrap();
    let result = f.dispatch("threat-leads:build", None).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["sourceCoverage"]["processedThreats"], 256);
    assert_eq!(result["data"]["sourceCoverage"]["unprocessedThreats"], 1);
    assert_eq!(result["data"]["leadCount"], 256);
    assert_eq!(std::fs::read_to_string(path).unwrap(), model);
}

#[test]
fn unsupported_source_receipts_cannot_claim_complete_coverage() {
    let f = Fixture::new();
    for coverage in [
        json!({"schemaVersion":1,"status":"bounded","completeRepositoryCoverage":true}),
        json!({"schemaVersion":2,"status":"bounded","completeRepositoryCoverage":false}),
    ] {
        std::fs::write(
            f.artifact(),
            json!({"leadCount":0,"leads":[],"sourceCoverage":coverage}).to_string(),
        )
        .unwrap();
        assert!(f.dispatch("threat-leads:read", None).is_err());
    }
}

#[test]
fn reading_saved_hints_keeps_the_consumed_context_receipt_after_context_changes() {
    let f = Fixture::new();
    let built = f.dispatch("threat-leads:build", None).unwrap();
    let context_receipt = built["data"]["sources"]["threatModelSha256"]
        .as_str()
        .unwrap();
    let path = crate::capabilities::persistent_threat_model_path(f.root.path());
    std::fs::write(
        path,
        json!({"threats":[],"title":"Changed current context"}).to_string(),
    )
    .unwrap();
    let read = f.dispatch("threat-leads:read", None).unwrap();
    assert_eq!(
        read["data"]["sources"]["threatModelSha256"],
        context_receipt
    );
    assert!(read["output"].as_str().unwrap().contains(context_receipt));
    assert!(read["output"]
        .as_str()
        .unwrap()
        .contains("current source equivalence are not established"));
}

#[test]
fn explicit_summary_repair_uses_saved_cards_even_without_active_context() {
    let f = Fixture::new();
    let built = f.dispatch("threat-leads:build", None).unwrap();
    let before = std::fs::read(f.artifact()).unwrap();
    let summary = f.artifact().with_extension("md");
    std::fs::write(&summary, "STALE_OWNED_SUMMARY").unwrap();
    std::fs::remove_file(crate::capabilities::persistent_threat_model_path(
        f.root.path(),
    ))
    .unwrap();
    let read = f.dispatch("threat-leads:read", None).unwrap();
    assert_eq!(read["summaryPublication"]["status"], "stale");
    assert_eq!(read["artifacts"].as_array().unwrap().len(), 1);
    let repaired = f
        .dispatch_input("threat-leads:build", json!({"repairSummary":true}), None)
        .unwrap();
    assert_eq!(repaired["data"], built["data"]);
    assert_eq!(repaired["summaryPublication"]["status"], "current");
    assert_eq!(std::fs::read(f.artifact()).unwrap(), before);
    assert!(!std::fs::read_to_string(summary)
        .unwrap()
        .contains("STALE_OWNED_SUMMARY"));
    assert!(!crate::capabilities::persistent_threat_model_path(f.root.path()).exists());
    assert!(!f.workspace.state_dir().join("campaigns").exists());
}

#[test]
fn canceled_or_invalid_summary_repair_preserves_the_saved_pair() {
    let f = Fixture::new();
    f.dispatch("threat-leads:build", None).unwrap();
    let before = std::fs::read(f.artifact()).unwrap();
    let summary = f.artifact().with_extension("md");
    std::fs::write(&summary, "OWNED_STALE").unwrap();
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    assert!(f
        .dispatch_input(
            "threat-leads:build",
            json!({"repairSummary":true}),
            Some(&cancellation)
        )
        .is_err());
    assert!(f
        .dispatch_input(
            "threat-leads:build",
            json!({"repairSummary":"invalid"}),
            None
        )
        .is_err());
    assert_eq!(std::fs::read(f.artifact()).unwrap(), before);
    assert_eq!(std::fs::read_to_string(&summary).unwrap(), "OWNED_STALE");
    std::fs::write(f.artifact(), "{}").unwrap();
    assert!(f
        .dispatch_input("threat-leads:build", json!({"repairSummary":true}), None)
        .is_err());
    assert_eq!(std::fs::read_to_string(summary).unwrap(), "OWNED_STALE");
}
