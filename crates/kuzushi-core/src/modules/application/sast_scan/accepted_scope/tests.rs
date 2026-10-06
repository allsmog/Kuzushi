use super::*;
use crate::workspace::*;

fn fixture() -> (
    tempfile::TempDir,
    WorkspaceTarget,
    crate::V2Config,
    ScanScopeRef,
) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("included.env"),
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("excluded.env"),
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let ctx = context(&workspace, &config);
    let draft = create_scan_scope_proposal(&ctx, None).unwrap();
    FindingStore::open(workspace.findings_db_path()).unwrap();
    let excluded = edit_scan_scope_proposal(
        &ctx,
        &draft.reference,
        ScanScopeEdit::ExcludePath {
            path: "excluded.env".into(),
            reason: "Explicit fixture exclusion".into(),
        },
    )
    .unwrap();
    let accepted = accept_scan_scope_proposal(
        &ctx,
        &excluded.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            exclusions: true,
            overlapping_discovery: false,
        },
    )
    .unwrap();
    let reference = ScanScopeRef {
        proposal: accepted.reference,
        scope_id: "repository".into(),
    };
    (root, workspace, config, reference)
}

fn context<'a>(
    workspace: &'a WorkspaceTarget,
    config: &'a crate::V2Config,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

fn prepared(
    workspace: &WorkspaceTarget,
    config: &crate::V2Config,
    reference: &ScanScopeRef,
    task: &str,
) -> Result<Value> {
    ModuleRegistry::with_v2_builtins().prepare_dispatch_input("sast:scan", json!({"taskMode":"manual","tasks":[task],"scanScopeRef":reference,"triage":false,"verify":false,"autoPatch":false}), &context(workspace,config), None).map(|value| value.value().clone())
}

#[test]
fn prepared_scope_reference_resolves_exact_discovery_and_rejects_broader_paths() {
    let (_root, workspace, config, reference) = fixture();
    let input = prepared(&workspace, &config, &reference, "secret-scan").unwrap();
    let options = scope_scan_options(&input, false, &context(&workspace, &config)).unwrap();
    assert_eq!(
        options.discovery_files(),
        Some(["included.env".to_string()].as_slice())
    );
    let mut conflict = input.clone();
    conflict["paths"] = json!(["."]);
    assert!(bind_accepted_sast_scope_input(conflict, &context(&workspace, &config)).is_err());
    assert!(prepared(&workspace, &config, &reference, "agentic").is_err());
}

#[test]
fn exact_native_secret_scan_consumes_only_accepted_files_and_records_the_scope() {
    let (_root, workspace, config, reference) = fixture();
    let registry = ModuleRegistry::with_v2_builtins();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let mut ctx = context(&workspace, &config);
    ctx.findings_store = Some(&store);
    let input = prepared(&workspace, &config, &reference, "secret-scan").unwrap();
    let prepared = registry
        .prepare_dispatch_input("sast:scan", input, &ctx, None)
        .unwrap();
    let output = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(output["data"]["findingsCount"], 1);
    let findings = store.list_findings(20).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path, "included.env");
}

#[test]
fn source_changes_refuse_a_saved_scope_before_model_or_native_work() {
    let (root, workspace, config, reference) = fixture();
    std::fs::write(root.path().join("included.env"), "changed source\n").unwrap();
    assert!(prepared(&workspace, &config, &reference, "secret-scan").is_err());
}
