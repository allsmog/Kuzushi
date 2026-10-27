use super::*;
use crate::{OptionScope, OptionTarget, ToolOptionStore};

fn saved_semgrep_options() -> ToolOptionStore {
    let mut store = ToolOptionStore::default();
    for (name, value) in [
        ("semgrepConfig", json!(["unused-global-rules.yml"])),
        ("semgrepJobs", json!(2)),
        ("semgrepTimeoutMs", json!(60000)),
    ] {
        store.set_value(
            OptionScope::Global,
            OptionTarget::Tool("sast:scan".into()),
            name,
            value,
        );
    }
    store
}

#[test]
fn approved_jobs_ignore_saved_engine_options_and_execute_the_frozen_input() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "// owned inert source\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    workspace.ensure_state_dir().unwrap();
    let findings = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins();
    let mut ctx = context(&workspace, &config);
    ctx.findings_store = Some(&findings);
    let draft = draft(&registry, &ctx);
    approve_draft_with_limits(&registry, &ctx, &draft, 0, 0).unwrap();
    let trace = crate::run_lifecycle::RunObservationHandle::jsonl(root.path(), "frozen-options")
        .unwrap()
        .start_root_task("sast:scan")
        .unwrap()
        .trace_handle();
    ctx.trace = Some(&trace);
    let input = bound_input(&plan(root.path()), 0);
    let store = saved_semgrep_options();
    let before = store.clone();
    let prepared = registry
        .prepare_dispatch_input("sast:scan", input.clone(), &ctx, Some(&store))
        .unwrap()
        .authorize_explicit_headless();
    assert_eq!(prepared.value(), &input);
    assert_eq!(store, before);
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(result["ok"], true, "{result}");
    let snapshot = open_ledger(&ctx)
        .unwrap()
        .allowance_snapshot("study")
        .unwrap();
    assert_eq!(snapshot.committed_calls, 0);
    assert_eq!(snapshot.unresolved_calls, 0);
}

#[test]
fn ordinary_and_call_only_allowances_keep_stored_option_precedence() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    workspace.ensure_state_dir().unwrap();
    let _findings = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    let approval = registry
        .prepare_dispatch_input("campaign:approve-allowance", approval(), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(approval, &ctx, None)
        .unwrap();
    let store = saved_semgrep_options();
    for mut input in [
        json!({}),
        json!({"allowanceRef":{
            "schemaVersion":1,"investigationId":"study","revision":1,"workId":"legacy",
        }}),
    ] {
        input["taskMode"] = json!("manual");
        input["tasks"] = json!(["semgrep"]);
        let prepared = registry
            .prepare_dispatch_input("sast:scan", input, &ctx, Some(&store))
            .unwrap();
        assert_eq!(prepared.value()["semgrepJobs"], 2);
        assert_eq!(
            prepared.value()["semgrepConfig"],
            json!(["unused-global-rules.yml"])
        );
    }
}

#[test]
fn altered_or_unknown_work_cannot_bypass_stored_options_as_an_approved_job() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "// owned inert source\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    let draft = draft(&registry, &ctx);
    approve_draft_with_limits(&registry, &ctx, &draft, 0, 0).unwrap();
    let original = bound_input(&plan(root.path()), 0);
    let mut changed = original.clone();
    changed["maxFindings"] = json!(1);
    let mut stale = original.clone();
    stale["allowanceRef"]["revision"] = json!(2);
    let mut missing = original.clone();
    missing["allowanceRef"]["workId"] = json!("finite:missing");
    let store = saved_semgrep_options();
    for input in [changed, stale, missing] {
        assert!(registry
            .prepare_dispatch_input("sast:scan", input, &ctx, Some(&store))
            .is_err());
    }
    assert!(registry
        .prepare_dispatch_input("secret-scan:scan", original, &ctx, Some(&store))
        .is_err());
    let snapshot = open_ledger(&ctx)
        .unwrap()
        .allowance_snapshot("study")
        .unwrap();
    assert_eq!(snapshot.committed_calls, 0);
    assert_eq!(snapshot.unresolved_calls, 0);
}
