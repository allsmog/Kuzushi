use super::*;
use crate::run_artifacts::{
    load_run_request_context, write_run_artifact_json, RecordedAllowanceOrigin, TraceHandle,
};

fn review_parent(ctx: &ToolExecutionContext<'_>) -> AccountingRuntime {
    let mut runtime = bound_runtime(ctx, &AccountingRuntime::default());
    let mut work = runtime.binding.as_ref().unwrap().work().clone();
    work.work = InvestigationWork::Review;
    work.run_id = "owned-parent-review".into();
    runtime.binding = Some(AllowanceBinding::new(open_ledger(ctx).unwrap(), work).unwrap());
    runtime
}

fn publish_input(workspace: &WorkspaceTarget) -> Value {
    let input = json!({"enrichment":true});
    write_run_artifact_json(
        workspace.root(),
        "child",
        "input.json",
        "tool input",
        &input,
    )
    .unwrap();
    input
}

fn assert_saved_input(workspace: &WorkspaceTarget, input: &Value) {
    let path = crate::run_artifacts::run_artifact_path(workspace.root(), "child", "input.json");
    let saved: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(&saved, input);
}

fn revise_study(ctx: &ToolExecutionContext<'_>) {
    open_ledger(ctx)
        .unwrap()
        .approve_allowance(&crate::allowance::AllowanceApprovalV1 {
            schema_version: 1,
            investigation_id: "study".into(),
            expected_revision: 1,
            model: MODEL.into(),
            limits: crate::allowance::AllowanceLimits {
                max_provider_calls: 4,
                protected_review_calls: 1,
            },
            reason: "Owned revised ceiling. No provider request.".into(),
            work_plan: None,
        })
        .unwrap();
}

#[test]
fn refused_child_keeps_parent_reference_without_changing_input_or_spending() {
    let (_root, workspace, config) = fixture();
    let mut ctx = context(&workspace, &config);
    approve_context(&ctx);
    let runtime = review_parent(&ctx);
    let trace = TraceHandle::jsonl(workspace.root(), "child");
    ctx.trace = Some(&trace);
    let input = publish_input(&workspace);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let prepared = registry
        .prepare_dispatch_input("context:build", input.clone(), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    assert_allowance_refused(
        registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
            .unwrap_err(),
    );
    let recorded = load_run_request_context(workspace.root(), "child").unwrap();
    assert!(matches!(
        recorded.allowance_origin,
        RecordedAllowanceOrigin::Inherited {
            work: InvestigationWork::Review,
            ..
        }
    ));
    let grant = recorded.allowance.unwrap().unwrap();
    assert_eq!(grant.reference.investigation_id, "study");
    assert_eq!(grant.run_committed_calls, 0);
    assert_eq!(grant.current.protected_review_remaining(), 1);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    assert_saved_input(&workspace, &input);
}

#[test]
fn foreign_parent_ledger_is_refused_before_receipt_retention() {
    let (_parent_root, parent, config) = fixture();
    let parent_ctx = context(&parent, &config);
    approve_context(&parent_ctx);
    let runtime = review_parent(&parent_ctx);
    let (_root, workspace, child_config) = fixture();
    let mut ctx = context(&workspace, &child_config);
    approve_context(&ctx);
    let trace = TraceHandle::jsonl(workspace.root(), "child");
    ctx.trace = Some(&trace);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let input = publish_input(&workspace);
    let error = bind_runtime(
        registry.resolve_tool("context:build").unwrap(),
        &input,
        &ctx,
        Some(&runtime),
    )
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("cannot replace an inherited allowance ledger"));
    let read = load_run_request_context(workspace.root(), "child").unwrap();
    assert_eq!(read.allowance.unwrap(), None);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn model_free_work_does_not_record_an_offered_parent_grant() {
    let (_root, workspace, config) = fixture();
    let mut ctx = context(&workspace, &config);
    approve_context(&ctx);
    let runtime = review_parent(&ctx);
    let trace = TraceHandle::jsonl(workspace.root(), "child");
    ctx.trace = Some(&trace);
    write_run_artifact_json(
        workspace.root(),
        "child",
        "input.json",
        "tool input",
        &json!({}),
    )
    .unwrap();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    assert!(bind_runtime(
        registry.resolve_tool("context:build").unwrap(),
        &json!({}),
        &ctx,
        Some(&runtime)
    )
    .unwrap()
    .is_none());
    assert_eq!(
        load_run_request_context(workspace.root(), "child")
            .unwrap()
            .allowance
            .unwrap(),
        None
    );
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn stale_parent_is_recorded_for_history_but_cannot_admit_the_child() {
    let (_root, workspace, config) = fixture();
    let mut ctx = context(&workspace, &config);
    approve_context(&ctx);
    let runtime = review_parent(&ctx);
    revise_study(&ctx);
    let trace = TraceHandle::jsonl(workspace.root(), "child");
    ctx.trace = Some(&trace);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let input = publish_input(&workspace);
    let error = bind_runtime(
        registry.resolve_tool("context:build").unwrap(),
        &input,
        &ctx,
        Some(&runtime),
    )
    .err()
    .unwrap();
    assert_allowance_refused(error);
    let read = load_run_request_context(workspace.root(), "child")
        .unwrap()
        .allowance
        .unwrap()
        .unwrap();
    assert_eq!(read.reference.revision, 1);
    assert_eq!(read.current.revision, 2);
    assert_eq!(read.current.protected_review_remaining(), 1);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn foreign_trace_cannot_receive_the_workspace_parent_reference() {
    let (_root, workspace, config) = fixture();
    let mut ctx = context(&workspace, &config);
    approve_context(&ctx);
    let runtime = review_parent(&ctx);
    let elsewhere = tempfile::tempdir().unwrap();
    let trace = TraceHandle::jsonl(elsewhere.path(), "child");
    ctx.trace = Some(&trace);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let error = bind_runtime(
        registry.resolve_tool("context:build").unwrap(),
        &json!({"enrichment":true}),
        &ctx,
        Some(&runtime),
    )
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("receipt belongs to another target"));
    assert!(!crate::run_artifacts::run_artifact_path(
        elsewhere.path(),
        "child",
        "inherited-allowance.json"
    )
    .exists());
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}
