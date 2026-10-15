use super::tests::{approval, context};
use super::*;
use crate::{FindingStore, V2Config, WorkspaceTarget};

fn draft(registry: &ModuleRegistry, ctx: &ToolExecutionContext<'_>) -> Value {
    registry
        .execute_tool(
            "campaign:study",
            json!({"campaignId":"finite",
        "scanInput":{"taskMode":"manual","tasks":["secret-scan"]}}),
            ctx,
        )
        .unwrap()
}

fn approve_draft(
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
    draft: &Value,
) -> Result<Value> {
    approve_draft_with_limits(registry, ctx, draft, 9, 3)
}

fn approve_draft_with_limits(
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
    draft: &Value,
    calls: u32,
    review: u32,
) -> Result<Value> {
    let mut input = approval();
    input["maxProviderCalls"] = json!(calls);
    input["protectedReviewCalls"] = json!(review);
    input["campaignId"] = json!("finite");
    input["campaignJobs"] = json!(3);
    input["maxJobAttempts"] = json!(1);
    input["campaignPlanSha256"] = draft["data"]["planSha256"].clone();
    let prepared = registry
        .prepare_dispatch_input("campaign:approve-allowance", input, ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, ctx, None)
}

fn plan(root: &std::path::Path) -> Value {
    let path = crate::capabilities::campaign::campaign_plan_path(root, "finite");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn study_draft_never_starts_jobs_and_unapproved_children_are_refused() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    let draft = draft(&registry, &ctx);
    assert_eq!(draft["data"]["jobCount"], 3);
    assert_eq!(draft["data"]["workers"], 1);
    assert!(draft["output"]
        .as_str()
        .unwrap()
        .contains("No jobs started"));
    let plan = plan(root.path());
    assert_eq!(plan["requiresWorkApproval"], true);
    let error = registry
        .execute_tool("sast:scan", plan["jobs"][0]["input"].clone(), &ctx)
        .unwrap_err();
    assert!(error.to_string().contains("requires approval"), "{error:#}");
    assert_eq!(
        crate::runtime::runtime_failure_metadata(&error)
            .unwrap()
            .error_class,
        crate::RuntimeFailureClass::AllowanceRefused
    );
    approve_draft(&registry, &ctx, &draft).unwrap();
    assert_eq!(
        open_ledger(&ctx)
            .unwrap()
            .allowance_snapshot("study")
            .unwrap()
            .work_plan
            .unwrap()
            .jobs
            .len(),
        3
    );
}

#[test]
fn zero_calls_allow_three_fresh_offline_passes_and_refuse_a_fourth() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    workspace.ensure_state_dir().unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins();
    let mut ctx = context(&workspace, &config);
    ctx.findings_store = Some(&store);
    let draft = draft(&registry, &ctx);
    approve_draft_with_limits(&registry, &ctx, &draft, 0, 0).unwrap();
    let plan = plan(root.path());
    for index in 0..3 {
        execute_offline_pass(&registry, &workspace, &config, &store, &plan, index);
    }
    let trace = crate::run_artifacts::TraceHandle::jsonl(root.path(), "unapproved-fourth-pass");
    ctx.trace = Some(&trace);
    let error = registry
        .execute_tool("sast:scan", bound_input(&plan, 0), &ctx)
        .unwrap_err();
    assert!(error.to_string().contains("attempt limit"), "{error:#}");
    let snapshot = open_ledger(&ctx)
        .unwrap()
        .allowance_snapshot("study")
        .unwrap();
    assert_eq!(snapshot.limits.max_provider_calls, 0);
    assert_eq!(snapshot.limits.protected_review_calls, 0);
    assert_eq!(snapshot.committed_calls, 0);
    assert_eq!(snapshot.unresolved_calls, 0);
}

fn execute_offline_pass(
    registry: &ModuleRegistry,
    workspace: &WorkspaceTarget,
    config: &V2Config,
    store: &FindingStore,
    plan: &Value,
    index: usize,
) {
    let trace = crate::run_lifecycle::RunObservationHandle::jsonl(
        workspace.root(),
        format!("offline-pass-{index}"),
    )
    .unwrap()
    .start_root_task("sast:scan")
    .unwrap()
    .trace_handle();
    let mut child_ctx = context(&workspace, &config);
    child_ctx.findings_store = Some(&store);
    child_ctx.trace = Some(&trace);
    let input = bound_input(&plan, index);
    let prepared = registry
        .prepare_dispatch_input("sast:scan", input, &child_ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &child_ctx, None)
        .unwrap();
    assert_eq!(result["ok"], true, "{result}");
}

fn bound_input(plan: &Value, index: usize) -> Value {
    let mut input = plan["jobs"][index]["input"].clone();
    input["allowanceRef"] = json!({"schemaVersion":1,"investigationId":"study","revision":1,
        "workId":format!("finite:trial-{:03}", index + 1)});
    input
}

#[test]
fn source_drift_and_changed_plan_cannot_inherit_an_old_approval() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("main.rs");
    std::fs::write(&source, "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    let draft = draft(&registry, &ctx);
    std::fs::write(&source, "fn main() { changed(); }\n").unwrap();
    let error = approve_draft(&registry, &ctx, &draft).unwrap_err();
    assert!(error.to_string().contains("different source"), "{error:#}");
    std::fs::write(&source, "fn main() {}\n").unwrap();
    let mut wrong = draft;
    wrong["data"]["planSha256"] = json!("a".repeat(64));
    let error = approve_draft(&registry, &ctx, &wrong).unwrap_err();
    assert!(error.to_string().contains("digest"), "{error:#}");
}
