use super::*;
use kuzushi_core::{ModuleRegistry, ToolExecutionContext, WorkspaceTarget};
use serde_json::json;

#[test]
fn prepared_dispatch_approves_and_enforces_allowance_for_real_context_executor() {
    let fixture = Fixture::new("context", 3, 1);
    let workspace = context_workspace(&fixture);
    let target = workspace.root();
    let mut config = V2Config::default();
    config.model = Some(MODEL.into());
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    approve_workspace(&registry, &ctx);
    let input = json!({"enrichment":true,"allowanceRef":{
        "schemaVersion":1,"investigationId":"dispatch-study","revision":1,"workId":"context-1"
    }});
    let result = registry
        .execute_tool_with_runtime("context:build", input.clone(), &ctx, Some(&fixture.runtime))
        .unwrap();
    assert_eq!(fixture.provider_calls(), 1);
    assert_eq!(result["ok"], true);
    let artifact: serde_json::Value =
        serde_json::from_slice(&fs::read(target.join(".kuzushi/context-snapshot.json")).unwrap())
            .unwrap();
    assert_eq!(artifact["enrichedContext"]["schemaVersion"], 1);
    assert!(registry
        .execute_tool_with_runtime("context:build", input, &ctx, Some(&fixture.runtime))
        .is_err());
    assert_eq!(
        fixture.provider_calls(),
        1,
        "no second provider attempt fits before protected review"
    );
    assert_workspace_allowance(&workspace);
}

fn assert_workspace_allowance(workspace: &WorkspaceTarget) {
    let snapshot = SpendLimiter::open(workspace.findings_db_path())
        .unwrap()
        .allowance_snapshot("dispatch-study")
        .unwrap();
    assert_eq!(snapshot.committed_calls, 1);
    assert_eq!(snapshot.protected_review_remaining(), 1);
    assert_eq!(snapshot.cost.observed_usd_if_available(), None);
}

fn context_workspace(fixture: &Fixture) -> WorkspaceTarget {
    let target = fixture.root.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("main.rs"), "fn main() {}\n").unwrap();
    WorkspaceTarget::new(&target).unwrap()
}

fn approve_workspace(registry: &ModuleRegistry, ctx: &ToolExecutionContext<'_>) {
    let input = json!({"investigationId":"dispatch-study","expectedRevision":0,"model":MODEL,
        "maxProviderCalls":2,"protectedReviewCalls":1,"reason":"Offline provider interception only"});
    let prepared = registry
        .prepare_dispatch_input("campaign:approve-allowance", input, ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, ctx, None)
        .unwrap();
}

#[test]
fn inherited_allowance_cannot_be_replaced_by_nested_work() {
    let fixture = Fixture::new("loop", 3, 1);
    let runtime = fixture
        .runtime
        .with_allowance_binding(fixture.binding.clone())
        .unwrap();
    runtime
        .with_allowance_binding(fixture.binding.clone())
        .unwrap();
    let other = AllowanceBinding::new(
        fixture.ledger.clone(),
        AllowanceWork {
            investigation_id: "offline-study".into(),
            revision: 1,
            run_id: "offline-run".into(),
            work_id: "source-scan".into(),
            model: MODEL.into(),
            work: InvestigationWork::Review,
        },
    )
    .unwrap();
    assert!(runtime.with_allowance_binding(other).is_err());
    assert_eq!(fixture.provider_calls(), 0);
}
