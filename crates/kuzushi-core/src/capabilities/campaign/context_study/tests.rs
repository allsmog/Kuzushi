use super::*;
use crate::{V2Config, WorkspaceTarget};

const MODEL: &str = "openai-codex:gpt-5.5";

mod diagnosis;
mod execution;
mod map_handoff;
mod recovery;
mod scope;

fn context<'a>(workspace: &'a WorkspaceTarget, config: &'a V2Config) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

fn draft(
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
    options: Value,
) -> Result<Value> {
    let prepared = registry.prepare_dispatch_input(
        "campaign:context-study",
        json!({
            "campaignId":"context-draft","investigationId":"investigation","contextInput":options,
        }),
        ctx,
        None,
    )?;
    registry.dispatch_prepared_input_with_runtime(prepared, ctx, None)
}

fn approval(receipt: &ContextStudyReceipt) -> Value {
    json!({"investigationId":"investigation","expectedRevision":0,"model":MODEL,
        "maxProviderCalls":5,"protectedReviewCalls":2,"reason":"Offline context study test",
        "campaignId":receipt.campaign_id,"campaignPlanSha256":receipt.plan_sha256,
        "campaignJobs":1,"maxJobAttempts":1})
}

fn approve(
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
    input: Value,
) -> Result<Value> {
    let prepared = registry
        .prepare_dispatch_input("campaign:approve-allowance", input, ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, ctx, None)
}

#[test]
fn context_study_freezes_one_job_without_spending_or_switching_context() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    let result = draft(&registry, &ctx, json!({})).unwrap();
    let receipt = load_context_study(root.path(), "context-draft").unwrap();
    assert_eq!(serde_json::to_value(&receipt).unwrap(), result["data"]);
    assert_eq!(receipt.input["activate"], false);
    assert_eq!(receipt.input["model"], MODEL);
    assert!(draft(&registry, &ctx, json!({})).is_err());
    let approved = approve(&registry, &ctx, approval(&receipt)).unwrap();
    let snapshot: crate::allowance::AllowanceSnapshot =
        serde_json::from_value(approved["data"]["allowance"].clone()).unwrap();
    assert_eq!(snapshot.committed_calls, 0);
    assert_eq!(snapshot.work_plan.as_ref().unwrap().jobs[0].tool, TOOL);
    assert_eq!(
        receipt.bound_input(&snapshot).unwrap()["allowanceRef"]["workId"],
        "context-draft:context-001"
    );
    assert!(
        crate::capabilities::threat_model::load_active_threat_model(root.path())
            .unwrap()
            .is_none()
    );
}

#[test]
fn context_study_rejects_scope_expansion_activation_model_and_source_drift() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("main.rs");
    std::fs::write(&source, "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    for options in [
        json!({"activate":true}),
        json!({"pipeline":"staged"}),
        json!({"variantScan":true}),
        json!({"seed":["unbound"]}),
        json!({"scope":"path:src"}),
        json!({"unknown":true}),
    ] {
        assert!(
            draft(&registry, &ctx, options.clone()).is_err(),
            "{options}"
        );
    }
    draft(&registry, &ctx, json!({})).unwrap();
    let receipt = load_context_study(root.path(), "context-draft").unwrap();
    for (key, value) in [
        ("campaignJobs", json!(2)),
        ("maxJobAttempts", json!(2)),
        ("model", json!("openai-codex:changed")),
        ("investigationId", json!("reset-spending")),
    ] {
        let mut input = approval(&receipt);
        input[key] = value;
        assert!(approve(&registry, &ctx, input).is_err(), "{key}");
    }
    std::fs::write(source, "fn changed() {}\n").unwrap();
    assert!(approve(&registry, &ctx, approval(&receipt))
        .unwrap_err()
        .to_string()
        .contains("source or configuration changed"));
}

#[test]
fn selected_preparation_is_frozen_approved_and_runs_through_shared_dispatch() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    registry.execute_tool("campaign:context-study", json!({
        "campaignId":"context-draft","investigationId":"investigation","contextInput":{"methodology":"pasta"},
        "preparationJobs":[{"tool":"context:build","input":{"sampleLimit":10}},
            {"tool":"entry-points:extract","input":{}}]
    }), &ctx).unwrap();
    let receipt = load_context_study(root.path(), "context-draft").unwrap();
    assert_eq!(receipt.job_count(), 3);
    assert_eq!(receipt.input["methodology"], "pasta");
    assert!(approve(&registry, &ctx, approval(&receipt)).is_err());
    let mut terms = approval(&receipt);
    terms["campaignJobs"] = json!(3);
    let approved = approve(&registry, &ctx, terms).unwrap();
    let snapshot: crate::allowance::AllowanceSnapshot =
        serde_json::from_value(approved["data"]["allowance"].clone()).unwrap();
    let plan = read_bounded_plan(root.path(), "context-draft").unwrap();
    for (index, job) in plan["jobs"].as_array().unwrap().iter().take(2).enumerate() {
        let run_id = format!("preparation-{index}");
        let trace = crate::run_artifacts::TraceHandle::jsonl(root.path(), &run_id);
        let mut run_ctx = context(&workspace, &config);
        run_ctx.trace = Some(&trace);
        let mut input = job["input"].clone();
        input["allowanceRef"] = json!({"schemaVersion":1,"investigationId":"investigation","revision":snapshot.revision,
            "workId":format!("context-draft:{}", job["jobId"].as_str().unwrap())});
        let prepared = registry
            .prepare_dispatch_input(job["tool"].as_str().unwrap(), input, &run_ctx, None)
            .unwrap()
            .authorize_explicit_headless();
        registry
            .dispatch_prepared_input_with_runtime(prepared, &run_ctx, None)
            .unwrap();
    }
    assert!(root.path().join(".kuzushi/context-snapshot.json").exists());
    assert!(root.path().join(".kuzushi/entry-points.json").exists());
    let reloaded = receipt.load_allowance(root.path()).unwrap().unwrap();
    assert_eq!(reloaded.committed_calls, 0);
    assert_eq!(reloaded.work_plan.as_ref().unwrap().jobs.len(), 3);
    assert!(receipt.bound_input(&reloaded).is_ok());
}

#[test]
fn context_preparation_refuses_expansion_enrichment_and_target_changes() {
    let root = tempfile::tempdir().unwrap();
    let foreign = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    for jobs in [
        json!([{"tool":"context:build","input":{}},{"tool":"context:build","input":{}}]),
        json!([{"tool":"campaign:context-study","input":{}}]),
        json!([{"tool":"context:build","input":{"enrichment":true}}]),
        json!([{"tool":"entry-points:extract","input":{"target":foreign.path()}}]),
        json!([{"tool":"entry-points:extract","input":{},"unexpected":"ignored"}]),
    ] {
        let result = registry.execute_tool("campaign:context-study", json!({
            "campaignId":"invalid-preparation","investigationId":"investigation","contextInput":{},"preparationJobs":jobs
        }), &ctx);
        assert!(result.is_err(), "{jobs}");
        assert!(!campaign_plan_path(root.path(), "invalid-preparation").exists());
    }
}
