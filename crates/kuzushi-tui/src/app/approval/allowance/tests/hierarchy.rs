use super::*;
use kuzushi_core::{
    capabilities::campaign::ContextMatrixReceipt, ToolExecutionContext, WorkspaceTarget,
};

fn compiled_matrix(app: &ShellApp, root: &std::path::Path) -> ContextMatrixReceipt {
    std::fs::write(
        root.join("note.md"),
        "Owned inert approval fixture. Never executed.\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root).unwrap();
    let ctx = ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let cases = context_cases(&registry, &ctx);
    let output = registry.execute_tool("campaign:study", json!({
        "campaignId":"approval-matrix", "investigationId":"study", "baselineCaseId":"case-0",
        "scanInput":{"taskMode":"manual","tasks":["license-scan"]}, "contextCases":cases,
    }), &ctx).unwrap();
    serde_json::from_value(output["data"].clone()).unwrap()
}

fn context_cases(
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
) -> Vec<serde_json::Value> {
    (0..8).map(|index| {
        let label = format!("Boundary {index}: full context and receipts remain available for inspection");
        let output = registry.execute_tool("threat-model:import", json!({
            "activate":false, "label":label, "document":{"version":"1","methodology":"stride",
            "title":label,"systemContext":"Owned inert text","dfd":{"nodes":[
                {"id":"app","name":"App","type":"process","trustZone":"repository"}],
                "flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}
        }), ctx).unwrap();
        json!({"id":format!("case-{index}"), "label":label, "threatModelRef":output["data"]["modelRef"]})
    }).collect()
}

#[test]
fn many_case_approval_shows_spending_before_all_context_receipts() {
    let root = tempfile::tempdir().unwrap();
    let mut app = app_with_commitments(root.path());
    let receipt = compiled_matrix(&app, root.path());
    let input = json!({"investigationId":"study","expectedRevision":2,"model":TEST_MODEL,
        "campaignId":receipt.campaign_id,"campaignPlanSha256":receipt.plan_sha256,
        "campaignJobs":receipt.job_count,"maxJobAttempts":1,"maxProviderCalls":12,
        "protectedReviewCalls":4,"reason":"Inspect the exact owned matrix"});
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .matrix
        .receipt = Some(receipt.clone());
    let confirm = with_accounting_terms(&app, &input, confirmation(&input));
    app.request_confirm(confirm);
    let model = crate::ui_view_models::allowance_review_model(&app, 120, 36).unwrap();
    let first_page = model
        .lines
        .iter()
        .take(model.page_rows)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "24 fixed jobs",
        "1 worker(s)",
        "Execution model: none; this frozen discovery uses native engines",
        "Calls already committed: 1",
        "unresolved: 1",
        "Total provider calls: 12",
        "Protected review calls: 4",
        "Dollar ceiling: not enforced",
    ] {
        assert!(first_page.contains(required), "{first_page}");
    }
    assert!(!first_page.contains("Threat context:"));
    assert!(!model.allows_approval());
    let full = model.lines.join("\n");
    for case in &receipt.matrix.cases {
        assert!(full.contains(&case.label));
        assert!(full.contains(
            case.base_input["threatModelRef"]["revisionId"]
                .as_str()
                .unwrap()
        ));
    }
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .allowance
            .as_ref()
            .unwrap()
            .committed_calls,
        1
    );
    assert!(!app.has_running_work());
}
