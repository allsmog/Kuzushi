use super::*;

#[test]
fn planned_rule_sources_reach_report_and_export_without_reopening_them() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("owned.txt"), "Owned inert source.\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins();
    let ctx = crate::ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let selectors = json!(["p/owned-fixture", " owned \\\"rules\\\"\n.yaml "]);
    let prepared = registry.prepare_dispatch_input("campaign:study", json!({
        "campaignId":"rule-report", "scanInput":{
            "taskMode":"manual", "tasks":["semgrep"], "threatModelRef":null, "scanContextRef":null,
            "semgrepConfig":selectors, "semgrepTimeoutMs":60000, "semgrepJobs":1
        }
    }), &ctx, None).unwrap().authorize_explicit_headless();
    let draft = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    let approval = registry.prepare_dispatch_input("campaign:approve-allowance", json!({
        "campaignId":"rule-report", "investigationId":"rule-report", "expectedRevision":0,
        "campaignPlanSha256":draft["data"]["planSha256"], "campaignJobs":3, "maxJobAttempts":1,
        "model":"openai-codex:gpt-5.5", "maxProviderCalls":1, "protectedReviewCalls":1,
        "reason":"Owned report fixture; no jobs or provider requests"
    }), &ctx, None).unwrap().authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(approval, &ctx, None)
        .unwrap();
    let receipt = load_investigation_report(&workspace, "rule-report").unwrap();
    let value = serde_json::to_value(&receipt).unwrap();
    let selection = &value["scanSelection"][0];
    assert_eq!(selection["parameters"]["semgrepConfig"], selectors);
    assert_eq!(selection["parameters"]["tasks"], json!(["semgrep"]));
    assert_eq!(selection["parameters"]["semgrepJobs"], 1);
    assert_eq!(selection["parameters"]["semgrepTimeoutMs"], 60000);
    assert!(selection.get("caseId").is_none());
    assert!(selection["parameters"].get("threatModelRef").is_none());
    assert!(selection.get("ruleContentHashes").is_none());
    assert_eq!(receipt.occurrence.completed, 0);
    assert!(receipt.attempts.is_empty());
    let preview = preview_workspace_findings_export(
        &workspace,
        WorkspaceExportFormat::Json,
        &WorkspaceExportOptions::default().with_campaign(Some("rule-report".into())),
    )
    .unwrap();
    assert_eq!(
        preview.investigation.unwrap()["scanSelection"],
        value["scanSelection"]
    );
}
