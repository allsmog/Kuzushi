use super::*;
use crate::workspace::{
    accept_scan_scope_proposal, create_scan_scope_proposal, ProposedScanScope, ScanScopeDraft,
    ScopeCoverageApproval, WorkspaceTarget,
};

fn boundary(id: &str) -> ProposedScanScope {
    ProposedScanScope {
        id: id.into(),
        name: id.into(),
        paths: vec![id.into()],
        rationale: "Owned fixture scope".into(),
        shared_dependencies: Vec::new(),
        open_questions: Vec::new(),
    }
}

#[test]
fn accepted_scopes_compile_six_frozen_jobs_and_reject_tampering() {
    let root = tempfile::tempdir().unwrap();
    for id in ["app", "other", "shared"] {
        std::fs::create_dir(root.path().join(id)).unwrap();
        std::fs::write(
            root.path().join(id).join("owned.rs"),
            "// Labeled source fixture\n",
        )
        .unwrap();
    }
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let draft = ScanScopeDraft {
        schema_version: 1,
        scopes: vec![boundary("app"), boundary("other"), boundary("shared")],
        shared_scope: None,
        shared_discovery: false,
        exclusions: Vec::new(),
    };
    let proposal = create_scan_scope_proposal(&ctx, Some(draft)).unwrap();
    let accepted = accept_scan_scope_proposal(
        &ctx,
        &proposal.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            exclusions: false,
            overlapping_discovery: false,
        },
    )
    .unwrap();
    let input = json!({"campaignId":"owned-scope-study","scopeProposalRef":accepted.reference,"scopeCases":[{"scopeId":"app"},{"scopeId":"other"}],"scanInput":{"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":null,"scanContextRef":null}});
    let result = ModuleRegistry::with_v2_builtins()
        .execute_tool("campaign:study", input.clone(), &ctx)
        .unwrap();
    let receipt: ScopeStudyReceipt = serde_json::from_value(result["data"].clone()).unwrap();
    assert_eq!(receipt.job_count, 6);
    assert_eq!(receipt.workers, 1);
    assert_eq!(receipt.scope_study.unplanned_scope_ids, vec!["shared"]);
    assert!(!campaign_dir(root.path(), "owned-scope-study")
        .join("queue.json")
        .exists());
    let mut usage_input = input;
    usage_input["campaignId"] = json!("owned-resource-study");
    usage_input["resourceBaselineCampaignId"] = json!("owned-scope-study");
    let usage_result = ModuleRegistry::with_v2_builtins()
        .execute_tool("campaign:study", usage_input, &ctx)
        .unwrap();
    let usage_receipt: ScopeStudyReceipt =
        serde_json::from_value(usage_result["data"].clone()).unwrap();
    let evidence = usage_receipt.resource_evidence.as_ref().unwrap();
    assert_eq!(evidence.cases.len(), 2);
    assert!(evidence.project(1).unwrap().provider_calls.is_none());
    let mut changed_usage =
        approved_work::read_bounded_plan(root.path(), "owned-resource-study").unwrap();
    changed_usage["resourceEvidence"]["cases"][0]["equivalenceSha256"] = json!("changed");
    assert!(validate_scope_study_plan("owned-resource-study", &changed_usage).is_err());
    let plan = approved_work::read_bounded_plan(root.path(), "owned-scope-study").unwrap();
    assert_eq!(plan["jobs"][3]["caseId"], "other");
    assert_eq!(plan["jobs"][3]["input"]["scanScopeRef"]["scopeId"], "other");
    let mut changed = plan.clone();
    changed["jobs"][0]["input"]["scanScopeRef"]["scopeId"] = json!("shared");
    assert!(validate_scope_study_plan("owned-scope-study", &changed).is_err());
    let mut extra = plan;
    extra["jobs"]
        .as_array_mut()
        .unwrap()
        .push(json!({"tool":"sast:scan","input":{}}));
    assert!(validate_scope_study_plan("owned-scope-study", &extra).is_err());
    let registry = ModuleRegistry::with_v2_builtins();
    let approval = json!({"campaignId":"owned-scope-study","investigationId":"scope-accounting","campaignPlanSha256":receipt.plan_sha256,
        "campaignJobs":6,"maxJobAttempts":1,"expectedRevision":0,"model":"openai-codex:gpt-5.5","maxProviderCalls":8,"protectedReviewCalls":2,"reason":"Owned source-only planning fixture"});
    let prepared = registry
        .prepare_dispatch_input("campaign:approve-allowance", approval.clone(), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    let store = crate::SpendLimiter::read_campaign_allowance(
        &workspace.findings_db_path(),
        "owned-scope-study",
    )
    .unwrap()
    .unwrap();
    assert_eq!(store.committed_calls, 0);
    assert_eq!(store.work_plan.as_ref().unwrap().jobs.len(), 6);
    let findings = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
    let occurrence = crate::findings::derive_scope_study_occurrence_report(
        root.path(),
        "owned-scope-study",
        &findings,
    )
    .unwrap();
    assert_eq!(occurrence.cases.len(), 2);
    assert!(occurrence
        .cases
        .iter()
        .all(|scope| scope.occurrence.planned == 3
            && scope.occurrence.pending == 3
            && scope.occurrence.completed == 0));
    let report =
        crate::workspace::load_investigation_report_document(&workspace, "owned-scope-study")
            .unwrap();
    assert_eq!(report.work_counts().planned, 6);
    assert_eq!(report.summary().finding_count, 0);
    std::fs::write(
        root.path().join("app/owned.rs"),
        "// Changed owned source\n",
    )
    .unwrap();
    let mut changed = approval;
    changed["expectedRevision"] = json!(1);
    let prepared = registry
        .prepare_dispatch_input("campaign:approve-allowance", changed, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    assert!(registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .is_err());
}
