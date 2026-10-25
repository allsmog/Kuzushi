use super::*;
use kuzushi_core::capabilities::campaign::{
    ContextMatrixReceipt, ScopeStudyDraft, ScopeStudyReceipt,
};
use kuzushi_core::workspace::{
    accept_scan_scope_proposal, create_scan_scope_proposal, ProposedScanScope, ScanScopeDraft,
    ScanScopeProposalRef, ScopeCoverageApproval,
};
use kuzushi_core::ModuleRegistry;

fn accepted_scopes(ctx: &ToolExecutionContext<'_>) -> ScanScopeProposalRef {
    let scopes = [("first", "source.rs"), ("second", "extra.rs")]
        .into_iter()
        .map(|(id, file)| ProposedScanScope {
            id: id.into(),
            name: id.into(),
            paths: vec![file.into()],
            rationale: "Owned inert source".into(),
            shared_dependencies: Vec::new(),
            open_questions: Vec::new(),
        })
        .collect();
    let draft = ScanScopeDraft {
        schema_version: 1,
        scopes,
        shared_scope: None,
        shared_discovery: false,
        exclusions: Vec::new(),
    };
    let proposal = create_scan_scope_proposal(ctx, Some(draft)).unwrap();
    accept_scan_scope_proposal(
        ctx,
        &proposal.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            exclusions: false,
            overlapping_discovery: false,
        },
    )
    .unwrap()
    .reference
}

fn scoped_fixture(history: bool) -> (tempfile::TempDir, BatchScanConfig) {
    let (root, mut draft) = fixture_with_engine("secret-scan");
    std::fs::write(root.path().join("extra.rs"), "// Owned inert source.\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let reference = accepted_scopes(&ctx);
    let mut input = json!({"campaignId":"native-scopes","scopeProposalRef":reference,
        "scopeCases":[{"scopeId":"first"},{"scopeId":"second"}],
        "scanInput":{"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":null,"scanContextRef":null}});
    let registry = ModuleRegistry::with_v2_builtins();
    let mut output = registry
        .execute_tool("campaign:study", input.clone(), &ctx)
        .unwrap();
    if history {
        input["resourceBaselineCampaignId"] = json!("native-scopes");
        input["campaignId"] = json!("native-scopes-history");
        output = registry
            .execute_tool("campaign:study", input, &ctx)
            .unwrap();
    }
    let receipt: ScopeStudyReceipt = serde_json::from_value(output["data"].clone()).unwrap();
    draft.study.scope_draft = Some(ScopeStudyDraft {
        proposal_ref: receipt.scope_study.proposal_ref.clone(),
        cases: receipt.scope_study.selections.clone(),
    });
    draft.prior_campaign_id = receipt
        .resource_evidence
        .as_ref()
        .map(|value| value.baseline_campaign_id.clone());
    draft.study.scope_receipt = Some(receipt);
    (root, draft)
}

fn context_case(
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
    id: &str,
) -> serde_json::Value {
    let output = registry.execute_tool("threat-model:import", json!({"activate":false,"label":id,
        "document":{"version":"1","methodology":"stride","title":id,"systemContext":"Owned inert source, never executed.",
            "dfd":{"nodes":[{"id":"source","name":"Source","type":"data-store","trustZone":"repository"}],
                "flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}}), ctx).unwrap();
    json!({"id":id,"label":id,"threatModelRef":output["data"]["modelRef"]})
}

fn matrix_fixture() -> (tempfile::TempDir, BatchScanConfig) {
    let (root, mut draft) = fixture_with_engine("license-scan");
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let cases = ["baseline", "alternative"].map(|id| context_case(&registry, &ctx, id));
    let output = registry
        .execute_tool(
            "campaign:study",
            json!({"campaignId":"native-contexts",
        "baselineCaseId":"baseline","contextCases":cases,
        "scanInput":{"taskMode":"manual","tasks":["license-scan"]}}),
            &ctx,
        )
        .unwrap();
    let receipt: ContextMatrixReceipt = serde_json::from_value(output["data"].clone()).unwrap();
    draft.study.matrix.cases = receipt
        .matrix
        .cases
        .iter()
        .map(
            |case| kuzushi_core::capabilities::campaign::ContextCaseInput {
                id: case.id.clone(),
                label: case.label.clone(),
                passes: case.passes,
                threat_model_ref: case.base_input["threatModelRef"].clone(),
            },
        )
        .collect();
    draft.study.matrix.receipt = Some(receipt);
    (root, draft)
}

fn resource_text(config: &BatchScanConfig) -> String {
    crate::ui_view_models::study_config::study_resource_lines(config).join("\n")
}

#[test]
fn frozen_native_scopes_need_no_model_requests_and_preserve_existing_spending() {
    let (_root, mut config) = scoped_fixture(false);
    config.trials = 9;
    config.study.scan_input = Some(json!({"tasks":["agentic"]}));
    let before = config.clone();
    let text = resource_text(&config);
    assert!(
        text.contains("6 native jobs · 0 model-provider requests"),
        "{text}"
    );
    assert!(text.contains("Local compute and scanner-service costs are not estimated"));
    assert!(text.contains("Protected Review limit: 2 calls within the total"));
    assert!(!text.contains("Provider requests: not estimated"));
    assert_eq!(config, before);
}

#[test]
fn frozen_native_context_matrix_needs_no_model_calibration() {
    let (_root, config) = matrix_fixture();
    let before = config.clone();
    let text = resource_text(&config);
    assert!(
        text.contains("6 native jobs · 0 model-provider requests"),
        "{text}"
    );
    assert!(!text.contains("No calibrated whole-matrix estimate"));
    assert_eq!(config, before);
}

#[test]
fn uncalibrated_prior_scope_usage_does_not_hide_a_frozen_model_free_contract() {
    let (_root, config) = scoped_fixture(true);
    assert!(config
        .study
        .scope_receipt
        .as_ref()
        .unwrap()
        .resource_evidence
        .is_some());
    let before = config.clone();
    assert!(resource_text(&config).contains("6 native jobs · 0 model-provider requests"));
    assert_eq!(config, before);
}

#[test]
fn any_model_or_runtime_case_withholds_the_zero_request_claim() {
    let (_root, original) = scoped_fixture(false);
    for input in [json!({"tasks":["agentic"]}), json!({"triage":true})] {
        let mut config = original.clone();
        config
            .study
            .scope_receipt
            .as_mut()
            .unwrap()
            .scope_study
            .cases[1]
            .base_input = input;
        assert!(!resource_text(&config).contains("0 model-provider requests"));
    }
    let mut config = original;
    config
        .study
        .scope_receipt
        .as_mut()
        .unwrap()
        .scope_study
        .cases[1]
        .equivalence
        .components
        .model = Some("recorded-model".into());
    assert!(!resource_text(&config).contains("0 model-provider requests"));
}

#[test]
fn empty_inconsistent_and_overflowed_scope_counts_never_look_free() {
    let (_root, original) = scoped_fixture(false);
    let receipt = original.study.scope_receipt.as_ref().unwrap();
    let mut bad_count = receipt.clone();
    bad_count.job_count += 1;
    let mut empty = receipt.clone();
    empty.scope_study.cases.clear();
    let mut zero_pass = receipt.clone();
    zero_pass.scope_study.cases[0].passes = 0;
    zero_pass.job_count = 3;
    let mut overflow = receipt.clone();
    overflow.scope_study.cases[0].passes = usize::MAX;
    for receipt in [bad_count, empty, zero_pass, overflow] {
        let mut config = original.clone();
        config.study.scope_receipt = Some(receipt);
        assert!(!resource_text(&config).contains("0 model-provider requests"));
    }
}

#[test]
fn unfrozen_cases_never_borrow_a_zero_estimate_from_an_older_single_plan() {
    let (_root, mut scope) = scoped_fixture(false);
    scope.study.scope_receipt = None;
    assert!(!resource_text(&scope).contains("0 model-provider requests"));
    let (_root, mut matrix) = matrix_fixture();
    matrix.study.matrix.receipt = None;
    assert!(!resource_text(&matrix).contains("0 model-provider requests"));
}

#[test]
fn an_unrecorded_model_does_not_hide_a_runtime_backed_matrix_case() {
    let (_root, mut config) = matrix_fixture();
    let case = &mut config.study.matrix.receipt.as_mut().unwrap().matrix.cases[1];
    case.base_input["tasks"] = json!(["agentic"]);
    assert!(!resource_text(&config).contains("0 model-provider requests"));
}
