//! A real accepted boundary must survive the report's shared export boundary.
use super::*;

fn context<'a>(
    workspace: &'a WorkspaceTarget,
    config: &'a crate::V2Config,
) -> crate::ToolExecutionContext<'a> {
    crate::ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

fn draft() -> ScanScopeDraft {
    serde_json::from_value(json!({
        "schemaVersion":1,
        "scopes":[
            {"id":"app","name":"Application","paths":["app"],"rationale":"Review application source","sharedDependencies":["integration"],"openQuestions":[]},
            {"id":"docs","name":"Documentation","paths":["README.md"],"rationale":"Keep loose root files visible","sharedDependencies":[],"openQuestions":[]},
            {"id":"integration","name":"Shared library","paths":["shared"],"rationale":"Shared dependency","sharedDependencies":[],"openQuestions":[]}
        ],
        "sharedScope":{"id":"shared-context","name":"Shared context","paths":["shared"],"rationale":"Context only","sharedDependencies":[],"openQuestions":[]},
        "sharedDiscovery":false,
        "exclusions":[{"path":"app/excluded.rs","reason":"Operator excluded fixture file"}]
    }))
    .unwrap()
}

fn fixture() -> (
    tempfile::TempDir,
    WorkspaceTarget,
    crate::V2Config,
    ScanScopeRef,
) {
    let root = tempfile::tempdir().unwrap();
    for directory in ["app", "shared"] {
        fs::create_dir_all(root.path().join(directory)).unwrap();
    }
    for file in [
        "app/main.rs",
        "app/excluded.rs",
        "shared/lib.rs",
        "README.md",
    ] {
        fs::write(
            root.path().join(file),
            "// Labeled source fixture. Never executed.\n",
        )
        .unwrap();
    }
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let proposed =
        create_scan_scope_proposal(&context(&workspace, &config), Some(draft())).unwrap();
    let accepted = accept_scan_scope_proposal(
        &context(&workspace, &config),
        &proposed.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            exclusions: true,
            overlapping_discovery: false,
        },
    )
    .unwrap();
    let reference = ScanScopeRef {
        proposal: accepted.reference,
        scope_id: "app".into(),
    };
    (root, workspace, config, reference)
}

fn plan(workspace: &WorkspaceTarget, config: &crate::V2Config, reference: &ScanScopeRef) {
    compile_scan_batch_plan(ScanBatchPlanSpec {
        root: workspace.root(),
        batch_id: Some("scoped-report".into()),
        trials: 3,
        requested_workers: 1,
        gate_policy: ScanBatchGatePolicy::default(),
        prepared_input: json!({"taskMode":"manual","tasks":["secret-scan"],"scanScopeRef":reference,"threatModelRef":null}),
        config,
        registry: &ModuleRegistry::with_v2_builtins(),
    })
    .unwrap();
}

fn export_result(
    workspace: &WorkspaceTarget,
    config: &crate::V2Config,
) -> anyhow::Result<serde_json::Value> {
    let registry = ModuleRegistry::with_v2_builtins();
    let ctx = context(workspace, config);
    let prepared = registry
        .prepare_dispatch_input(
            "workspace:export-findings",
            json!({"output":"scoped-report.json","campaignId":"scoped-report","allowEmpty":true}),
            &ctx,
            None,
        )?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

fn export(workspace: &WorkspaceTarget, config: &crate::V2Config) -> serde_json::Value {
    let result = export_result(workspace, config).unwrap();
    serde_json::from_slice(
        &fs::read(result["data"]["investigationReceiptPath"].as_str().unwrap()).unwrap(),
    )
    .unwrap()
}

#[test]
fn shared_export_retains_selected_scope_and_accepted_proposal_limits() {
    let (_root, workspace, config, reference) = fixture();
    plan(&workspace, &config, &reference);
    let receipt = export(&workspace, &config);
    assert_eq!(receipt["scope"]["scanScopeRef"], json!(reference));
    let proposal = &receipt["scope"]["acceptedScopeProposal"];
    assert_eq!(proposal["reference"], json!(reference.proposal));
    assert_eq!(proposal["coverage"]["discoveryMembers"]["app"]["total"], 1);
    assert_eq!(
        proposal["coverage"]["contextMembers"]["shared-context"]["total"],
        1
    );
    assert_eq!(proposal["coverage"]["excludedFiles"]["total"], 1);
    assert_eq!(
        proposal["record"]["draft"]["exclusions"][0]["reason"],
        "Operator excluded fixture file"
    );
    assert_eq!(receipt["occurrence"]["pending"], 3);
    assert!(receipt["allowance"].is_null());
}

#[test]
fn historical_report_keeps_original_scope_after_source_changes() {
    let (root, workspace, config, reference) = fixture();
    plan(&workspace, &config, &reference);
    let original = load_scan_scope_proposal(&workspace, &reference.proposal).unwrap();
    fs::write(
        root.path().join("app/main.rs"),
        "// Changed fixture source.\n",
    )
    .unwrap();
    fs::write(root.path().join("app/new.rs"), "// New fixture source.\n").unwrap();
    let receipt = export(&workspace, &config);
    assert_eq!(receipt["scope"]["acceptedScopeProposal"], json!(original));
    assert_eq!(receipt["occurrence"]["completed"], 0);
    assert_eq!(receipt["occurrence"]["pending"], 3);
}

#[test]
fn damaged_scope_evidence_does_not_replace_a_previous_export() {
    let (_root, workspace, config, reference) = fixture();
    plan(&workspace, &config, &reference);
    export(&workspace, &config);
    let output = workspace.root().join("scoped-report.json");
    let previous = fs::read(&output).unwrap();
    let scope_root = workspace_state_dir(workspace.root()).join("scan-scopes");
    fs::remove_dir_all(scope_root).unwrap();
    let error = export_result(&workspace, &config).unwrap_err();
    assert!(format!("{error:#}").contains("scope evidence is unavailable"));
    assert_eq!(fs::read(output).unwrap(), previous);
}

#[test]
fn receipt_write_failure_leaves_the_previous_export_intact() {
    let (_root, workspace, config, reference) = fixture();
    plan(&workspace, &config, &reference);
    export(&workspace, &config);
    let output = workspace.root().join("scoped-report.json");
    let receipt = workspace
        .root()
        .join("scoped-report.json.investigation.json");
    fs::write(&output, "previous export").unwrap();
    fs::remove_file(&receipt).unwrap();
    fs::create_dir(&receipt).unwrap();
    assert!(export_result(&workspace, &config).is_err());
    assert_eq!(fs::read_to_string(&output).unwrap(), "previous export");
}

fn record_confirmed_outside_study(workspace: &WorkspaceTarget) {
    use crate::findings::{ReviewDecision, ReviewDecisionVerdict, Severity, TriageAuthor};
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("outside-study", workspace.root(), "running")
        .unwrap();
    let finding = Finding::new_tool(
        "semgrep",
        "labeled.rule",
        "app/main.rs",
        1,
        None,
        Severity::High,
        "Labeled finding outside the study",
    );
    let id = store.insert_finding("outside-study", &finding).unwrap();
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "labeled fixture decision".into(),
                dismiss_reason: None,
                actor: Some("operator".into()),
            },
        )
        .unwrap();
}

fn confirmed_sarif(
    workspace: &WorkspaceTarget,
    config: &crate::V2Config,
    input: serde_json::Value,
) -> serde_json::Value {
    let registry = ModuleRegistry::with_v2_builtins();
    let ctx = context(workspace, config);
    let prepared = registry
        .prepare_dispatch_input("report:sarif", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = crate::ToolExecutionContext {
        findings_store: Some(&store),
        ..ctx
    };
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    serde_json::from_slice(&fs::read(result["data"]["path"].as_str().unwrap()).unwrap()).unwrap()
}

#[test]
fn confirmed_sarif_selects_only_the_study_and_embeds_its_receipt() {
    let (_root, workspace, config, reference) = fixture();
    plan(&workspace, &config, &reference);
    record_confirmed_outside_study(&workspace);

    let history = confirmed_sarif(&workspace, &config, json!({"output": "all.sarif"}));
    assert_eq!(history["runs"][0]["results"].as_array().unwrap().len(), 1);

    let study = confirmed_sarif(
        &workspace,
        &config,
        json!({"output": "study.sarif", "campaignId": "scoped-report"}),
    );
    let run = &study["runs"][0];
    assert!(run["results"].as_array().unwrap().is_empty());
    let receipt = &run["properties"]["kuzushiExport"]["investigation"];
    assert_eq!(receipt["campaignId"], "scoped-report");
    assert_eq!(receipt["scope"]["scanScopeRef"], json!(reference));
}
