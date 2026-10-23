use super::*;
use kuzushi_core::{
    capabilities::campaign::{execute_study_plan, StudyPlanReceipt},
    ToolExecutionContext, V2Config, WorkspaceTarget,
};
use serde_json::json;

fn fixture() -> (tempfile::TempDir, BatchScanConfig, Value) {
    fixture_with_engine("agentic")
}

fn fixture_with_engine(engine: &str) -> (tempfile::TempDir, BatchScanConfig, Value) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("note.md"), "Owned inert example\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let output = execute_study_plan(
        &json!({"campaignId":"owned-approval","investigationId":"owned",
        "scanInput":{"taskMode":"manual","tasks":[engine],"threatModelRef":null}}),
        &ctx,
    )
    .unwrap();
    let receipt: StudyPlanReceipt = serde_json::from_value(output["data"].clone()).unwrap();
    let input = json!({"campaignId":receipt.campaign_id,"campaignPlanSha256":receipt.plan_sha256,
        "campaignJobs":receipt.job_count});
    let mut draft = BatchScanConfig::load(root.path(), None);
    draft.study.record_receipt(receipt);
    (root, draft, input)
}

#[test]
fn summary_uses_frozen_conditions_instead_of_mutable_form_fields() {
    let (_root, mut config, input) = fixture();
    config.trials = 9;
    config.effective_workers = 8;
    config.study.scan_input = Some(json!({"tasks":["secret-scan"],"paths":["other"]}));
    let lines = summary(&config, &input).unwrap().details.join("\n");
    assert!(lines.contains("Scan: 3 passes · 1 worker(s)"));
    assert!(lines.contains("Engines: agentic"));
    assert!(lines.contains("Scope: whole repository"));
    assert!(lines.contains("Threat context: explicitly omitted"));
    assert!(lines.contains("Execution model: openai-oauth:gpt-5.5"));
    assert!(!lines.contains("secret-scan") && !lines.contains("other"));
    assert!(!lines.contains("openai-codex:"));
    assert_eq!(
        config
            .study
            .receipt
            .as_ref()
            .unwrap()
            .equivalence
            .components
            .model
            .as_deref(),
        Some("openai-codex:gpt-5.5")
    );
}

#[test]
fn native_work_does_not_present_the_configured_model_as_an_execution_model() {
    let (_root, config, input) = fixture_with_engine("license-scan");
    let receipt = config.study.receipt.as_ref().unwrap();
    assert!(receipt.equivalence.components.model.is_none());
    let text = summary(&config, &input).unwrap().details.join("\n");
    assert!(text.contains("Execution model: none; this frozen discovery uses native engines"));
    assert!(!text.contains("gpt-5.5"));
}

#[test]
fn missing_recorded_model_is_disclosed_without_substitution() {
    assert!(execution_model_line(Some("")).contains("unrecorded"));
    assert_eq!(
        execution_model_line(Some("operator-selected-model")),
        "Execution model: operator-selected-model"
    );
}

#[test]
fn compact_overview_keeps_every_frozen_model_and_discloses_missing_values() {
    let models = [
        Some("model-a"),
        None,
        Some("model-a"),
        Some(""),
        Some("model-b"),
    ];
    let lines = model_overview(&models);
    assert_eq!(
        lines,
        [
            "Model: model-a",
            "Model: none (native engines)",
            "Model: unrecorded; inspect plan details",
            "Model: model-b"
        ]
    );
}

#[test]
fn overview_uses_frozen_work_and_keeps_receipts_in_details() {
    let (_root, mut config, input) = fixture();
    config.trials = 25;
    config.effective_workers = 8;
    let preview = summary(&config, &input).unwrap();
    assert!(preview
        .overview
        .iter()
        .any(|line| line == "Scan: 3 passes · 1 worker(s)"));
    assert!(preview
        .overview
        .iter()
        .any(|line| line == "Model: openai-oauth:gpt-5.5"));
    assert!(!preview.overview.join("\n").contains("Threat context"));
    assert!(preview
        .details
        .join("\n")
        .contains("Threat context: explicitly omitted"));
}

#[test]
fn semgrep_time_allowance_is_bound_to_the_frozen_work() {
    let (_root, mut config, input) = fixture_with_engine("semgrep");
    config.study.scan_input = Some(json!({"tasks":["semgrep"],"semgrepTimeoutMs":60000}));
    let text = summary(&config, &input).unwrap().details.join("\n");
    assert!(text.contains("1800000 ms per job"));
    assert!(!text.contains("60000 ms per job"));
    assert!(text.contains("Source authentication is separate"));
}

#[test]
fn semgrep_time_allowance_names_explicit_limits_and_conditional_selection() {
    assert!(semgrep_time_line(&json!({"tasks":["license-scan"]})).is_empty());
    assert!(
        semgrep_time_line(&json!({"tasks":["semgrep"],"semgrepTimeoutMs":60000}))
            .contains("60000 ms per job")
    );
    assert!(semgrep_time_line(&json!({"taskMode":"auto"})).contains("when selected"));
    assert!(
        semgrep_time_line(&json!({"tasks":["semgrep"],"semgrepJobs":4}))
            .contains("Scan workers within each job: 4")
    );
    assert!(semgrep_time_line(&json!({"tasks":["semgrep"]}))
        .contains("Scan workers within each job: 1"));
}

#[test]
fn mismatched_identity_digest_and_workload_are_disclosed() {
    let (_root, config, input) = fixture();
    for (key, value) in [
        ("campaignId", json!("other")),
        ("campaignPlanSha256", json!("sha256:other")),
        ("campaignJobs", json!(2)),
    ] {
        let mut changed = input.clone();
        changed[key] = value;
        let lines = summary(&config, &changed).unwrap().overview;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("differs from the displayed plan"));
    }
}

#[test]
fn missing_context_and_automatic_engines_do_not_look_like_known_omissions() {
    assert!(context_line(&json!({})).contains("no explicit reference"));
    assert!(engine_line(&json!({"taskMode":"auto"})).contains("automatic selection"));
    assert!(engine_line(&json!({"taskMode":"manual"})).contains("not recorded"));
    assert_eq!(
        scope_line(&json!({"scanScopeRef":{"scopeId":"worker"}})),
        "Scope: accepted boundary worker"
    );
    assert_eq!(
        scope_line(&json!({"paths":["service"]})),
        "Scope: 1 selected path(s): service"
    );
}

#[test]
fn path_summaries_are_bounded_and_disclose_omissions() {
    let input = json!({"paths":["a","b","c","d"]});
    let text = scope_line(&input);
    assert!(text.contains("4 selected path(s): a, b, c"));
    assert!(text.contains("further paths remain in the frozen inputs"));
    assert!(bounded_label(&"世".repeat(200)).ends_with('…'));
    assert_eq!(bounded_label(&"世".repeat(200)).chars().count(), 97);
    assert!(scope_line(&json!({"scanScopeRef":{}})).contains("unavailable"));
    assert_eq!(
        scope_line(&json!({"shard":"worker"})),
        "Scope: selected shard worker"
    );
}

#[test]
fn an_existing_context_generation_does_not_hide_the_selected_scan_plan() {
    let (_root, mut config, input) = fixture();
    let context: ContextStudyReceipt = serde_json::from_value(json!({"campaignId":"older-map",
        "investigationId":"owned","planSha256":"sha256:older","sourceIdentity":"owned-source",
        "configSha256":"owned-config","model":"openai-codex:gpt-5.5","input":{},"preparationJobs":[]})).unwrap();
    config.context_generation = Some(crate::app::StudyContextGeneration {
        receipt: Some(context),
        ..Default::default()
    });
    assert!(summary(&config, &input)
        .unwrap()
        .details
        .join("\n")
        .contains("Scan: 3 passes"));
    let context_input =
        json!({"campaignId":"older-map","campaignPlanSha256":"sha256:older","campaignJobs":1});
    assert!(summary(&config, &context_input)
        .unwrap()
        .details
        .join("\n")
        .contains("Execution model: openai-oauth:gpt-5.5"));
    assert!(summary(&config, &context_input)
        .unwrap()
        .details
        .join("\n")
        .contains("Context: 1 fixed jobs"));
}

#[test]
fn matrix_and_scope_previews_keep_each_frozen_case_distinct() {
    let (_root, config, _input) = fixture();
    let receipt = config.study.receipt.as_ref().unwrap();
    let cases = vec![
        FrozenContextCase {
            id: "first".into(),
            label: "First boundary".into(),
            passes: 2,
            base_input: receipt.scan_input.clone(),
            equivalence: receipt.equivalence.clone(),
            omission_scope_sha256: None,
        },
        FrozenContextCase {
            id: "second".into(),
            label: "Second boundary".into(),
            passes: 3,
            base_input: json!({"taskMode":"manual","tasks":["secret-scan"],"scanScopeRef":{"scopeId":"second"},"threatModelRef":null}),
            equivalence: receipt.equivalence.clone(),
            omission_scope_sha256: None,
        },
    ];
    for kind in ["scopes", "context cases"] {
        let summary = case_summary("cases", "sha256:cases", 5, 1, kind, &cases);
        let lines = summary.lines.join("\n");
        assert!(lines.contains(&format!("2 {kind} · 5 fixed jobs · 1 worker(s)")));
        assert!(
            lines.contains("First boundary: 2 passes")
                && lines.contains("Second boundary: 3 passes")
        );
        assert!(
            lines.contains("Engines: secret-scan")
                && lines.contains("Scope: accepted boundary second")
        );
    }
}

#[test]
fn review_preview_uses_the_frozen_strategy_and_workload() {
    let (_root, mut config, _input) = fixture();
    // Synthetic presenter fixture, never approved or executed.
    let receipt = serde_json::from_value(json!({"schemaVersion":1,"campaignId":"review",
        "investigationId":"owned","planSha256":"sha256:review","sourceIdentity":"owned-source",
        "configSha256":"owned-config","model":"openai-codex:gpt-5.5",
        "input":{"strategy":"standard","threatModelRef":null},"findings":[]}))
    .unwrap();
    config.study.review_receipt = Some(receipt);
    let input =
        json!({"campaignId":"review","campaignPlanSha256":"sha256:review","campaignJobs":1});
    let text = summary(&config, &input).unwrap().details.join("\n");
    assert!(text.contains("Review: 0 frozen observations · 1 worker"));
    assert!(text.contains("Strategy: standard"));
    assert!(text.contains("Execution model: openai-oauth:gpt-5.5"));
    assert!(text.contains("Threat context: explicitly omitted"));
    assert!(!text.contains("Scan: 3 passes"));
}

#[test]
fn context_approval_keeps_frozen_inheritance_membership_and_inventory_extent() {
    let (_root, mut config, _) = fixture();
    let reference = kuzushi_core::ThreatModelRef {
        model_id: kuzushi_core::ThreatModelId::new(),
        revision_id: kuzushi_core::ThreatModelRevisionId::new(),
        sha256: "c".repeat(64),
    };
    let model = config
        .study
        .receipt
        .as_ref()
        .unwrap()
        .equivalence
        .components
        .model
        .clone()
        .unwrap();
    let receipt: ContextStudyReceipt = serde_json::from_value(json!({
        "campaignId":"evidence-context","investigationId":"owned",
        "planSha256":"sha256:frozen","sourceIdentity":"owned-source",
        "configSha256":"owned-config","model":model,"preparationJobs":[],
        "input":{"sourcePaths":[" app /lib.py","app/lib.py"],"inheritedContextRef":reference},
        "sourceInventory":{"enumerationComplete":false,"selectedMembershipKnown":true,
            "truncation":{"reason":"entry cap reached"}}
    }))
    .unwrap();
    config.context_generation = Some(crate::app::StudyContextGeneration {
        receipt: Some(receipt),
        context_input: json!({"inheritedContextRef":null,"sourcePaths":["unfrozen.py"]}),
        ..Default::default()
    });
    let approval = json!({"campaignId":"evidence-context","campaignPlanSha256":"sha256:frozen","campaignJobs":1});
    let text = summary(&config, &approval).unwrap().details.join("\n");
    assert!(text.contains("Threat context: inherited"));
    assert!(text.contains(reference.revision_id.as_str()));
    assert!(text.contains("Evidence: 2 exact files (quoted)"));
    assert!(text.contains("\" app /lib.py\"") && text.contains("\"app/lib.py\""));
    assert!(text.contains("Repository enumeration: partial; all selected files are recorded"));
    assert!(text.contains("entry cap reached"));
    assert!(!text.contains("legacy selection") && !text.contains("unfrozen.py"));
}
