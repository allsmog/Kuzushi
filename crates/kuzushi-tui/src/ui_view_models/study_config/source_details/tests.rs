use super::*;
use kuzushi_core::{
    capabilities::campaign::*, modules::ToolExecutionContext, V2Config, WorkspaceTarget,
};
use serde_json::json;

fn planned_study() -> (tempfile::TempDir, BatchScanConfig) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "// Owned source identity fixture.\n",
    )
    .unwrap();
    let config = V2Config::default();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let result = execute_study_plan(&json!({"campaignId":"source-view-test", "scanInput":{"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":null,"scanContextRef":null}}), &ctx).unwrap();
    let receipt: StudyPlanReceipt = serde_json::from_value(result["data"].clone()).unwrap();
    let mut form = BatchScanConfig::load(root.path(), None);
    form.cursor = 3;
    form.study.record_receipt(receipt);
    (root, form)
}

#[test]
fn source_overview_keeps_identity_and_omissions_without_the_options_document() {
    let (_root, config) = planned_study();
    let text = source_lines(&config).join("\n");
    assert!(text.contains("Source content: tree:"));
    assert!(text.contains("Git SHA unavailable"));
    assert!(text.contains("explicitly omitted"));
    assert!(!text.contains("maxInventoryFiles"));
    assert!(!text.contains("RECORDED ENGINE INPUTS"));
}

#[test]
fn explicit_options_preserve_the_complete_prepared_input_and_context_text() {
    let (_root, mut config) = planned_study();
    config.source_view.selected = StudySourceView::Options;
    let receipt = config.study.receipt.as_mut().unwrap();
    receipt.supporting_context = Some("Operator line one\nOperator line two".into());
    let expected = serde_json::to_string_pretty(&receipt.scan_input).unwrap();
    let text = source_lines(&config).join("\n");
    assert!(text.contains(&expected));
    assert!(text.contains("Operator line one\nOperator line two"));
    assert!(text.contains("Other engines do not consume it"));
}

#[test]
fn readable_settings_use_current_metadata_without_mutating_the_frozen_plan_or_form() {
    let (root, mut config) = planned_study();
    let mut app = crate::app::ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    config.source_view.selected = StudySourceView::Settings;
    let before = config.clone();
    app.router.campaign_mut().batch_scan_config = Some(config);
    let projected = crate::ui_view_models::study_config::study_projection(&app).unwrap();
    let text = source_lines(&projected).join("\n");
    let spec = projected
        .source_option_specs
        .iter()
        .find(|spec| spec.name == "maxInventoryFiles")
        .unwrap();
    assert!(text.contains("PREPARED SETTINGS"));
    assert!(text.contains("Max inventory files (maxInventoryFiles)"));
    assert!(text.contains(&spec.description));
    assert!(text.contains("current tool descriptors"));
    assert_eq!(
        app.router.campaign().batch_scan_config.as_ref().unwrap(),
        &before
    );
    assert!(!root
        .path()
        .join(".kuzushi/v3/campaigns/source-view-test/queue.json")
        .exists());
}

#[test]
fn frozen_inputs_show_recorded_facts_without_promoting_health_or_readiness() {
    let (_root, mut config) = planned_study();
    config.source_view.selected = StudySourceView::Inputs;
    config
        .study
        .receipt
        .as_mut()
        .unwrap()
        .equivalence
        .components
        .engine_identity
        .requested_selection = json!({"executables":[{"name":"owned-engine","path":"/owned/tool","sha256":"sha256:owned"}]});
    let text = source_lines(&config).join("\n");
    assert!(text.contains("Case: Study"));
    assert!(text.contains("/owned/tool") && text.contains("sha256:owned"));
    assert!(text.contains("do not establish engine health"));
    assert!(!text.contains("maxInventoryFiles"));
}

#[test]
fn missing_plans_never_present_draft_inputs_as_frozen() {
    let root = tempfile::tempdir().unwrap();
    let mut config = BatchScanConfig::load(root.path(), None);
    config.study.scan_input = Some(json!({"tasks":["owned-unprepared"]}));
    for view in [
        StudySourceView::Inputs,
        StudySourceView::Settings,
        StudySourceView::Options,
    ] {
        config.source_view.selected = view;
        let text = source_lines(&config).join("\n");
        assert!(text.contains("No frozen"));
        assert!(!text.contains("owned-unprepared"));
    }
}

#[test]
fn supplemental_context_distinguishes_omitted_legacy_missing_and_recorded_text() {
    assert!(supporting_context_summary(&json!({}), None).contains("legacy live"));
    assert!(
        supporting_context_summary(&json!({"scanContextRef":null}), None)
            .contains("explicitly omitted")
    );
    assert!(
        supporting_context_summary(&json!({"scanContextRef":{"object":{}}}), None)
            .contains("unavailable")
    );
    assert!(
        supporting_context_summary(&json!({"scanContextRef":{}}), Some("é"))
            .contains("2 bytes recorded")
    );
}

#[test]
fn matrix_cases_keep_their_own_executable_facts_and_exact_options() {
    let (_root, mut config) = planned_study();
    let receipt = config.study.receipt.take().unwrap();
    let mut cases = Vec::new();
    for label in ["Alpha", "Beta"] {
        let mut equivalence = receipt.equivalence.clone();
        equivalence.components.engine_identity.requested_selection = json!({"executables":[{"name":"owned-engine","path":format!("/owned/{label}"),"sha256":format!("sha256:{label}")}]});
        let mut input = receipt.scan_input.clone();
        input["semgrepBinary"] = json!(format!("/owned/{label}"));
        cases.push(FrozenContextCase {
            id: label.into(),
            label: label.into(),
            passes: 3,
            base_input: input,
            equivalence,
            omission_scope_sha256: None,
        });
    }
    config.study.matrix.receipt = Some(ContextMatrixReceipt {
        schema_version: 1,
        campaign_id: "presentation-matrix".into(),
        investigation_id: None,
        plan_path: receipt.plan_path,
        plan_sha256: receipt.plan_sha256,
        workers: 1,
        requested_workers: 1,
        worker_limitation: None,
        job_count: 6,
        supporting_context: None,
        resource_evidence: None,
        matrix: ContextMatrixMetadataV1 {
            schema_version: 1,
            baseline_case_id: "Alpha".into(),
            cases,
        },
    });
    config.source_view.selected = StudySourceView::Inputs;
    let inputs = source_lines(&config).join("\n");
    let (alpha, beta) = inputs.split_once("Case: Beta").unwrap();
    assert!(alpha.contains("/owned/Alpha") && !alpha.contains("/owned/Beta"));
    assert!(beta.contains("/owned/Beta") && !beta.contains("/owned/Alpha"));
    config.source_view.selected = StudySourceView::Options;
    let options = source_lines(&config).join("\n");
    let (alpha, beta) = options.split_once("Case: Beta").unwrap();
    assert!(alpha.contains("/owned/Alpha") && beta.contains("/owned/Beta"));
}

#[test]
fn plain_form_is_exhaustive_and_plain_reader_respects_the_selected_view() {
    let (root, mut config) = planned_study();
    let mut app = crate::app::ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    config.source_view.selected = StudySourceView::Inputs;
    app.router.campaign_mut().batch_scan_config = Some(config);
    let form = crate::renderer::render_plain_app(&app, 80);
    for expected in [
        "SOURCE OVERVIEW",
        "RECORDED ENGINE INPUTS",
        "PREPARED SETTINGS",
        "EXACT PREPARED OPTIONS",
        "maxInventoryFiles",
    ] {
        assert!(form.contains(expected), "{form}");
    }
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .detail_reader_scroll = Some(0);
    let reader = crate::renderer::render_plain_app(&app, 80);
    assert!(reader.contains("RECORDED ENGINE INPUTS"));
    assert!(!reader.contains("maxInventoryFiles"));
}

#[test]
fn threat_model_reference_distinguishes_legacy_omission_and_malformed_values() {
    assert!(context_reference_summary(&json!({})).contains("legacy selection"));
    assert_eq!(
        context_reference_summary(&json!({"threatModelRef":null})),
        "explicitly omitted"
    );
    assert!(
        context_reference_summary(&json!({"threatModelRef":{"modelId":"bad"}}))
            .contains("malformed")
    );
    let reference = kuzushi_core::ThreatModelRef {
        model_id: kuzushi_core::ThreatModelId::new(),
        revision_id: kuzushi_core::ThreatModelRevisionId::new(),
        sha256: "a".repeat(64),
    };
    let input = json!({"threatModelRef":reference});
    let summary = context_reference_summary(&input);
    assert!(summary.contains(reference.model_id.as_str()));
    assert!(summary.contains(reference.revision_id.as_str()));
    assert!(summary.contains("JSON has the exact content hash"));
    let mut malformed = input;
    malformed["threatModelRef"]["modelId"] = json!("tm_\u{1b}[31m");
    let summary = context_reference_summary(&malformed);
    assert!(summary.contains("malformed") && !summary.contains('\u{1b}'));
}
