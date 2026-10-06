use super::*;
use crate::app::{ConfirmKind, PendingConfirm, ShellView};
use kuzushi_core::allowance::{AllowanceLimits, AllowanceSnapshot, ProviderRunUsage};
use kuzushi_core::capabilities::campaign::{
    execute_study_plan, ScanResourceEvidence, StudyPlanReceipt,
};
use kuzushi_core::{
    modules::ToolExecutionContext, runtime::RuntimeCostReport, V2Config, WorkspaceTarget,
};
use ratatui::{backend::TestBackend, Terminal};
use serde_json::json;

fn fixture() -> (tempfile::TempDir, BatchScanConfig) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("source.rs"), "fn main() {}\n").unwrap();
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
    let output = execute_study_plan(&json!({"campaignId":"usage-draft","investigationId":"usage-study","scanInput":{"taskMode":"manual","tasks":["agentic"],"threatModelRef":null}}), &ctx).unwrap();
    let receipt: StudyPlanReceipt = serde_json::from_value(output["data"].clone()).unwrap();
    let usage = ProviderRunUsage {
        run_id: "labeled-observed-scan".into(),
        investigation_id: "usage-study".into(),
        model: config.model.unwrap(),
        tool: "sast:scan".into(),
        source_identity: receipt.equivalence.components.workspace_identity.clone(),
        config_sha256: receipt.equivalence.components.config_sha256.clone(),
        committed_calls: 4,
        unresolved_calls: 0,
    };
    let mut draft = BatchScanConfig::load(root.path(), None);
    draft.prior_runs.push(BatchPriorRun {
        run_id: usage.run_id.clone(),
        evidence: ViewDataState::Ready(Ok(ScanResourceEvidence {
            run_id: usage.run_id.clone(),
            cost_usd: None,
            provider_usage: Some(usage),
            equivalence: Some(receipt.equivalence.clone()),
            calibration_limitation: None,
        })),
    });
    draft.prior_run_id = Some("labeled-observed-scan".into());
    draft.study.investigation_id = "usage-study".into();
    draft.study.record_receipt(receipt);
    draft.study.max_provider_calls = Some(8);
    draft.study.protected_review_calls = Some(2);
    draft.study.allowance = Some(AllowanceSnapshot {
        schema_version: 1,
        investigation_id: "usage-study".into(),
        revision: 1,
        model: "openai-codex:gpt-5.5".into(),
        limits: AllowanceLimits {
            max_provider_calls: 8,
            protected_review_calls: 2,
        },
        committed_calls: 4,
        review_calls: 0,
        unresolved_calls: 0,
        cost: RuntimeCostReport::UNAVAILABLE,
        work_plan: None,
    });
    (root, draft)
}

#[test]
fn unknown_dollars_do_not_hide_request_evidence_or_a_proposed_shortfall() {
    let (_root, config) = fixture();
    let before = config.clone();
    let text = crate::ui_view_models::study_config::study_resource_lines(&config).join("\n");
    assert!(text.contains("Observed: 4 provider requests"));
    assert!(text.contains("Full plan estimate: 12 provider requests"));
    assert!(text.contains("2 context/scan calls available"));
    assert!(text.contains("exceeds available calls by 10"));
    assert!(text.contains("Dollar estimate: unavailable") && !text.contains("$0.0000"));
    assert_eq!(config, before);
}

#[test]
fn invalidated_or_changed_conditions_keep_usage_historical_and_unknown_evidence_never_looks_free() {
    let (_root, mut config) = fixture();
    config
        .study
        .receipt
        .as_mut()
        .unwrap()
        .equivalence
        .components
        .workspace_identity = "different-sha-and-tree".into();
    let text = crate::ui_view_models::study_config::study_resource_lines(&config).join("\n");
    assert!(text.contains("Observed: 4") && text.contains("conditions differ"));
    assert!(!text.contains("Full plan estimate"));
    config.study.invalidate_plan();
    assert!(
        crate::ui_view_models::study_config::study_resource_lines(&config)
            .join("\n")
            .contains("Prepare the draft")
    );
    config.prior_runs[0].evidence = ViewDataState::Ready(Err("labeled corrupt evidence".into()));
    assert!(
        crate::ui_view_models::study_config::study_resource_lines(&config)
            .join("\n")
            .contains("Historical usage unavailable")
    );
}

#[test]
fn changing_usage_requires_a_new_plan_and_preserves_limits_attempts_and_scan_options() {
    let (_root, mut config) = fixture();
    let mut study = config.study.clone();
    study.invalidate_plan();
    config.cycle_prior_run();
    assert!(config.prior_run_id.is_none());
    config.cycle_prior_run();
    assert_eq!(
        config.prior_run_id.as_deref(),
        Some("labeled-observed-scan")
    );
    assert_eq!(config.study, study);
}

#[test]
fn approval_uses_exact_proposed_terms_and_resource_reading_survives_all_sizes() {
    let (_root, mut config) = fixture();
    let mut app = crate::ShellApp::new(V2Config::default(), None);
    config.cursor = BatchScanConfigRow::ALL
        .iter()
        .position(|row| *row == BatchScanConfigRow::PriorRun)
        .unwrap();
    let receipt = config.study.receipt.as_ref().unwrap().clone();
    app.router.campaign_mut().batch_scan_config = Some(config);
    app.set_shell_view(ShellView::Campaign);
    let input = json!({"investigationId":"usage-study","expectedRevision":1,"campaignId":receipt.campaign_id,"campaignPlanSha256":receipt.plan_sha256,"maxProviderCalls":10,"protectedReviewCalls":2,"maxJobAttempts":1});
    let confirm = PendingConfirm {
        kind: ConfirmKind::InvestigationWork,
        tool: "campaign:approve-allowance".into(),
        target: "usage-study".into(),
        rationale: Some("Labeled proposed terms".into()),
        actor: None,
        allowlist: None,
        remembered: false,
    };
    let confirm = crate::app::approval::allowance::with_accounting_terms(&app, &input, confirm);
    assert!(confirm
        .rationale
        .as_ref()
        .unwrap()
        .contains("4 context/scan calls available"));
    assert!(confirm
        .rationale
        .as_ref()
        .unwrap()
        .contains("exceeds available calls by 8"));
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(
            text.contains("Usage evidence")
                && text.contains("r re")
                && text.contains("L next")
                && text.contains("Esc back"),
            "{width}x{height}: {text}"
        );
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    let normalized = plain.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains("Full plan estimate: 12 provider requests"));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .max_provider_calls,
        Some(8)
    );
}
