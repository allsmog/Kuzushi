use super::*;
use crate::app::FindingLedgerCounts;
use kuzushi_core::{V2Config, WorkspaceTarget};

#[test]
fn report_counts_distinguish_each_decision_from_pending_and_source_reassessment() {
    let counts = ReportReviewCounts {
        findings: 9,
        decisions: ReviewDecisionCounts {
            confirmed: 1,
            to_fix: 1,
            rejected_false_positive: 2,
            deferred: 1,
            accepted_risk: 1,
            suppressed: 1,
        },
        reassessment_required: 1,
    };
    assert_eq!(review_decision_totals(counts), "9 findings · 2 pending · TP: 2 · FP: 2 · 1 deferred · 1 accepted risk · 1 suppressed · source review needed: 1");
    assert_eq!(
        review_footer_totals(counts),
        "2 pending · 2 TP · 2 FP · 1 deferred · 1 accepted risk · 1 suppressed · 1 source review"
    );
}

fn cache_workspace(
    app: &mut ShellApp,
    result: Result<kuzushi_core::workspace::WorkspaceReviewSummary, String>,
) {
    let key = crate::app::ViewHydrationKey::WorkspaceReportReview {
        findings_watermark: app.findings_read_watermark(),
    };
    let target = app.target_owned().unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(crate::app::ViewHydrationResult {
            target,
            key,
            value: crate::app::ViewHydrationValue::WorkspaceReportReview(result),
        });
}

#[test]
fn workspace_report_ignores_selected_scan_counts_and_explicit_reopen_retries_reading() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.router.report_mut().toggle_scope();
    app.domain_mut()
        .set_finding_ledger_counts(FindingLedgerCounts {
            total: 1,
            reviewed: 1,
            confirmed: 1,
            ..Default::default()
        });
    cache_workspace(
        &mut app,
        Ok(kuzushi_core::workspace::WorkspaceReviewSummary {
            finding_count: 3,
            decisions: ReviewDecisionCounts {
                rejected_false_positive: 2,
                ..Default::default()
            },
            reassessment_required: 0,
        }),
    );
    assert_eq!(
        report_review_summary(&app),
        "3 findings · 1 pending · TP: 0 · FP: 2"
    );
    assert_eq!(report_review_footer_summary(&app), "1 pending · 2 FP");
    app.set_shell_view(crate::ShellView::Report);
    app.domain_mut()
        .set_review_source_applicabilities(std::collections::BTreeMap::from([(
            "other-scan".into(),
            kuzushi_core::workspace::WorkspaceReviewSourceApplicability::ReassessmentRequired,
        )]));
    let plain = crate::renderer::render_plain_app(&app, 80);
    assert!(
        plain.contains("3 findings · 1 pending · TP: 0 · FP: 2"),
        "{plain}"
    );
    assert!(
        !plain.contains("Review: 1 finding needs source reassessment"),
        "{plain}"
    );
    assert!(!plain.contains('\x1b'));
    cache_workspace(&mut app, Err("Owned unavailable source".into()));
    assert!(report_review_summary(&app).contains("unavailable"));
    assert_eq!(report_review_footer_summary(&app), "Report unavailable");
    assert!(crate::renderer::render_plain_app(&app, 80).contains("Owned unavailable source"));
    app.open_report_from_current_origin();
    assert_eq!(report_review_footer_summary(&app), "Report loading");
}

#[test]
fn selected_study_and_workspace_history_keep_distinct_report_membership() {
    use kuzushi_core::capabilities::campaign::{
        compile_scan_batch_plan, ScanBatchGatePolicy, ScanBatchPlanSpec,
    };
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    compile_scan_batch_plan(ScanBatchPlanSpec {
        root: root.path(),
        batch_id: Some("owned-empty-study".into()),
        trials: 3,
        requested_workers: 1,
        gate_policy: ScanBatchGatePolicy::default(),
        prepared_input: serde_json::json!({"taskMode":"manual","tasks":["secret-scan"]}),
        config: &V2Config::default(),
        registry: &kuzushi_core::ModuleRegistry::with_v2_builtins(),
    })
    .unwrap();
    let document = kuzushi_core::workspace::load_investigation_report_document(
        &workspace,
        "owned-empty-study",
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    cache_workspace(
        &mut app,
        Ok(kuzushi_core::workspace::WorkspaceReviewSummary {
            finding_count: 9,
            ..Default::default()
        }),
    );
    let key = app.report_hydration_key();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(crate::app::ViewHydrationResult {
            target: app.target_owned().unwrap(),
            key,
            value: crate::app::ViewHydrationValue::InvestigationReport(Ok(Some(document))),
        });
    assert_eq!(
        report_review_summary(&app),
        "0 findings · 0 pending · TP: 0 · FP: 0"
    );
    assert_eq!(report_review_footer_summary(&app), "0 pending");
    app.router.report_mut().toggle_scope();
    assert_eq!(
        report_review_summary(&app),
        "9 findings · 9 pending · TP: 0 · FP: 0"
    );
    assert_eq!(report_review_footer_summary(&app), "9 pending");
}

#[test]
fn empty_report_has_explicit_zero_decisions_without_a_clean_coverage_claim() {
    let counts = ReportReviewCounts {
        findings: 0,
        decisions: ReviewDecisionCounts::default(),
        reassessment_required: 0,
    };
    assert_eq!(
        review_decision_totals(counts),
        "0 findings · 0 pending · TP: 0 · FP: 0"
    );
    assert_eq!(review_footer_totals(counts), "0 pending");
}

#[test]
fn retrying_an_open_report_preserves_scope_format_and_reading_position() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(crate::ShellView::Report);
    app.router.report_mut().toggle_scope();
    app.router.report_mut().move_format(3);
    app.router.default_scroll_mut().scroll_down(7);
    let format = app.router.report().format();
    app.open_report_from_current_origin();
    assert!(app.router.report().workspace_history());
    assert_eq!(app.router.report().format(), format);
    assert_eq!(app.router.default_scroll().offset(), 7);
    assert_eq!(app.input_mode(), crate::app::InputMode::Navigate);
    assert_eq!(report_review_footer_summary(&app), "Report loading");
}
