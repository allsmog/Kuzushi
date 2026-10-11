use super::*;
use crate::app::view_hydration::{ViewHydrationKey, ViewHydrationResult, ViewHydrationValue};
use crate::app::ViewDataState;
use kuzushi_core::capabilities::campaign::ContextMatrixMetadataV1;
use kuzushi_core::findings::{
    BatchOccurrenceReport, BatchOccurrenceRow, BatchTrialReport, ContextCaseOccurrenceReport,
    ContextMatrixOccurrenceReport, IdentityFoldPolicy,
};

fn report() -> ContextMatrixOccurrenceReport {
    ContextMatrixOccurrenceReport {
        schema_version: 1,
        campaign_id: "matrix-ui".into(),
        plan_sha256: "a".repeat(64),
        baseline_case_id: "alpha".into(),
        cases: (0..8).map(case_report).collect(),
    }
}

fn case_report(index: usize) -> ContextCaseOccurrenceReport {
    let id = if index == 0 {
        "alpha".into()
    } else {
        format!("case{index}")
    };
    ContextCaseOccurrenceReport {
        id,
        label: format!("Context {index}"),
        threat_model_ref: json!(null),
        occurrence: BatchOccurrenceReport {
            schema_version: 1,
            batch_id: "matrix-ui".into(),
            equivalence_key: index.to_string(),
            identity_fold: IdentityFoldPolicy::default(),
            planned: 10,
            completed: 10,
            failed: 0,
            pending: 0,
            gate: None,
            trials: (0..10).map(|pass| trial(index, pass)).collect(),
            rows: (0..20).map(|row| observation(index, row)).collect(),
        },
    }
}

fn trial(case: usize, pass: usize) -> BatchTrialReport {
    BatchTrialReport {
        trial: pass + 1,
        job_id: format!("case{case}-pass{pass}"),
        state: "completed".into(),
        attempts: 1,
        run_id: Some(format!("case{case}-run{pass}")),
        attempt_run_ids: Vec::new(),
        finding_run_ids: Vec::new(),
        failure_reason: None,
    }
}

fn observation(case: usize, row: usize) -> BatchOccurrenceRow {
    BatchOccurrenceRow {
        fold_key: format!("row{row}"),
        identity_id: None,
        identity_basis: None,
        seen: case + 1,
        completed: 10,
        planned: 10,
        failed: 0,
        severities: vec!["info".into()],
        locations: vec![],
        titles: vec![],
        fingerprints: vec![],
        run_ids: vec![],
        representative_fingerprint: row.to_string(),
        representative_title: format!(
            "Labeled synthetic observation {row} with a long title to check wrapping"
        ),
        representative_severity: "info".into(),
        representative_location: "main.rs".into(),
    }
}

fn result_fixture() -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = fixture();
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.matrix.cases = report()
        .cases
        .iter()
        .map(|case| ContextCaseInput {
            id: case.id.clone(),
            label: case.label.clone(),
            passes: 10,
            threat_model_ref: json!(null),
        })
        .collect();
    config.study.matrix.receipt = Some(ContextMatrixReceipt {
        schema_version: 1,
        campaign_id: "matrix-ui".into(),
        investigation_id: None,
        plan_path: "plan.json".into(),
        plan_sha256: "a".repeat(64),
        workers: 1,
        requested_workers: 1,
        worker_limitation: None,
        job_count: 80,
        supporting_context: None,
        resource_evidence: None,
        matrix: ContextMatrixMetadataV1 {
            schema_version: 1,
            baseline_case_id: "alpha".into(),
            cases: vec![],
        },
    });
    config.study.matrix.results = true;
    seed_report(&app, app.target().unwrap(), report());
    (root, app)
}

fn seed_report(app: &ShellApp, target: &std::path::Path, report: ContextMatrixOccurrenceReport) {
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: target.into(),
            key: ViewHydrationKey::ContextMatrixReport {
                campaign_id: report.campaign_id.clone(),
                plan_sha256: report.plan_sha256.clone(),
            },
            value: ViewHydrationValue::ContextMatrixReport(Ok(report)),
        });
}

#[test]
fn entering_results_discards_the_pre_run_cache_without_changing_focus_or_draft() {
    let (_root, mut app) = result_fixture();
    app.set_input("kept draft");
    app.set_cursor(3);
    let view = app.shell_view();
    assert!(matches!(
        app.cached_context_matrix_report(),
        ViewDataState::Ready(Ok(_))
    ));
    assert!(app.open_matrix_results().effects.is_empty());
    assert!(!matches!(
        app.cached_context_matrix_report(),
        ViewDataState::Ready(Ok(_))
    ));
    assert_eq!(app.shell_view(), view);
    assert_eq!((app.input(), app.cursor()), ("kept draft", 3));
}

#[test]
fn baseline_selection_confirms_the_completed_pass_and_preserves_the_case_cursor() {
    let (_root, mut app) = result_fixture();
    app.handle_matrix_result_key(KeyCode::Down);
    app.handle_matrix_result_key(KeyCode::Char('b'));
    assert!(app
        .handle_matrix_result_key(KeyCode::Enter)
        .unwrap()
        .effects
        .is_empty());
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(
        config.study.matrix.baseline_run_id.as_deref(),
        Some("case0-run0")
    );
    assert_eq!(config.study.matrix.cursor, 1);
    assert_eq!(config.study.matrix.pass_selection, None);
    let lines = crate::ui_view_models::matrix_result_lines(&app, 36, 7);
    assert!(lines.iter().any(|line| line == "Baseline pass selected."));
}

#[test]
fn selected_last_case_and_pass_remain_visible_in_every_viewport() {
    use ratatui::{backend::TestBackend, Terminal};
    let (_root, mut app) = result_fixture();
    for _ in 0..7 {
        app.handle_matrix_result_key(KeyCode::Down);
    }
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        for text in ["Context 7", "observed 8 / 10", "PgUp/PgDn", "Esc"] {
            assert!(screen.contains(text), "{width}x{height}: {text}: {screen}");
        }
        app.handle_matrix_result_key(KeyCode::Enter);
        for _ in 0..9 {
            app.handle_matrix_result_key(KeyCode::Down);
        }
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        assert!(
            screen.contains("Pass 10 · completed"),
            "{width}x{height}: {screen}"
        );
        app.handle_matrix_result_key(KeyCode::Esc);
    }
}

#[test]
fn detail_paging_reaches_the_last_observation_and_case_changes_restore_the_top() {
    let (_root, mut app) = result_fixture();
    app.handle_matrix_result_key(KeyCode::End);
    let lines = crate::ui_view_models::matrix_result_lines(&app, 36, 7).join("\n");
    assert!(lines.contains("observation 19"), "{lines}");
    app.handle_matrix_result_key(KeyCode::Down);
    let lines = crate::ui_view_models::matrix_result_lines(&app, 36, 7).join("\n");
    assert!(lines.contains("observed 2 / 10"), "{lines}");
    assert!(!lines.contains("observation 19"));
}

#[test]
fn result_cache_is_isolated_by_target_and_plan_digest() {
    let (root, app) = result_fixture();
    let key = ViewHydrationKey::ContextMatrixReport {
        campaign_id: "matrix-ui".into(),
        plan_sha256: "b".repeat(64),
    };
    assert!(!matches!(
        app.workbench_cache()
            .borrow()
            .cached_matrix_report(root.path(), &key),
        ViewDataState::Ready(_)
    ));
    let key = ViewHydrationKey::ContextMatrixReport {
        campaign_id: "matrix-ui".into(),
        plan_sha256: "a".repeat(64),
    };
    assert!(!matches!(
        app.workbench_cache()
            .borrow()
            .cached_matrix_report(std::path::Path::new("/foreign"), &key),
        ViewDataState::Ready(_)
    ));
}

#[test]
fn narrow_case_labels_preserve_the_distinguishing_name_after_a_shared_prefix() {
    let (root, mut app) = result_fixture();
    let mut report = report();
    report.cases.truncate(3);
    for (case, name) in report.cases.iter_mut().zip(["Alpha", "Beta", "Gamma"]) {
        case.label = format!("Labeled diagram {name}");
    }
    seed_report(&app, app.target().unwrap(), report);
    app.handle_matrix_result_key(KeyCode::Down);
    let lines = crate::ui_view_models::matrix_result_lines(&app, 36, 7).join("\n");
    for name in ["Alpha", "Beta", "Gamma"] {
        assert!(lines.contains(name), "{lines}");
    }
    drop(root);
}

#[test]
fn report_action_binds_the_exact_plan_and_returns_to_the_same_case_and_draft() {
    let (_root, mut app) = result_fixture();
    app.set_input("kept draft");
    app.set_cursor(3);
    app.handle_matrix_result_key(KeyCode::Down);
    let update = app.handle_matrix_result_key(KeyCode::Char('R')).unwrap();
    assert!(update.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::Report);
    let reference = app.router.report().study().unwrap();
    assert_eq!(reference.campaign_id, "matrix-ui");
    assert_eq!(reference.plan_sha256, "a".repeat(64));
    assert!(!app.router.report().workspace_history());
    assert_eq!((app.input(), app.cursor()), ("kept draft", 3));
    app.close_report_to_origin();
    assert_eq!(app.shell_view(), ShellView::Campaign);
    let matrix = &app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .matrix;
    assert!(matrix.results && matrix.open);
    assert_eq!(matrix.cursor, 1);
}

#[test]
fn report_refresh_discards_old_outcomes_without_accepting_another_plan_or_target() {
    let (_root, mut app) = result_fixture();
    app.handle_matrix_result_key(KeyCode::Char('R'));
    let target = app.target_owned().unwrap();
    let key = app.report_hydration_key();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: target.clone(),
            key: key.clone(),
            value: ViewHydrationValue::InvestigationReport(Err("prior failure".into())),
        });
    assert!(matches!(
        app.workbench_cache()
            .borrow()
            .cached_selected_report(Some(&target), &key),
        ViewDataState::Ready(Err(_))
    ));
    app.close_report_to_origin();
    app.handle_matrix_result_key(KeyCode::Char('R'));
    assert!(!matches!(
        app.workbench_cache()
            .borrow()
            .cached_selected_report(Some(&target), &key),
        ViewDataState::Ready(_)
    ));
    let foreign = ViewHydrationKey::InvestigationStudyReport {
        campaign_id: "other-plan".into(),
        plan_sha256: "a".repeat(64),
        findings_watermark: None,
    };
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: target.clone(),
            key: foreign,
            value: ViewHydrationValue::InvestigationReport(Err("foreign result".into())),
        });
    assert!(!matches!(
        app.workbench_cache()
            .borrow()
            .cached_selected_report(Some(&target), &key),
        ViewDataState::Ready(_)
    ));
}

#[test]
fn missing_explicit_study_never_becomes_a_workspace_history_export() {
    let (_root, mut app) = result_fixture();
    app.handle_matrix_result_key(KeyCode::Char('R'));
    let target = app.target_owned().unwrap();
    let key = app.report_hydration_key();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target,
            key,
            value: ViewHydrationValue::InvestigationReport(Ok(None)),
        });
    assert!(crate::ui_view_models::report_investigation_lines(&app)
        .join("\n")
        .contains("selected study receipt unavailable"));
    let update = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(update.effects.is_empty());
    assert!(app
        .router
        .report()
        .reveal_error()
        .unwrap()
        .contains("Selected study receipt"));
}

#[test]
fn report_entry_removes_stale_navigation_hints_and_preserves_errors() {
    let (_root, mut app) = result_fixture();
    app.set_info_notice("navigate", "Previous view keys");
    app.handle_matrix_result_key(KeyCode::Char('R'));
    assert!(app.advisory().notice.is_none());
    app.close_report_to_origin();
    app.set_error_notice("navigate", "Preserved error");
    app.handle_matrix_result_key(KeyCode::Char('R'));
    assert_eq!(
        app.advisory().notice.as_ref().unwrap().message,
        "Preserved error"
    );
}
