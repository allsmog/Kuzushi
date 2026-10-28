use super::*;
use kuzushi_core::{Finding, FindingStore, Severity, WorkspaceTarget};

mod allowance;
mod fixture;
mod report;
use fixture::review_fixture;

fn key(app: &mut ShellApp, code: KeyCode) -> InputUpdate {
    app.handle_matrix_result_key(code).unwrap()
}

fn selected_key(app: &ShellApp) -> Option<&str> {
    app.router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .matrix
        .observation_key
        .as_deref()
}

fn seed_current_report(app: &ShellApp, report: ContextMatrixOccurrenceReport) {
    seed_report(app, app.target().unwrap(), report);
}

#[test]
fn case_finding_navigation_preserves_case_reading_and_declines_missing_exact_references() {
    let (_root, mut app) = result_fixture();
    let matrix = &mut app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .matrix;
    matrix.cursor = 2;
    matrix.detail_scroll = 7;
    key(&mut app, KeyCode::Char('f'));
    assert_eq!(selected_key(&app), Some("row0"));
    key(&mut app, KeyCode::Down);
    assert_eq!(selected_key(&app), Some("row1"));
    assert!(key(&mut app, KeyCode::Enter).effects.is_empty());
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .matrix
        .observation_notice
        .as_ref()
        .unwrap()
        .contains("no exact observation reference"));
    assert!(crate::ui_view_models::matrix_result_lines(&app, 120, 100)
        .join("\n")
        .contains("no exact observation reference"));
    key(&mut app, KeyCode::Esc);
    let matrix = &app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .matrix;
    assert!(matrix.observation_key.is_none());
    assert_eq!((matrix.cursor, matrix.detail_scroll), (2, 7));
}

fn recorded_pair(root: &std::path::Path) -> (FindingStore, i64) {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = Finding::new_tool(
        "fixture",
        "same-policy",
        "main.rs",
        1,
        None,
        Severity::Info,
        "Owned policy observation",
    );
    store
        .record_run_started("alpha-owned", root, "completed")
        .unwrap();
    store.insert_finding("alpha-owned", &finding).unwrap();
    let original = store
        .list_findings_for_scan_id("alpha-owned")
        .unwrap()
        .remove(0);
    store
        .record_run_started("beta-owned", root, "completed")
        .unwrap();
    store.insert_finding("beta-owned", &finding).unwrap();
    (store, original.id.unwrap())
}

#[test]
fn review_opens_the_recorded_generation_and_back_restores_exact_experiment_state() {
    let (root, mut app) = result_fixture();
    let (store, id) = recorded_pair(root.path());
    let mut report = report();
    report.cases[0].occurrence.rows[0].representative_observation_ref =
        Some(format!("generation:{id}"));
    seed_current_report(&app, report);
    app.set_input("Held operator draft\nsecond line");
    app.set_cursor(5);
    app.set_active_findings_filter(Some("rank:critical".into()));
    app.router.campaign_mut().active_batch_id = Some("previous-study".into());
    key(&mut app, KeyCode::Char('f'));
    let before = app.router.campaign().batch_scan_config.clone();
    let update = key(&mut app, KeyCode::Enter);
    assert!(app.matrix_observation_return_is_available());
    assert!(app.router.campaign().active_batch_id.is_none());
    let open = update
        .effects
        .into_iter()
        .find_map(|effect| match effect {
            crate::app::ShellEffect::OpenFinding(open) => Some(open),
            crate::app::ShellEffect::RefreshFindings(_) => None,
            _ => panic!("Reading a case finding must not dispatch model or discovery work"),
        })
        .unwrap();
    assert_eq!(open.reference, format!("generation:{id}"));
    for effect in app.resolve_open_finding_effect(open) {
        if let crate::app::ShellEffect::FinalizeOpenFinding(open) = effect {
            app.finalize_open_finding_effect(open);
        }
    }
    assert_eq!(app.selected_finding().as_ref().unwrap().id, Some(id));
    assert_eq!(
        app.selected_finding().as_ref().unwrap().scan_id.as_deref(),
        Some("alpha-owned")
    );
    assert_eq!(
        store.list_findings_for_scan_id("beta-owned").unwrap().len(),
        1
    );
    app.go_back();
    assert_eq!(app.router.campaign().batch_scan_config, before);
    assert_eq!(
        app.active_findings_filter().as_deref(),
        Some("rank:critical")
    );
    assert_eq!(
        app.router.campaign().active_batch_id.as_deref(),
        Some("previous-study")
    );
    assert_eq!(
        (app.input(), app.cursor()),
        ("Held operator draft\nsecond line", 5)
    );
}

#[test]
fn empty_cases_and_unavailable_reads_do_not_open_review_or_create_work() {
    let (_root, mut app) = result_fixture();
    let mut report = report();
    report.cases[0].occurrence.rows.clear();
    seed_current_report(&app, report);
    assert!(key(&mut app, KeyCode::Char('f')).effects.is_empty());
    assert!(selected_key(&app).is_none());
    app.workbench_cache()
        .borrow_mut()
        .invalidate_study_usage(app.target().unwrap());
    assert!(key(&mut app, KeyCode::Char('f')).effects.is_empty());
    assert!(!app.matrix_observation_return_is_available());
}

#[test]
fn changing_target_cannot_restore_the_old_case_reader() {
    let (root, mut app) = result_fixture();
    let (_store, id) = recorded_pair(root.path());
    let mut report = report();
    report.cases[0].occurrence.rows[0].representative_observation_ref =
        Some(format!("generation:{id}"));
    seed_current_report(&app, report);
    key(&mut app, KeyCode::Char('f'));
    key(&mut app, KeyCode::Enter);
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    assert!(!app.restore_matrix_observation_origin());
    assert!(!app.matrix_observation_return_is_available());
    app.set_target(Some(root.path().into()));
    assert!(!app.matrix_observation_return_is_available());
}

#[test]
fn every_case_observation_is_selectable_and_its_detail_pages_at_all_viewports() {
    let (_root, mut app) = result_fixture();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        key(&mut app, KeyCode::Char('f'));
        let frame = super::reading::page(&app);
        assert!(
            frame.contains("Enter review") && frame.contains("Esc cases"),
            "{width}x{height}: {frame}"
        );
        let area = crate::ui_view_models::matrix_body(
            crate::ui_view_models::study_config::study_config_area(width, height),
            true,
        );
        let visible =
            crate::ui_view_models::matrix_result_lines(&app, area.width.into(), area.height.into());
        assert!(
            visible.iter().any(|line| line.starts_with("▸ info · ")),
            "{width}x{height}: {visible:?}"
        );
        for index in 0..20 {
            assert_eq!(selected_key(&app), Some(format!("row{index}").as_str()));
            let text =
                crate::ui_view_models::matrix_result_lines(&app, width.into(), height.into())
                    .join("\n");
            assert!(
                text.contains(&format!("observation {index}")),
                "{width}x{height}: {text}"
            );
            key(&mut app, KeyCode::End);
            key(&mut app, KeyCode::Home);
            key(&mut app, KeyCode::Down);
        }
        key(&mut app, KeyCode::Esc);
    }
}

#[test]
fn refresh_keeps_selected_observation_identity_when_rows_are_reordered() {
    let (_root, mut app) = result_fixture();
    let mut report = report();
    report.cases[0].occurrence.rows[1].representative_observation_ref =
        Some("generation:202".into());
    seed_current_report(&app, report.clone());
    key(&mut app, KeyCode::Char('f'));
    key(&mut app, KeyCode::Down);
    report.cases[0].occurrence.rows.reverse();
    seed_current_report(&app, report);
    assert_eq!(selected_key(&app), Some("row1"));
    let update = key(&mut app, KeyCode::Enter);
    assert!(update.effects.iter().any(|effect| matches!(effect,
        crate::app::ShellEffect::OpenFinding(open) if open.reference == "generation:202")));
}
