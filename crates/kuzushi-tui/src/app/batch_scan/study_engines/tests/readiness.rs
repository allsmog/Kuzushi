use super::*;
use crate::app::{ViewHydrationResult, ViewHydrationValue};
use crate::ui_view_models::study_engines::{
    engine_detail, engine_line, engine_rows, selected_engine_requirements,
};

#[test]
fn every_picker_task_has_an_actual_catalog_route_and_experimental_choices_stay_opt_in() {
    let (_root, mut app) = fixture(false);
    for task in app.sast_task_rows() {
        assert!(
            app.registry()
                .scan_task_preview(task.id, &json!({}))
                .is_ok(),
            "{}",
            task.id
        );
    }
    focus(&mut app, "codeql");
    let row = engine_rows(&app)
        .into_iter()
        .find(|row| row.id.as_deref() == Some("codeql"))
        .unwrap();
    assert!(engine_line(&row, true).contains("[Labs] codeql"));
    assert!(!row.selected);
    let detail = engine_detail(&app, 200).join("\n");
    assert!(detail.contains("Experimental (Labs)"));
    assert!(detail.contains("native scan task"));
    assert!(detail.contains("authenticated source-bound database"));
    assert!(app.study_engine_picker().unwrap().automatic);
}

fn cache_dependency_result(
    app: &mut ShellApp,
    missing: Vec<String>,
) -> crate::app::ViewHydrationKey {
    let key = app
        .workbench_cache()
        .borrow()
        .executable_options_key(selected_engine_requirements(app));
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target().unwrap().to_path_buf(),
            key: key.clone(),
            value: ViewHydrationValue::ExecutableOptions(missing),
        });
    key
}

#[test]
fn dependency_hints_distinguish_unchecked_missing_and_presence_only() {
    let (_root, mut app) = fixture(false);
    focus(&mut app, "semgrep");
    assert!(engine_detail(&app, 200)
        .join("\n")
        .contains("DEPENDENCIES UNCHECKED"));
    cache_dependency_result(&mut app, vec!["semgrepBinary".into()]);
    let detail = engine_detail(&app, 200).join("\n");
    assert!(detail.contains("DEPENDENCY MISSING: semgrepBinary"));
    assert!(engine_detail(&app, 36)[1].starts_with("DEPENDENCY MISSING:"));
    assert!(!detail.contains("Executable found"));
    cache_dependency_result(&mut app, Vec::new());
    let detail = engine_detail(&app, 200).join("\n");
    assert!(detail.contains("Executable found (presence only)"));
    assert!(detail.contains("CHECKS PENDING"));
}

#[test]
fn recheck_invalidates_presence_without_changing_selection_draft_or_jobs() {
    let (_root, mut app) = fixture(false);
    focus(&mut app, "semgrep");
    app.set_input("owned unfinished command");
    let picker = app.study_engine_picker().unwrap().clone();
    let study = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    let old = cache_dependency_result(&mut app, vec!["semgrepBinary".into()]);
    assert!(app
        .handle_study_engine_key(KeyCode::Char('r'))
        .effects
        .is_empty());
    assert_eq!(app.study_engine_picker().unwrap(), &picker);
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study,
        study
    );
    assert_eq!(app.input(), "owned unfinished command");
    let new = app
        .workbench_cache()
        .borrow()
        .executable_options_key(selected_engine_requirements(&app));
    assert_ne!(old, new);
    assert!(app
        .workbench_cache()
        .borrow()
        .cached_executable_options(app.target().unwrap(), &new)
        .is_not_requested());
}

#[test]
fn missing_model_and_unsupported_scope_remain_distinct_from_experimental_status() {
    let (_root, mut app) = fixture(true);
    focus(&mut app, "offense-review");
    let detail = engine_detail(&app, 240).join("\n");
    for expected in [
        "UNSUPPORTED:",
        "Experimental (Labs)",
        "PREREQUISITE MISSING",
        "offense-review:threat-hunt",
    ] {
        assert!(detail.contains(expected), "{expected}");
    }
    assert!(app
        .handle_study_engine_key(KeyCode::Enter)
        .effects
        .is_empty());
    assert!(app.study_engine_picker().unwrap().automatic);
}

#[test]
fn compact_model_prerequisite_precedes_generic_scope_and_catalog_copy() {
    let (_root, mut app) = fixture(false);
    focus(&mut app, "offense-review");
    let detail = engine_detail(&app, 36);
    assert!(detail[0].contains("model required"));
    assert!(detail[1].starts_with("PREREQUISITE MISSING:"));
}

#[test]
fn experimental_badge_and_presence_refresh_are_visible_at_six_sizes_and_plain_is_exhaustive() {
    let (_root, mut app) = fixture(false);
    focus(&mut app, "codeql");
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
        assert!(text.contains("[Labs] codeql"), "{width}x{height}");
        assert!(text.contains("r check"), "{width}x{height}");
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    for expected in [
        "Experimental (Labs)",
        "database",
        "CHECKS PENDING",
        "No jobs start",
    ] {
        assert!(plain.contains(expected), "{expected}");
    }
}
