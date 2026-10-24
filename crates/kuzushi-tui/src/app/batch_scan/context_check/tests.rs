use super::*;
use crate::app::{EffectRuntime, ShellEffect};
use crossterm::event::KeyCode;
use kuzushi_core::{ToolExecutionContext, V2Config, WorkspaceTarget};
use ratatui::{backend::TestBackend, Terminal};

fn dispatch(app: &ShellApp, root: &std::path::Path, tool: &str, input: Value) -> Value {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let ctx = ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = app
        .registry()
        .prepare_dispatch_input(tool, input, &ctx, None)
        .unwrap();
    app.registry()
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap()
}

fn fixture() -> (tempfile::TempDir, ShellApp, ThreatModelRef) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("reader.txt"),
        "Owned fixture, never executed.\n",
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    let document = json!({"version":"1","methodology":"stride","systemContext":"Overview", "dfd":{"nodes":[{"id":"app","name":"App","type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}});
    let result = dispatch(
        &app,
        root.path(),
        "threat-model:import",
        json!({"document":document,"label":"Selected","activate":false}),
    );
    let reference: ThreatModelRef =
        serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    app.open_batch_scan_config(None);
    app.open_study_context_picker();
    app.edit_context_picker(|config| {
        config.context_picker.as_mut().unwrap().selected = Some(reference.clone())
    });
    let read = dispatch(
        &app,
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":reference}),
    );
    app.cache_study_context_preview(&read["data"]);
    (root, app, reference)
}

fn prepared_check(app: &mut ShellApp) -> Value {
    let update = app.handle_study_context_key(KeyCode::Char('c'));
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("Shared dispatch required")
    };
    assert_eq!(request.tool_name, "threat-model:verify");
    serde_json::from_str(request.input.as_ref().unwrap()).unwrap()
}

#[test]
fn checked_revision_needs_inspection_and_explicit_use_without_changing_study() {
    let (root, mut app, reference) = fixture();
    app.set_input("Preserved composer draft");
    let study = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    let input = prepared_check(&mut app);
    assert_eq!(input["threatModelRef"], json!(reference));
    let result = dispatch(&app, root.path(), "threat-model:verify", input);
    assert!(app.cache_study_result("threat-model:verify", &result["data"]));
    let picker = app.study_context_picker().unwrap();
    assert_eq!(json!(picker.selected), result["data"]["modelRef"]);
    assert!(picker.preview.is_none() && picker.pending_check.is_none());
    app.handle_study_context_key(KeyCode::Char('a'));
    assert!(app.study_context_picker().is_some());
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study,
        study
    );
    assert_eq!(app.input(), "Preserved composer draft");
}

#[test]
fn completion_preserves_a_different_selection_target_and_closed_picker() {
    let (root, mut app, reference) = fixture();
    let input = prepared_check(&mut app);
    let result = dispatch(&app, root.path(), "threat-model:verify", input);
    app.edit_context_picker(|config| config.context_picker.as_mut().unwrap().selected = None);
    app.cache_study_result("threat-model:verify", &result["data"]);
    assert!(app.study_context_picker().unwrap().selected.is_none());
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_deref()
        .unwrap()
        .contains("selection is unchanged"));
    app.handle_study_context_key(KeyCode::Esc);
    app.cache_study_result("threat-model:verify", &result["data"]);
    assert!(app.study_context_picker().is_none());
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    app.cache_study_result("threat-model:verify", &result["data"]);
    assert_eq!(app.target(), Some(other.path()));
    assert_ne!(
        reference.revision_id.as_str(),
        result["data"]["modelRef"]["revisionId"].as_str().unwrap()
    );
}

#[test]
fn late_read_from_a_different_target_is_ignored_even_when_reference_matches() {
    let (root, mut app, reference) = fixture();
    let old_read = dispatch(
        &app,
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":reference}),
    );
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    app.open_batch_scan_config(None);
    app.open_study_context_picker();
    app.edit_context_picker(|config| {
        config.context_picker.as_mut().unwrap().selected = Some(reference)
    });
    assert!(app.cache_study_context_preview(&old_read["data"]));
    assert!(app.study_context_picker().unwrap().preview.is_none());
    assert_eq!(app.target(), Some(other.path()));
}

#[test]
fn failed_or_partial_checks_preserve_context_and_disclose_recovery() {
    let (root, mut app, reference) = fixture();
    let input = prepared_check(&mut app);
    app.context_check_failed("threat-model:verify", "Context source content changed");
    assert!(app
        .study_context_picker()
        .unwrap()
        .preview
        .as_ref()
        .unwrap()
        .source_state
        .contains("source check stopped"));
    assert_eq!(
        app.study_context_picker().unwrap().selected,
        Some(reference.clone())
    );
    assert!(app
        .study_context_picker()
        .unwrap()
        .preview
        .as_ref()
        .unwrap()
        .source_status
        .is_none());
    assert!(app.study_context_picker().unwrap().preview.is_some());
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_deref()
        .unwrap()
        .contains("source content changed"));
    prepared_check(&mut app);
    let mut result = dispatch(&app, root.path(), "threat-model:verify", input);
    result["data"]["sourceCheckCurrent"] = json!(false);
    app.cache_study_result("threat-model:verify", &result["data"]);
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_deref()
        .unwrap()
        .contains("current-source status is unverified"));
}

#[test]
fn late_check_results_preserve_editor_menu_diagram_paging_and_raw_reading() {
    for changed in 0..6 {
        let (root, mut app, reference) = fixture();
        app.reduce_resize(40, 12);
        let input = prepared_check(&mut app);
        let result = dispatch(&app, root.path(), "threat-model:verify", input);
        match changed {
            0 => app.open_context_editor(),
            1 => {
                app.handle_study_context_key(KeyCode::Char(' '));
            }
            2 => {
                app.handle_study_context_key(KeyCode::Char('v'));
            }
            3 => {
                app.handle_study_context_key(KeyCode::PageDown);
            }
            4 => {
                app.handle_study_context_key(KeyCode::Tab);
            }
            _ => {
                app.handle_study_context_key(KeyCode::Char('p'));
            }
        }
        let before = app.study_context_picker().unwrap().clone();
        if changed == 3 {
            assert!(
                before.detail_scroll > 0,
                "The paging action must actually move the reader"
            );
        }
        app.cache_study_result("threat-model:verify", &result["data"]);
        let after = app.study_context_picker().unwrap();
        assert_eq!(after.selected, Some(reference), "state {changed}");
        assert_eq!(after.preview, before.preview);
        assert_eq!(after.editor_visible, before.editor_visible);
        assert_eq!(after.diagram_visible, before.diagram_visible);
        assert_eq!(after.actions_selected, before.actions_selected);
        assert_eq!(after.detail_scroll, before.detail_scroll);
        assert_eq!(after.text_view, before.text_view);
        if changed == 0 {
            assert!(app.context_edit_draft().is_some());
        }
    }
}

#[test]
fn source_drift_and_catalog_loading_are_honest_in_the_reader() {
    let (root, mut app, reference) = fixture();
    std::fs::write(root.path().join("reader.txt"), "Different source\n").unwrap();
    let read = dispatch(
        &app,
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":reference}),
    );
    app.cache_study_context_preview(&read["data"]);
    let lines = crate::ui_view_models::study_context::context_detail_lines(&app, 120).join("\n");
    assert!(lines.contains("Source drift at inspection: content changed"));
    assert!(!lines.contains("selected revision is unavailable"));
    assert!(lines.contains("Catalog membership is unavailable"));
}

#[test]
fn actual_worker_settles_in_context_browser_with_no_model_selected() {
    let (_root, mut app, _) = fixture();
    let update = app.handle_study_context_key(KeyCode::Char('c'));
    EffectRuntime::execute(&mut app, update.effects);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline && app.has_running_work() {
        app.drain_background_events();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    app.drain_background_events();
    assert!(!app.has_running_work());
    let picker = app.study_context_picker().unwrap();
    assert!(
        picker.pending_check.is_none() && picker.preview.is_none(),
        "{:?}",
        app.log_lines()
    );
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_deref()
        .unwrap()
        .contains("Context source check:"));
    assert!(app.config().model.is_none());
}

#[test]
fn menu_and_primary_controls_remain_reachable_at_every_supported_size() {
    let (_root, mut app, _) = fixture();
    app.set_input("Unchanged draft");
    let preview = app.study_context_picker().unwrap().preview.clone();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text = buffer
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(
            text.contains("c check") && text.contains("Space actions"),
            "{width}x{height}: {text}"
        );
        app.handle_study_context_key(KeyCode::Char(' '));
        for index in 0..crate::ui_view_models::study_context::CONTEXT_ACTIONS.len() {
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
            let label = crate::ui_view_models::study_context::CONTEXT_ACTIONS[index].1;
            assert!(text.contains(label), "{width}x{height}: {label}: {text}");
            app.handle_study_context_key(KeyCode::Down);
        }
        app.handle_study_context_key(KeyCode::Esc);
    }
    assert_eq!(app.input(), "Unchanged draft");
    assert_eq!(app.study_context_picker().unwrap().preview, preview);
}
