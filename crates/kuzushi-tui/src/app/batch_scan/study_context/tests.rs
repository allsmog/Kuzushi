use super::*;
use crate::app::{InputMode, ShellEffect, ShellView};
use kuzushi_core::capabilities::threat_model::{
    commit_threat_model_revision, load_active_threat_model, ScopeRef, ThreatModelCommit,
    ThreatModelRevisionSource,
};
use kuzushi_core::WorkspaceTarget;
use kuzushi_core::{modules::ToolExecutionContext, V2Config};
use ratatui::{backend::TestBackend, Terminal};

fn commit(root: &std::path::Path, label: &str) -> ThreatModelRef {
    commit_document(
        root,
        label,
        &json!({
            "version":"1", "methodology":"stride", "title":label,
            "dfd":{"nodes":[{"id":"app", "name":label, "type":"process", "trustZone":"internal"}],"flows":[],"trustBoundaries":[]},
            "threats":[], "summary":{}, "openQuestions":["Which callers are trusted?"],
        }),
    )
}

fn commit_document(root: &std::path::Path, label: &str, document: &Value) -> ThreatModelRef {
    commit_threat_model_revision(
        root,
        document,
        ThreatModelCommit {
            model_id: None,
            new_model: true,
            label: label.into(),
            scope: ScopeRef::legacy_root(root, &format!("sha256:{}", "1".repeat(64))),
            methodology: "stride".into(),
            source: ThreatModelRevisionSource::Import,
            source_revision_id: None,
            run_id: None,
            activate: Some(true),
            actor: "test".into(),
        },
    )
    .unwrap()
    .model_ref
}

mod diagram;
mod goal_guidance;
mod scanner;
mod scopes;

#[test]
fn existing_context_map_review_requires_inspection_and_uses_shared_dispatch() {
    let (root, mut app, first, _) = fixture();
    app.handle_study_context_key(KeyCode::Up);
    assert!(app
        .handle_study_context_key(KeyCode::Char('m'))
        .effects
        .is_empty());
    let result = inspect(&app, root.path(), &first);
    app.cache_tool_snapshot("threat-model:read", &result);
    let update = app.handle_study_context_key(KeyCode::Char('m'));
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("shared prepared dispatch required");
    };
    assert_eq!(request.tool_name, "campaign:context-map");
    assert_eq!(
        serde_json::from_str::<Value>(request.input.as_ref().unwrap()).unwrap()["threatModelRef"],
        json!(first)
    );
}

#[test]
fn existing_context_map_cache_matches_selection_and_never_substitutes_another_revision() {
    let (root, mut app, first, second) = fixture();
    app.handle_study_context_key(KeyCode::Up);
    let result = inspect(&app, root.path(), &first);
    app.cache_tool_snapshot("threat-model:read", &result);
    app.cache_context_map_result(
        &json!({"contextOrigin":"revision", "modelRef":second, "attemptId":"wrong-result"}),
    );
    assert_eq!(app.reviewed_context_map_attempt(), None);
    app.cache_context_map_result(
        &json!({"contextOrigin":"revision", "modelRef":first, "attemptId":"selected-result"}),
    );
    assert_eq!(app.reviewed_context_map_attempt(), Some("selected-result"));
    app.handle_study_context_key(KeyCode::Down);
    assert_eq!(app.reviewed_context_map_attempt(), None);
}

fn fixture() -> (tempfile::TempDir, ShellApp, ThreatModelRef, ThreatModelRef) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
    let first = commit(root.path(), "First context");
    let second = commit(root.path(), "Current context");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.open_batch_scan_config(None);
    app.hydrate_all_view_data_for_test();
    app.open_study_context_picker();
    (root, app, first, second)
}

fn inspect(app: &ShellApp, root: &std::path::Path, reference: &ThreatModelRef) -> Value {
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
        .prepare_dispatch_input(
            "threat-model:read",
            json!({"threatModelRef":reference}),
            &ctx,
            None,
        )
        .unwrap();
    app.registry()
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap()
}

#[test]
fn study_context_requires_inspection_then_binds_exact_revision_without_activation() {
    let (root, mut app, first, second) = fixture();
    app.handle_study_context_key(KeyCode::Up);
    assert_eq!(
        app.study_context_picker().unwrap().selected.as_ref(),
        Some(&first)
    );
    app.handle_study_context_key(KeyCode::Char('a'));
    assert!(app.study_context_picker().is_some());
    let update = app.handle_study_context_key(KeyCode::Enter);
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("shared prepared dispatch required");
    };
    assert_eq!(request.tool_name, "threat-model:read");
    let result = inspect(&app, root.path(), &first);
    app.cache_tool_snapshot("threat-model:read", &result);
    let investigation = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .investigation_id
        .clone();
    app.handle_study_context_key(KeyCode::Char('a'));
    assert!(app.study_context_picker().is_none());
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(
        config.study.scan_input.as_ref().unwrap()["threatModelRef"],
        json!(first)
    );
    assert_eq!(config.study.investigation_id, investigation);
    assert!(config.study.receipt.is_none());
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        second
    );
    let plan =
        super::super::launch::study_input(&app, root.path(), config, "context-study").unwrap();
    assert_eq!(plan["scanInput"]["threatModelRef"], json!(first));
}

#[test]
fn study_context_cancel_and_late_preview_preserve_draft_and_focus() {
    let (root, mut app, first, _) = fixture();
    app.set_input("unsent\noperator draft");
    app.set_cursor(4);
    let previous = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .clone();
    app.handle_study_context_key(KeyCode::Up);
    app.handle_study_context_key(KeyCode::Esc);
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study,
        previous
    );
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Prompt);
    let result = inspect(&app, root.path(), &first);
    app.cache_tool_snapshot("threat-model:read", &result);
    assert!(app.study_context_picker().is_none());
    assert_eq!((app.input(), app.cursor()), ("unsent\noperator draft", 4));
    assert_eq!(app.shell_view(), ShellView::Report);
}

#[test]
fn study_context_ignores_foreign_revision_and_omission_requires_explicit_action() {
    let (root, mut app, first, second) = fixture();
    let result = inspect(&app, root.path(), &first);
    app.cache_tool_snapshot("threat-model:read", &result);
    assert!(app.study_context_picker().unwrap().preview.is_none());
    app.handle_study_context_key(KeyCode::Up);
    app.handle_study_context_key(KeyCode::Up);
    assert!(app.study_context_picker().unwrap().selected.is_none());
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .scan_input
        .is_none());
    app.handle_study_context_key(KeyCode::Char('a'));
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .scan_input
        .as_ref()
        .unwrap()["threatModelRef"]
        .is_null());
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        second
    );
}

#[test]
fn study_context_reader_pages_at_every_viewport_and_plain_output_keeps_the_document() {
    let (root, mut app, _, second) = fixture();
    let result = inspect(&app, root.path(), &second);
    app.cache_tool_snapshot("threat-model:read", &result);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        assert!(screen.contains("CHOOSE STUDY CONTEXT"), "{screen}");
        assert!(screen.contains("Esc back"), "{screen}");
        let mut read = screen;
        for _ in 0..80 {
            let previous = app.study_context_picker().unwrap().detail_scroll;
            app.handle_study_context_key(KeyCode::PageDown);
            terminal
                .draw(|frame| crate::renderer::render_app(frame, &app))
                .unwrap();
            read.push_str(&format!("{:?}", terminal.backend().buffer()));
            if app.study_context_picker().unwrap().detail_scroll == previous {
                break;
            }
        }
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        assert!(
            read.contains("approved") && read.contains("scanning.") && read.contains("No model"),
            "{screen}"
        );
    }
    app.handle_study_context_key(KeyCode::Tab);
    let plain = crate::renderer::render_plain_app(&app, 80);
    assert!(plain.contains("Complete selected context document"));
    assert!(plain.contains("Which callers are trusted?"));
}
