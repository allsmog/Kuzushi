use super::*;
use crate::app::ShellEffect;
use crossterm::event::KeyModifiers;
use kuzushi_core::{
    capabilities::threat_model::{
        commit_threat_model_revision, load_active_threat_model, ScopeRef, ThreatModelCommit,
        ThreatModelRevisionSource,
    },
    modules::ToolExecutionContext,
    V2Config, WorkspaceTarget,
};
use ratatui::{backend::TestBackend, Terminal};

fn commit(root: &std::path::Path, label: &str) -> ThreatModelRef {
    commit_threat_model_revision(root, &json!({"version":"1","methodology":"stride","systemContext":label,"dfd":{"nodes":[{"id":"app","name":label,"type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{},"openQuestions":[{"question":"Owner?","answer":label}]}), ThreatModelCommit {
        model_id: None, new_model: true, label: label.into(),
        scope: ScopeRef::legacy_root(root, &format!("sha256:{}", "1".repeat(64))),
        methodology: "stride".into(), source: ThreatModelRevisionSource::Import,
        source_revision_id: None, run_id: None, activate: Some(true), actor: "test".into(),
    }).unwrap().model_ref
}

fn fixture() -> (tempfile::TempDir, ShellApp, ThreatModelRef, ThreatModelRef) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("owned.txt"), "Owned inert fixture").unwrap();
    let alpha = commit(root.path(), "Alpha");
    let beta = commit(root.path(), "Beta");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.set_shell_view(ShellView::Home);
    app.hydrate_all_view_data_for_test();
    app.open_context_history();
    app.router.threat_mut().open(ThreatView::Models);
    app.set_shell_view(ShellView::Threat);
    (root, app, alpha, beta)
}

fn key(app: &mut ShellApp, code: KeyCode) -> InputUpdate {
    app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn complete(app: &mut ShellApp, update: InputUpdate) -> Value {
    let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
        panic!("Expected shared tool preparation");
    };
    let workspace = WorkspaceTarget::new(app.target().unwrap()).unwrap();
    let input = serde_json::from_str(request.input.as_ref().unwrap()).unwrap();
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
        .prepare_dispatch_input(&request.tool_name, input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let result = app
        .registry()
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    app.cache_tool_snapshot(&request.tool_name, &result);
    result
}

#[test]
fn keyboard_history_inspects_exact_inactive_revision_and_compares_without_activation() {
    let (root, mut app, alpha, beta) = fixture();
    key(&mut app, KeyCode::Home);
    let inspect = key(&mut app, KeyCode::Enter);
    let result = complete(&mut app, inspect);
    assert_eq!(result["data"]["modelRef"], json!(alpha));
    assert_eq!(
        app.context_history().unwrap().data.as_ref().unwrap()["document"]["systemContext"],
        "Alpha"
    );
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Char('b'));
    key(&mut app, KeyCode::End);
    let compare = key(&mut app, KeyCode::Char('c'));
    let result = complete(&mut app, compare);
    assert_eq!(result["data"]["from"]["sha256"], alpha.sha256);
    assert_eq!(result["data"]["to"]["sha256"], beta.sha256);
    assert_eq!(
        result["data"]["target"],
        json!(std::fs::canonicalize(root.path()).unwrap())
    );
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        beta
    );
    assert_eq!(
        app.context_history().unwrap().baseline.as_ref(),
        Some(&alpha)
    );
}

#[test]
fn comparison_rejects_foreign_target_wrong_digest_and_late_completion() {
    let (root, mut app, alpha, beta) = fixture();
    app.router
        .threat_mut()
        .history_mut()
        .unwrap()
        .begin(ContextHistoryRequest::Compare {
            baseline: alpha.clone(),
            candidate: beta.clone(),
        });
    let valid = json!({"target":std::fs::canonicalize(root.path()).unwrap(), "from":{"modelId":alpha.model_id,"revisionId":alpha.revision_id,"sha256":alpha.sha256},"to":{"modelId":beta.model_id,"revisionId":beta.revision_id,"sha256":beta.sha256},"contextText":[]});
    let mut bad = valid.clone();
    bad["target"] = json!("/another/target");
    assert!(!app.cache_context_history_result("threat-model:diff", &bad));
    bad = valid.clone();
    bad["to"]["sha256"] = json!("wrong");
    assert!(!app.cache_context_history_result("threat-model:diff", &bad));
    assert!(app.cache_context_history_result("threat-model:diff", &valid));
    key(&mut app, KeyCode::Esc);
    assert!(!app.cache_context_history_result("threat-model:diff", &valid));
    assert!(app.context_history().unwrap().data.is_none());
}

#[test]
fn history_failure_is_retained_and_retry_uses_the_same_exact_reference() {
    let (_root, mut app, alpha, _) = fixture();
    key(&mut app, KeyCode::Home);
    key(&mut app, KeyCode::Enter);
    app.context_history_failed("threat-model:read", "Saved object is missing");
    let retry = key(&mut app, KeyCode::Enter);
    let [ShellEffect::PrepareRunTool(request)] = retry.effects.as_slice() else {
        panic!("retry must prepare a tool");
    };
    let input: Value = serde_json::from_str(request.input.as_ref().unwrap()).unwrap();
    assert_eq!(input["threatModelRef"], json!(alpha));
    assert!(app.context_history().unwrap().error.is_none());
}

#[test]
fn history_navigation_preserves_draft_origin_and_local_scroll() {
    let (_root, mut app, _, _) = fixture();
    app.editor_mut().set_input("Preserved operator draft α");
    key(&mut app, KeyCode::PageDown);
    let scroll = app.context_history().unwrap().scroll;
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.context_history().unwrap().scroll, scroll);
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Home);
    assert_eq!(app.input(), "Preserved operator draft α");
}

#[test]
fn history_paste_returns_losslessly_to_the_composer_without_submitting() {
    let (_root, mut app, _, _) = fixture();
    let update = app.reduce_paste("First line α\nSecond line");
    assert!(update.effects.is_empty());
    assert!(app.context_history().is_none());
    assert_eq!(app.editor().expanded_input(), "First line α\nSecond line");
}

#[test]
fn explicit_activation_and_restore_prepare_the_selected_historical_id() {
    let (_root, mut app, alpha, _) = fixture();
    key(&mut app, KeyCode::Home);
    for code in [KeyCode::Char('a'), KeyCode::Char('r')] {
        let update = key(&mut app, code);
        let [ShellEffect::PrepareRunTool(request)] = update.effects.as_slice() else {
            panic!("Expected shared preparation");
        };
        let input: Value = serde_json::from_str(request.input.as_ref().unwrap()).unwrap();
        assert_eq!(input["revisionId"], json!(alpha.revision_id));
    }
}

#[test]
fn full_reader_is_paged_at_each_viewport_and_plain_output_retains_all_text() {
    let (_root, mut app, _, _) = fixture();
    key(&mut app, KeyCode::Home);
    let update = key(&mut app, KeyCode::Enter);
    complete(&mut app, update);
    for (columns, rows) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        app.set_viewport(crate::app::TerminalViewport::new(columns, rows));
        let mut terminal = Terminal::new(TestBackend::new(columns, rows)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("INSPECT CONTEXT"));
        assert!(text.contains("Lines 1-"));
        assert!(
            text.contains("Esc back"),
            "visible back control required at {columns}x{rows}"
        );
        key(&mut app, KeyCode::End);
        let end = app.context_history().unwrap().scroll;
        key(&mut app, KeyCode::Up);
        assert_eq!(app.context_history().unwrap().scroll, end.saturating_sub(1));
        key(&mut app, KeyCode::Home);
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    assert!(plain.contains("Alpha"));
    assert!(plain.contains("openQuestions"));
    assert!(plain.contains("Context digest"));
}

#[test]
fn history_tab_preserves_both_document_and_summary_positions() {
    let (_root, mut app, _, _) = fixture();
    let update = key(&mut app, KeyCode::Enter);
    complete(&mut app, update);
    app.set_viewport(crate::app::TerminalViewport::new(40, 12));
    key(&mut app, KeyCode::End);
    let summary_scroll = app.context_history().unwrap().scroll;
    key(&mut app, KeyCode::Tab);
    assert!(app.context_history().unwrap().document_raw);
    key(&mut app, KeyCode::End);
    let document_scroll = app.context_history().unwrap().scroll;
    assert!(document_scroll > summary_scroll);
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.context_history().unwrap().scroll, summary_scroll);
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.context_history().unwrap().scroll, document_scroll);
}

#[test]
fn history_digit_opens_browser_and_escape_restores_the_origin_projection() {
    let (_root, mut app, _, _) = fixture();
    key(&mut app, KeyCode::Esc);
    app.router.threat_mut().open(ThreatView::Summary);
    app.set_shell_view(ShellView::Threat);
    app.router.default_scroll_mut().set(9);
    key(&mut app, KeyCode::Char('6'));
    assert!(app.context_history().is_some());
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.router.threat().view(), ThreatView::Summary);
    assert_eq!(app.router.default_scroll().offset(), 9);
}

#[test]
fn explicit_history_writes_have_real_receipts_and_preserve_the_original_selection() {
    let (root, mut app, alpha, _) = fixture();
    key(&mut app, KeyCode::Home);
    let activate = key(&mut app, KeyCode::Char('a'));
    complete(&mut app, activate);
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        alpha
    );
    assert!(app
        .context_history()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("Activated"));
    let restore = key(&mut app, KeyCode::Char('r'));
    complete(&mut app, restore);
    assert_ne!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        alpha
    );
    assert_eq!(
        app.context_history().unwrap().selected.as_ref(),
        Some(&alpha)
    );
    assert!(app
        .context_history()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("Restored"));
}

#[test]
fn history_completion_keeps_the_background_navigation_and_draft() {
    let (_root, mut app, _, _) = fixture();
    let update = key(&mut app, KeyCode::Enter);
    app.set_shell_view(ShellView::Report);
    app.editor_mut().set_input("retained draft");
    complete(&mut app, update);
    assert!(app.router.threat().history().unwrap().data.is_some());
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.input(), "retained draft");
}

#[test]
fn history_write_receipt_names_its_original_subject_after_cursor_movement() {
    let (root, mut app, alpha, beta) = fixture();
    key(&mut app, KeyCode::Home);
    let activate = key(&mut app, KeyCode::Char('a'));
    key(&mut app, KeyCode::Down);
    complete(&mut app, activate);
    let state = app.context_history().unwrap();
    assert_eq!(state.selected.as_ref(), Some(&beta));
    assert_eq!(
        state.notice.as_deref(),
        Some("Activated Alpha · revision 1.")
    );
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        alpha
    );
}
