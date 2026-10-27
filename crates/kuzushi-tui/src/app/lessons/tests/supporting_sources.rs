use super::*;
use serde_json::json;

fn app() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let (workspace, store, _) = fixture::prepare(root.path());
    let mut app = ShellApp::new(
        kuzushi_core::V2Config {
            model: Some("openai-codex:gpt-5.5".into()),
            ..Default::default()
        },
        Some(&workspace),
    );
    app.open_lessons();
    app.router.lessons.finding_id = store.list_all_findings().unwrap()[0].id;
    app.plan_lesson_generation();
    (root, app)
}

fn press(app: &mut ShellApp, code: KeyCode) {
    assert!(app
        .reduce_key(KeyEvent::new(code, KeyModifiers::NONE))
        .effects
        .is_empty());
}

#[test]
fn lesson_file_basket_cancels_or_applies_without_spending_or_losing_guidance() {
    let (_root, mut app) = app();
    let origin = app.shell_view();
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .context_generation
        .as_mut()
        .unwrap()
        .context_input["guidance"] = json!("Retain this guidance");
    press(&mut app, KeyCode::Char('f'));
    assert_eq!(app.shell_view(), ShellView::FilePicker);
    app.router.file_picker_mut().replace_files(Vec::new(), true);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let screen = super::reader::render(&app, width, height);
        let plain = crate::renderer::render_plain_app(&app, width as usize);
        for text in [screen, plain] {
            assert!(text.contains("Partial list"));
            assert!(text.contains("historical source"));
        }
    }
    app.router.file_picker_mut().paste_query("historical.txt");
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), origin);
    assert!(app
        .context_generation()
        .unwrap()
        .context_input
        .get("sourceEvidenceFiles")
        .is_none());
    press(&mut app, KeyCode::Char('f'));
    app.router
        .file_picker_mut()
        .paste_query("missing-historical.txt");
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Tab);
    assert_eq!(
        app.router.file_picker().filtered_paths(),
        ["missing-historical.txt"]
    );
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.shell_view(), origin);
    let generation = app.context_generation().unwrap();
    assert_eq!(
        generation.context_input["sourceEvidenceFiles"],
        json!(["missing-historical.txt"])
    );
    assert_eq!(generation.context_input["guidance"], "Retain this guidance");
    assert!(!app.has_running_work());
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .allowance
        .is_none());
}

#[test]
fn lesson_source_reader_owns_input_and_restores_plan_position() {
    let (root, mut app) = app();
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
    let input = json!({"campaignId":"lesson-source-reader","investigationId":"reader-test","generationTool":"findings:lesson-generate","contextInput":{"findingId":store.list_all_findings().unwrap()[0].id,"sourceEvidenceFiles":["hello.txt","missing.txt"]}});
    let ctx = kuzushi_core::ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = kuzushi_core::ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("campaign:context-study", input, &ctx, None)
        .unwrap();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    let receipt = serde_json::from_value(result["data"].clone()).unwrap();
    let generation = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .context_generation
        .as_mut()
        .unwrap();
    generation.receipt = Some(receipt);
    generation.scroll = 7;
    press(&mut app, KeyCode::Char('f'));
    assert_ne!(app.shell_view(), ShellView::FilePicker);
    press(&mut app, KeyCode::Char('v'));
    assert!(app.context_generation().unwrap().lesson_sources.is_some());
    app.editor_mut().set_input("Preserved composer draft");
    assert!(app
        .reduce_paste("Multiline paste\n東京 stays outside the composer")
        .effects
        .is_empty());
    assert_eq!(app.editor().input(), "Preserved composer draft");
    let text = crate::ui_view_models::context_generation::generation_lines(&app, 80).join("\n");
    assert!(text.contains("HISTORICAL LESSON SOURCE"));
    assert!(text.contains("no retained source membership"));
    for code in [
        KeyCode::Enter,
        KeyCode::Char('t'),
        KeyCode::Char('n'),
        KeyCode::Char('f'),
        KeyCode::Char('G'),
    ] {
        press(&mut app, code);
        assert!(app.context_generation().unwrap().lesson_sources.is_some());
    }
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Esc);
    assert!(app.context_generation().unwrap().lesson_sources.is_none());
    assert_eq!(app.context_generation().unwrap().scroll, 7);
    assert!(!app.has_running_work());
    assert!(store.finding_lessons(50, 0).unwrap().rows.is_empty());
}

#[test]
fn a_cited_only_lesson_plan_does_not_advertise_a_saved_supporting_bundle() {
    let (root, mut app) = app();
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = kuzushi_core::ToolExecutionContext {
        config: app.config(),
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let input = json!({"campaignId":"cited-only","investigationId":"reader-test","generationTool":"findings:lesson-generate","contextInput":{"findingId":store.list_all_findings().unwrap()[0].id}});
    let registry = kuzushi_core::ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("campaign:context-study", input, &ctx, None)
        .unwrap();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .context_generation
        .as_mut()
        .unwrap()
        .receipt = Some(serde_json::from_value(result["data"].clone()).unwrap());
    assert!(!app.context_generation().unwrap().has_lesson_source_bundle());
    let text = crate::ui_view_models::context_generation::generation_lines(&app, 80).join("\n");
    assert!(text.contains("cited capture only"));
    assert!(!text.contains("v reads"));
    press(&mut app, KeyCode::Char('v'));
    assert!(app.context_generation().unwrap().lesson_sources.is_none());
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("Use n, then f"));
    assert!(!app.has_running_work());
}
