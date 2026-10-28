use super::*;
use kuzushi_core::findings::LessonGeneration;

fn reading_app() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let (workspace, store, _) = fixture::prepare(root.path());
    let id = store.list_all_findings().unwrap()[0].id.unwrap();
    store
        .draft_finding_lesson(
            LessonContent {
                title: "Labeled model lesson".into(),
                text: (0..30)
                    .map(|i| format!("evidence-line-{i:02}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                applicability: "Owned fixture review".into(),
                limitations: "Historical synthetic guidance".into(),
            },
            store.lesson_origin(root.path(), id).unwrap(),
            Some(LessonGeneration {
                model: "openai-codex:gpt-5.5".into(),
                source_capture: "included".into(),
                input_bytes: 2048,
                synthesis_requests: 1,
                source_evidence_ref: None,
                run_id: Some("owned-model-run".into()),
                prompt_sha256: format!("sha256:{}", "a".repeat(64)),
            }),
        )
        .unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.open_lessons();
    app.workbench_cache().borrow_mut().lesson_pages.insert(
        (workspace.root().into(), 0),
        Ok(store.finding_lessons(50, 0).unwrap()),
    );
    (root, app)
}

fn press(app: &mut ShellApp, code: KeyCode) {
    assert!(
        app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE))
            .handled
    );
}

pub(super) fn render(app: &ShellApp, width: u16, height: u16) -> String {
    use ratatui::{backend::TestBackend, Terminal};
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    format!("{:?}", terminal.backend().buffer())
}

#[test]
fn page_keys_reach_every_evidence_line_without_gaps_at_all_six_sizes() {
    let (_root, mut app) = reading_app();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48), (96, 89)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        press(&mut app, KeyCode::Home);
        let mut pages = String::new();
        for _ in 0..100 {
            pages.push_str(&render(&app, width, height));
            let before = app.router.default_scroll().offset();
            press(&mut app, KeyCode::PageDown);
            if before == app.router.default_scroll().offset() {
                break;
            }
        }
        for index in 0..30 {
            assert!(
                pages.contains(&format!("evidence-line-{index:02}")),
                "Skipped {index} at {width}x{height}"
            );
        }
        assert!(pages.contains("Captured historical source supplied."));
        assert!(app.runtime_state.lesson_write.is_none());
    }
}

#[test]
fn prompt_and_field_carets_keep_boundary_keys_while_page_keys_preserve_the_composer() {
    let (_root, mut app) = reading_app();
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    app.set_input_mode(InputMode::Prompt);
    app.editor_mut().set_input("Retained composer");
    press(&mut app, KeyCode::Home);
    assert_eq!(app.editor().cursor(), 0);
    press(&mut app, KeyCode::PageDown);
    assert_eq!(app.editor().input(), "Retained composer");
    assert_eq!(app.editor().cursor(), 0);
    app.router.lessons.finding_id = Some(1);
    app.begin_lesson_draft(false);
    app.paste_lesson_field("Unsaved field");
    let mut expected = app.router.lessons.form.as_ref().unwrap().fields[0].clone();
    expected.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    press(&mut app, KeyCode::Home);
    assert_eq!(
        app.router.lessons.form.as_ref().unwrap().fields[0],
        expected
    );
    assert!(!app.router.lessons.form.as_ref().unwrap().confirming);
}

#[test]
fn a_visible_context_picker_keeps_keys_away_from_a_retained_hidden_form() {
    let (_root, mut app) = reading_app();
    app.router.lessons.finding_id = Some(1);
    app.begin_lesson_draft(false);
    app.paste_lesson_field("Retained hidden form");
    let form = app.router.lessons.form.clone();
    app.router.lessons.context_selecting = true;
    press(&mut app, KeyCode::Char('x'));
    assert_eq!(app.router.lessons.form, form);
    assert!(app.runtime_state.lesson_write.is_none());
}
