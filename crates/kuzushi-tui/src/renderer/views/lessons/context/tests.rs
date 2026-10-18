use super::*;

fn app() -> ShellApp {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_shell_view(crate::ShellView::Lessons);
    app.router.lessons.context_selecting = true;
    app.router.lessons.context_confirm = Some(LessonContextBase {
        label: "Owned context · revision 1".into(),
        reference: kuzushi_core::ThreatModelRef {
            model_id: "tm_11111111111111111111111111111111".parse().unwrap(),
            revision_id: "tmr_22222222222222222222222222222222".parse().unwrap(),
            sha256: format!("sha256:{}", "a".repeat(64)),
        },
    });
    app.router.lessons.selected = vec![SelectedLesson {
        title: "Reviewed greeting lesson".into(),
        reference: kuzushi_core::findings::LessonRef {
            lesson_id: "lesson-id".into(),
            revision: 2,
            sha256: format!("sha256:{}", "b".repeat(64)),
        },
    }];
    app
}

fn text(lines: Vec<Line<'static>>) -> String {
    lines
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn confirmation_names_saved_choices_without_loading_a_catalog_or_ledger() {
    let app = app();
    let rendered = text(context_document_lines(&app, Rect::new(0, 0, 120, 36)));
    for expected in [
        "Base: Owned context · revision 1",
        "Reviewed greeting lesson · revision 2",
        "EXACT REVISIONS",
        "tm_11111111111111111111111111111111 / tmr_22222222222222222222222222222222",
        "Lesson: lesson-id / revision 2",
        "Home/End first/last",
    ] {
        assert!(rendered.contains(expected), "{rendered}");
    }
    assert!(rendered.contains(&"a".repeat(64)) && rendered.contains(&"b".repeat(64)));
}

#[test]
fn zero_selection_explicitly_removes_inherited_lessons_and_labels_are_safe() {
    let mut app = app();
    app.router.lessons.selected[0].title = "Greeting\u{1b}[2J".into();
    app.router.lessons.context_confirm.as_mut().unwrap().label = "Base\u{1b}[31m".into();
    assert!(!text(context_document_lines(&app, Rect::new(0, 0, 120, 36))).contains('\u{1b}'));
    app.router.lessons.selected.clear();
    let rendered = text(context_document_lines(&app, Rect::new(0, 0, 40, 12)));
    assert!(rendered.contains("Selected lessons: 0."));
    assert!(rendered.contains("Zero removes them."));
    assert!(!rendered.contains("Lesson: lesson-id"));
}

#[test]
fn narrow_confirmation_keeps_copy_back_and_reference_controls_visible() {
    use ratatui::{backend::TestBackend, Terminal};
    let mut app = app();
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, &app))
        .unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    for expected in ["Enter copy", "Esc base", "Home/End read"] {
        assert!(
            rendered.contains(expected),
            "Missing {expected}: {rendered}"
        );
    }
}
