use super::*;

fn base(label: &str) -> LessonContextBase {
    LessonContextBase {
        reference: kuzushi_core::ThreatModelRef {
            model_id: "tm_11111111111111111111111111111111".parse().unwrap(),
            revision_id: "tmr_22222222222222222222222222222222".parse().unwrap(),
            sha256: format!("sha256:{}", "a".repeat(64)),
        },
        label: label.into(),
    }
}

fn lesson(index: usize) -> SelectedLesson {
    SelectedLesson {
        reference: LessonRef {
            lesson_id: format!("lesson-{index}"),
            revision: 2,
            sha256: format!("sha256:{}", "b".repeat(64)),
        },
        title: format!("Reviewed lesson {index}"),
    }
}

#[test]
fn context_choice_keeps_its_label_and_reference_after_catalog_changes() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let chosen = base("Owned context · revision 1");
    let mut rows = vec![crate::ui_view_models::study_context::ContextRow {
        reference: Some(chosen.reference.clone()),
        label: chosen.label.clone(),
        details: Vec::new(),
        copy_label: None,
    }];
    app.choose_lesson_context_base(&rows);
    rows[0].label = "Changed context".into();
    rows[0].reference = None;
    assert_eq!(app.router.lessons.context_confirm, Some(chosen));
    app.choose_lesson_context_base(&rows);
    assert!(app.router.lessons.context_confirm.is_none());
    assert!(app.runtime_state.lesson_write.is_none());
}

#[test]
fn copy_input_contains_exact_references_without_presentation_fields() {
    let chosen = base("Readable context label");
    let selected = vec![lesson(1), lesson(2)];
    assert_eq!(
        context_copy_input(&chosen, &selected),
        serde_json::json!({
            "threatModelRef":chosen.reference,
            "lessons":[selected[0].reference, selected[1].reference],
        })
    );
    assert_eq!(
        context_copy_input(&chosen, &[])["lessons"],
        serde_json::json!([])
    );
}

#[test]
fn selection_limit_preserves_the_existing_names_and_revisions() {
    let mut selected = (0..8).map(lesson).collect::<Vec<_>>();
    let before = selected.clone();
    assert!(toggle_reference(&mut selected, lesson(8)).is_err());
    assert_eq!(selected, before);
    let mut changed = lesson(0);
    changed.title = "Later title".into();
    changed.reference.revision = 3;
    toggle_reference(&mut selected, changed).unwrap();
    assert_eq!(selected, before[1..]);
}

#[test]
fn confirmation_navigation_is_bounded_after_resize_and_preserves_input() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_shell_view(ShellView::Lessons);
    app.router.lessons.context_selecting = true;
    app.router.lessons.context_confirm = Some(base("Chosen base"));
    app.router.lessons.selected = (0..8).map(lesson).collect();
    app.editor_mut().set_input("Retained composer");
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48), (96, 89)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let scroll = crate::renderer::lesson_reader_scroll(&app).unwrap();
        let maximum = scroll.max_offset;
        app.reduce_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        assert_eq!(app.router.default_scroll().offset(), maximum);
        app.reduce_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert_eq!(
            app.router.default_scroll().offset(),
            maximum.saturating_sub(scroll.page_rows)
        );
        app.reduce_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
        assert_eq!(app.router.default_scroll().offset(), 0);
        app.reduce_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(
            app.router.default_scroll().offset(),
            maximum.min(scroll.page_rows)
        );
    }
    app.handle_lesson_context_confirm(KeyCode::Esc);
    assert!(app.router.lessons.context_confirm.is_none());
    assert_eq!(app.router.default_scroll().offset(), 0);
    assert_eq!(app.editor().input(), "Retained composer");
    assert!(app.runtime_state.lesson_write.is_none());
}
