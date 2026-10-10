use super::*;
use crate::app::{PlanningTaskId, PlanningTaskRow};
use serde_json::json;

fn setup() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    let tasks = [
        PlanningTaskId::GatherRepoContext,
        PlanningTaskId::ImportThreatModel,
    ];
    let rows = tasks
        .iter()
        .map(|task| PlanningTaskRow::for_task(*task, root.path()))
        .collect();
    app.engagement
        .planning_picker_mut()
        .open(rows, tasks.into_iter().collect());
    app.engagement.set_option_override(
        PlanningTaskId::ImportThreatModel,
        "path".into(),
        json!(format!(
            "{}/owned-context.json",
            "long-source-directory".repeat(12)
        )),
    );
    app.router.setup_mut().set_cursor(2);
    app.set_shell_view(ShellView::Setup);
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    app.set_input("preserved composer draft");
    (root, app)
}

fn key(app: &mut ShellApp, code: KeyCode) {
    let update = app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE));
    assert!(update.handled && update.effects.is_empty());
    assert!(!app.has_running_work());
}

#[test]
fn setup_details_keep_selection_draft_and_scroll_without_starting_work() {
    let (_root, mut app) = setup();
    let selected = app.engagement.planning_picker().selected().clone();
    let input = app
        .resolved_input_for_planning_task(PlanningTaskId::ImportThreatModel)
        .unwrap();
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.router.setup().editor(), Some(SetupEditor::Details));
    key(&mut app, KeyCode::PageDown);
    let position = app.router.setup().detail_scroll();
    assert!(position > 0);
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.router.setup().editor(), Some(SetupEditor::Details));
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.router.setup().editor(), None);
    assert_eq!(app.router.setup().cursor(), 2);
    assert_eq!(app.input(), "preserved composer draft");
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.router.setup().detail_scroll(), position);
    assert_eq!(app.engagement.planning_picker().selected(), &selected);
    assert_eq!(
        app.resolved_input_for_planning_task(PlanningTaskId::ImportThreatModel)
            .unwrap(),
        input
    );
}

#[test]
fn pasted_text_leaves_inspection_for_the_original_composer_without_submission() {
    let (_root, mut app) = setup();
    key(&mut app, KeyCode::Tab);
    let update = app.reduce_paste("\n東京 context notes");
    assert!(update.handled && update.effects.is_empty());
    assert_eq!(app.router.setup().editor(), None);
    assert!(app.input().contains("preserved composer draft"));
    assert!(app.editor().has_pasted_blocks());
    assert!(app.editor_mut().inspect_paste_at_cursor());
    assert!(app
        .editor()
        .paste_inspection()
        .unwrap()
        .text()
        .contains("東京 context notes"));
    assert!(app.picker_prompt_focused());
    assert_eq!(app.router.setup().cursor(), 2);
    assert!(!app.has_running_work());
}

#[test]
fn resizing_and_paging_use_the_actual_reading_body_and_preserve_row_positions() {
    let (_root, mut app) = setup();
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::End);
    assert_eq!(
        app.router.setup().detail_scroll(),
        crate::renderer::setup_detail_scroll(&app)
            .unwrap()
            .max_offset
    );
    key(&mut app, KeyCode::Home);
    assert_eq!(app.router.setup().detail_scroll(), 0);
    app.set_viewport(crate::TerminalViewport::new(80, 24));
    let page = crate::renderer::setup_detail_scroll(&app)
        .unwrap()
        .page_rows;
    key(&mut app, KeyCode::PageDown);
    assert!(app.router.setup().detail_scroll() <= page);
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Tab);
    assert_eq!(app.router.setup().detail_scroll(), 0);
}
