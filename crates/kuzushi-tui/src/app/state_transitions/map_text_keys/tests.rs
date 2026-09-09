use super::*;
use crate::app::{FilePickerPurpose, PlanningTaskId};
use kuzushi_core::{V2Config, WorkspaceTarget};

fn map_app(target: &std::path::Path, row: MapRunConfigRowId) -> ShellApp {
    let workspace = WorkspaceTarget::new(target).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.open_map_run_config().unwrap();
    app.begin_map_text_edit(row);
    app
}

fn press(app: &mut ShellApp, code: KeyCode, modifiers: KeyModifiers) -> InputUpdate {
    let update = app.reduce_key(KeyEvent::new(code, modifiers));
    assert!(update.handled);
    update
}

#[test]
fn map_document_keyboard_and_paste_keep_one_exact_path() {
    let target = tempfile::tempdir().unwrap();
    let name = "Architecture, v2.md";
    std::fs::write(target.path().join(name), "context").unwrap();
    let mut app = map_app(target.path(), MapRunConfigRowId::DesignDocs);
    app.set_input("reserved shell draft".to_string());
    press(&mut app, KeyCode::Char('A'), KeyModifiers::SHIFT);
    assert!(app.reduce_paste("rchitecture, v2.md").handled);
    let update = press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert!(
        update.effects.is_empty(),
        "saving a field must not dispatch work"
    );
    let list = app.router.setup().map_run_config().text().unwrap();
    assert_eq!(list.values, [name]);
    assert!(list.field.is_none());
    assert_eq!(app.input(), "reserved shell draft");
    let input = app
        .resolved_input_for_planning_task(PlanningTaskId::BuildThreatModel)
        .unwrap();
    assert_eq!(input["designDocs"].as_array().unwrap().len(), 1);
}

#[test]
fn multiline_context_edits_at_cursor_and_saves_one_complete_entry() {
    let target = tempfile::tempdir().unwrap();
    let mut app = map_app(target.path(), MapRunConfigRowId::Context);
    app.reduce_paste("alpha");
    press(&mut app, KeyCode::Left, KeyModifiers::NONE);
    press(&mut app, KeyCode::Char('X'), KeyModifiers::SHIFT);
    press(&mut app, KeyCode::End, KeyModifiers::NONE);
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    app.reduce_paste("Second line, with commas\nand another line");
    let update = press(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
    assert!(update.effects.is_empty());
    let list = app.router.setup().map_run_config().text().unwrap();
    assert_eq!(
        list.values,
        ["alphXa\nSecond line, with commas\nand another line"]
    );
    assert!(list.field.is_none());
}

#[test]
fn invalid_document_keeps_its_draft_and_escape_cancels_without_saving() {
    let target = tempfile::tempdir().unwrap();
    let mut app = map_app(target.path(), MapRunConfigRowId::DesignDocs);
    app.reduce_paste("missing.md");
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    let state = app.router.setup().map_run_config();
    assert!(state.error().unwrap().contains("missing.md"));
    let list = state.text().unwrap();
    assert_eq!(list.field.as_ref().unwrap().text(), "missing.md");
    assert!(list.values.is_empty());
    press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    assert!(app
        .router
        .setup()
        .map_run_config()
        .text()
        .unwrap()
        .field
        .is_none());
    press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    assert!(app.router.setup().map_run_config().text().is_none());
    assert_eq!(app.shell_view(), ShellView::Setup);
}

#[test]
fn document_picker_returns_to_the_plan_without_a_knowledge_base_attachment() {
    let target = tempfile::tempdir().unwrap();
    let name = "Architecture, v2.md";
    std::fs::write(target.path().join(name), "context").unwrap();
    let mut app = map_app(target.path(), MapRunConfigRowId::DesignDocs);
    press(&mut app, KeyCode::Char('o'), KeyModifiers::CONTROL);
    assert_eq!(app.shell_view(), ShellView::FilePicker);
    assert_eq!(
        app.router.file_picker().purpose(),
        FilePickerPurpose::MapDocument
    );
    app.router
        .file_picker_mut()
        .replace_files(vec![name.into()], false);
    let update = press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert!(update.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(
        app.router.setup().map_run_config().text().unwrap().values,
        [name]
    );
    app.open_file_picker();
    assert_eq!(
        app.router.file_picker().purpose(),
        FilePickerPurpose::KnowledgeBase
    );
}

#[test]
fn file_search_owns_printable_keys_and_paste_instead_of_attaching_or_quitting() {
    let target = tempfile::tempdir().unwrap();
    let mut app = map_app(target.path(), MapRunConfigRowId::DesignDocs);
    press(&mut app, KeyCode::Char('o'), KeyModifiers::CONTROL);
    for ch in ['q', 'j', 'k'] {
        press(&mut app, KeyCode::Char(ch), KeyModifiers::NONE);
    }
    assert_eq!(app.router.file_picker().query(), "qjk");
    press(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
    let update = app.reduce_paste("Architecture, v2.md");
    assert!(update.effects.is_empty());
    assert_eq!(app.router.file_picker().query(), "Architecture, v2.md");
    assert_eq!(app.shell_view(), ShellView::FilePicker);
    assert!(app.input().is_empty());
}

#[test]
fn canceling_document_selection_restores_the_same_entry_list() {
    let target = tempfile::tempdir().unwrap();
    let mut app = map_app(target.path(), MapRunConfigRowId::DesignDocs);
    app.router.setup_mut().map_run_config_mut().begin_edit(
        MapRunConfigRowId::DesignDocs,
        vec!["first.md".into(), "second.md".into()],
    );
    app.router
        .setup_mut()
        .map_run_config_mut()
        .text_mut()
        .unwrap()
        .cursor = 1;
    let before = app.router.setup().map_run_config().clone();
    press(&mut app, KeyCode::Char('f'), KeyModifiers::NONE);
    press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(app.router.setup().map_run_config(), &before);
}

#[test]
fn quitting_with_a_map_draft_discloses_it_without_echoing_its_content() {
    let target = tempfile::tempdir().unwrap();
    let mut app = map_app(target.path(), MapRunConfigRowId::Context);
    app.reduce_paste("private architecture draft");
    press(&mut app, KeyCode::Char('c'), KeyModifiers::CONTROL);
    assert_eq!(app.shell_view(), ShellView::QuitConfirm);
    let rendered = crate::renderer::render_plain_app(&app, 120);
    assert!(rendered.contains("Map draft"));
    assert!(!rendered.contains("private architecture draft"));
    press(&mut app, KeyCode::Char('n'), KeyModifiers::NONE);
    assert_eq!(
        app.router
            .setup()
            .map_run_config()
            .text()
            .unwrap()
            .field
            .as_ref()
            .unwrap()
            .text(),
        "private architecture draft"
    );
}
