use super::*;
use crate::app::{InputMode, PickerFocus, SetupEditor, ShellApp, ShellView};
use kuzushi_core::V2Config;

#[test]
fn report_prompt_names_its_actual_return_and_destination_controls() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Navigate);
    let text = inactive_prompt_line(&app, 120).unwrap().to_string();
    assert!(text.contains("e edits path"), "{text}");
    assert!(text.contains("Esc returns"), "{text}");
    assert!(!text.contains("returns to prompt"), "{text}");
}

#[test]
fn picker_prompt_hints_follow_list_ownership_in_navigation_mode() {
    for (view, editor) in [
        (ShellView::Setup, None),
        (ShellView::Setup, Some(SetupEditor::Model)),
        (ShellView::Setup, Some(SetupEditor::Credentials)),
        (ShellView::TargetPicker, None),
        (ShellView::PlanningPicker, None),
    ] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(view);
        if let Some(editor) = editor {
            app.router.setup_mut().begin_editor(editor);
        }
        app.set_input_mode(InputMode::Navigate);
        let line = inactive_prompt_line(&app, 120).unwrap().to_string();
        assert!(line.contains("move"), "{view:?}: {line}");
        if view == ShellView::Setup && editor.is_none() {
            assert!(line.contains("Tab details"), "{line}");
        }
        assert!(!line.contains("Esc returns to prompt"), "{line}");
    }
}

#[test]
fn picker_prompt_text_remains_visible_when_it_owns_input() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.open_model_picker();
    app.set_input_mode(InputMode::Navigate);
    app.router.model_picker_mut().set_focus(PickerFocus::Prompt);
    app.set_input("back");
    assert!(inactive_prompt_line(&app, 120).is_none());
}

#[test]
fn picker_prompt_priority_preserves_normal_config_navigation_guidance() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Config);
    app.set_input_mode(InputMode::Navigate);
    let line = inactive_prompt_line(&app, 120).unwrap().to_string();
    assert!(line.contains("Esc returns to prompt"), "{line}");
}

#[test]
fn comparison_navigation_names_the_return_action() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::RunDiff);
    app.set_input_mode(InputMode::Navigate);
    let line = inactive_prompt_line(&app, 120).unwrap().to_string();
    assert!(line.contains("Esc back"));
    assert!(!line.contains("returns to prompt"));
}

#[test]
fn narrow_picker_prompt_renders_selection_and_command_controls_without_clipping() {
    use ratatui::{backend::TestBackend, Terminal};
    for view in [
        ShellView::Setup,
        ShellView::TargetPicker,
        ShellView::PlanningPicker,
    ] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(view);
        let mut terminal = Terminal::new(TestBackend::new(40, 1)).unwrap();
        terminal
            .draw(|frame| render_prompt(frame, frame.area(), &app))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        let hints = if view == ShellView::Setup {
            vec!["↑↓ move", "Tab details", "Enter", "type cmd"]
        } else {
            vec!["↑/↓ move", "Enter select", "type command"]
        };
        for hint in hints {
            assert!(text.contains(hint), "{view:?} missing {hint}: {text}");
        }
    }
}
