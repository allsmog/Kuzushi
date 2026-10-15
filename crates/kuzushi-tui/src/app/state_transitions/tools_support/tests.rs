use super::*;
use kuzushi_core::V2Config;

fn app(filter: &str) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.tools_mut().open(Some(filter.into()));
    app.set_shell_view(ShellView::Tools);
    app
}

fn key(app: &mut ShellApp, code: KeyCode) -> InputUpdate {
    app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE))
}

#[test]
fn support_enter_opens_settings_and_back_restores_filter_selection_and_draft() {
    let mut app = app("module:govulncheck");
    app.set_input("preserved operator\ndraft");
    app.set_cursor(5);
    app.set_input_mode(InputMode::Navigate);
    assert!(key(&mut app, KeyCode::Enter).effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::Options);
    assert_eq!(app.router.options().tool_name, "govulncheck:scan");
    assert_eq!(
        (app.input(), app.cursor()),
        ("preserved operator\ndraft", 5)
    );
    assert!(!app.has_running_work());
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Tools);
    assert_eq!(app.router.tools().filter(), Some("module:govulncheck"));
    assert_eq!(
        app.router.tools().selected_support(),
        Some("govulncheck:scan")
    );
    assert_eq!(app.input_mode(), InputMode::Navigate);
    assert_eq!(
        (app.input(), app.cursor()),
        ("preserved operator\ndraft", 5)
    );
}

#[test]
fn support_selection_reaches_every_match_and_survives_resize() {
    let mut app = app("module:fuzz");
    let names = crate::ui_view_models::tools_model(&app)
        .omitted_support
        .into_iter()
        .map(|tool| tool.tool)
        .collect::<Vec<_>>();
    assert!(names.len() > 5);
    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            key(&mut app, KeyCode::Down);
        }
        app.set_viewport(crate::TerminalViewport::new(40, 12));
        key(&mut app, KeyCode::Enter);
        assert_eq!(&app.router.options().tool_name, name);
        key(&mut app, KeyCode::Esc);
        assert_eq!(app.router.tools().selected_support(), Some(name.as_str()));
        assert!(!app.has_running_work());
    }
    key(&mut app, KeyCode::Down);
    assert_eq!(
        app.router.tools().selected_support(),
        names.last().map(String::as_str)
    );
}

#[test]
fn escape_returns_the_empty_composer_to_prompt_ownership() {
    let mut app = app("module:govulncheck");
    assert!(app.tools_support_owns_input());
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert!(!app.tools_support_owns_input());
    app.reduce_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
    assert_eq!(app.input(), "x");
    assert!(!app.has_running_work());
}

#[test]
fn notice_escape_dismisses_before_leaving_the_support_reader_or_settings() {
    let mut app = app("module:govulncheck");
    app.set_warn_notice("owned", "review this notice");
    key(&mut app, KeyCode::Esc);
    assert!(app.tools_support_owns_input());
    key(&mut app, KeyCode::Enter);
    app.set_warn_notice("owned", "review settings notice");
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Options);
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Tools);
}

#[test]
fn settings_footer_names_tools_back_instead_of_prompt_ownership() {
    let mut app = app("module:govulncheck");
    key(&mut app, KeyCode::Enter);
    let bindings = crate::ui_view_models::footer_keybindings(&app);
    assert!(bindings
        .iter()
        .any(|binding| binding.key == "Esc" && binding.label == "tools"));
    assert!(!bindings
        .iter()
        .any(|binding| binding.key == "Esc" && binding.label == "prompt"));
}

#[test]
fn prompt_draft_and_unknown_or_core_filters_keep_their_input_owner() {
    let mut app = app("module:govulncheck");
    app.set_input_mode(InputMode::Prompt);
    app.set_input("do not dispatch this draft");
    assert!(!app.tools_support_owns_input());
    assert!(app
        .handle_tools_support_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .is_none());
    assert_eq!(app.input(), "do not dispatch this draft");
    for filter in ["module:unknown-owned", "module:semgrep"] {
        app.set_input("");
        app.router.tools_mut().open(Some(filter.into()));
        assert!(!app.tools_support_owns_input());
    }
}

#[test]
fn field_escape_keeps_its_draft_before_returning_to_tools() {
    let mut app = app("module:govulncheck");
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Enter);
    assert!(app.tool_option_editor_open());
    app.reduce_paste("owned draft path");
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Options);
    assert!(!app.tool_option_editor_open());
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Tools);
    key(&mut app, KeyCode::Enter);
    key(&mut app, KeyCode::Enter);
    assert!(app
        .router
        .options_browser()
        .edit
        .as_ref()
        .unwrap()
        .field
        .text()
        .contains("owned draft path"));
    assert!(!app.has_running_work());
}
