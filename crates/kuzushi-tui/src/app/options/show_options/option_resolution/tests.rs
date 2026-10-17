use crate::ShellApp;
use kuzushi_core::V2Config;

#[test]
fn deferred_module_options_name_the_exact_tool_path_and_preserve_focus_and_draft() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("codeql".into()));
    app.set_input("held investigation draft");

    let error = app.resolve_options_tool(Some(".".into())).unwrap_err();

    assert!(error
        .to_string()
        .contains("Module codeql requires an exact tool"));
    assert!(error.to_string().contains("tools module:codeql"));
    assert!(!error.to_string().contains("requires a focused module"));
    assert_eq!(app.focused_module(), Some("codeql"));
    assert_eq!(app.input(), "held investigation draft");
    assert_eq!(
        app.resolve_options_tool(Some("codeql:scan".into()))
            .unwrap(),
        "codeql:scan"
    );
    assert!(!app.has_running_work());
}
