use super::*;
use crate::{ShellApp, ShellView, WorkbenchPage};
use kuzushi_core::V2Config;

#[test]
fn prompt_brand_uses_cli_name_only_when_binary_stem_is_not_public() {
    assert_eq!(prompt_brand_from_sources(Some("kz"), Some("node")), "kz");
}

#[test]
fn strip_windows_exe_is_char_boundary_safe() {
    // "a€€" is 7 bytes; len-4 = 3 lands inside the first '€' — a byte-index
    // slice would panic here, so this guards the regression.
    assert_eq!(strip_windows_exe("a€€"), "a€€");
    assert_eq!(strip_windows_exe("ab"), "ab"); // shorter than ".exe"
    assert_eq!(strip_windows_exe("kz.exe"), "kz");
    assert_eq!(strip_windows_exe("KZ.EXE"), "KZ");
    assert_eq!(strip_windows_exe("€tool.exe"), "€tool");
}

#[test]
fn prompt_brand_uses_public_binary_stem_before_cli_name_env() {
    assert_eq!(
        prompt_brand_from_sources(Some("kz"), Some("/usr/local/bin/kuzushi")),
        "kuzushi"
    );
    assert_eq!(
        prompt_brand_from_sources(Some("kuzushi"), Some("/usr/local/bin/kz")),
        "kz"
    );
}

#[test]
fn prompt_brand_uses_kz_binary_stem_for_unix_or_windows_paths() {
    assert_eq!(
        prompt_brand_from_sources(None, Some("/usr/local/bin/kz")),
        "kz"
    );
    assert_eq!(
        prompt_brand_from_sources(None, Some(r"C:\tools\kz.exe")),
        "kz"
    );
    assert_eq!(
        prompt_brand_from_sources(None, Some(r"C:\tools\KZ.EXE")),
        "kz"
    );
    assert_eq!(
        prompt_brand_from_sources(Some("kz"), Some(r"C:\tools\kuzushi.EXE")),
        "kuzushi"
    );
}

#[test]
fn prompt_brand_defaults_to_kuzushi() {
    assert_eq!(
        prompt_brand_from_sources(Some("kuzushi"), Some("/usr/local/bin/kuzushi")),
        "kuzushi"
    );
    assert_eq!(prompt_brand_from_sources(None, None), "kuzushi");
}

#[test]
fn prompt_model_projects_prompt_and_editor_state() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::ModuleRun);
    app.set_running_tool_for_test("sast:scan");
    app.set_input("scan ./demo");
    app.set_cursor(4);

    let model = prompt_model(&app);

    assert!(model.prefix.ends_with("/sast/run> "));
    assert_eq!(model.input, "scan ./demo");
    assert_eq!(model.cursor, 4);

    app.clear_running_tool_for_test();
    let model = prompt_model(&app);
    assert!(model.prefix.ends_with("/sast> "));
}

#[test]
fn workbench_prompt_projects_the_selected_mode_token_and_placeholder() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);

    for (page, token, placeholder) in [
        (WorkbenchPage::Map, "◇ MAP › ", "describe what to map"),
        (WorkbenchPage::Scan, "▦ SCAN › ", "describe what to scan"),
        (
            WorkbenchPage::Review,
            "▣ REVIEW › ",
            "describe what to review",
        ),
        (
            WorkbenchPage::Prove,
            "◎ PROVE › ",
            "describe what to verify",
        ),
        (
            WorkbenchPage::Fix,
            "◆ FIX › ",
            "describe the patch to draft",
        ),
    ] {
        app.router.workbench_mut().set_page(Some(page));
        let model = prompt_model(&app);
        assert_eq!(model.workbench_mode, Some(page));
        assert_eq!(model.prefix, token);
        assert_eq!(model.placeholder.as_deref(), Some(placeholder));
    }
}

#[test]
fn navigation_prompt_uses_the_default_prompt_binding() {
    let app = ShellApp::new(V2Config::default(), None);

    assert_eq!(
        navigation_prompt_label(&app),
        "NAVIGATE · Shift+Tab mode · Tab/[/] pane · Esc prompt"
    );
}

#[test]
fn navigation_prompt_uses_the_remapped_prompt_binding() {
    let mut config = V2Config::default();
    config.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
        context: "composer".to_string(),
        action: "prompt_mode".to_string(),
        bindings: vec!["x".to_string()],
    }];
    let app = ShellApp::new(config, None);

    assert_eq!(
        navigation_prompt_label(&app),
        "NAVIGATE · Shift+Tab mode · Tab/[/] pane · x prompt"
    );
}
