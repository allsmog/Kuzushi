use super::*;
use crate::{ShellApp, ShellView};
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
    app.shell_view = ShellView::ModuleRun;
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
