use super::*;
use crate::{ShellApp, ShellView};
use kuzushi_core::V2Config;

#[test]
fn prompt_brand_uses_cli_name_only_when_binary_stem_is_not_public() {
    assert_eq!(prompt_brand_from_sources(Some("kz"), Some("node")), "kz");
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
    app.focused_module = Some("sast".to_string());
    app.shell_view = ShellView::ModuleRun;
    app.input = "scan ./demo".to_string();
    app.cursor = 4;

    let model = prompt_model(&app);

    assert!(model.prefix.ends_with("/sast/run> "));
    assert_eq!(model.input, "scan ./demo");
    assert_eq!(model.cursor, 4);
}
