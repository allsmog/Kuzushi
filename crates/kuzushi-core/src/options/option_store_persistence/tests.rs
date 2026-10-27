use super::*;
use crate::options::OptionTarget;
use serde_json::json;

#[test]
fn global_options_inside_an_ignored_operator_home_keep_their_scope_and_persist() {
    let (repository, home) = ignored_home();
    let ignore = repository.path().join(".gitignore");
    let path = home.join(".kuzushi/v3/options.json");
    let mut store = ToolOptionStore::new();
    store.set_value(
        OptionScope::Global,
        OptionTarget::All,
        "ui.auto_open_viz",
        json!(false),
    );
    store.set_value(OptionScope::Session, OptionTarget::All, "limit", json!(7));
    store.save_persistent(&path, None).unwrap();
    let loaded = ToolOptionStore::load_persistent(&path, None).unwrap();
    assert_eq!(loaded, store.scope_only(OptionScope::Global));
    assert_eq!(std::fs::read_to_string(ignore).unwrap(), "operator-home/\n");
    assert!(!home.join(".kuzushi/.gitignore").exists());
}

fn ignored_home() -> (tempfile::TempDir, std::path::PathBuf) {
    let repository = tempfile::tempdir().unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "-q"])
        .arg(repository.path())
        .status()
        .unwrap()
        .success());
    let ignore = repository.path().join(".gitignore");
    std::fs::write(&ignore, "operator-home/\n").unwrap();
    let home = repository.path().join("operator-home");
    std::fs::create_dir(&home).unwrap();
    (repository, home)
}

#[test]
fn workspace_options_still_require_repository_policy_at_the_same_path() {
    let (_repository, home) = ignored_home();
    let path = home.join(".kuzushi/v3/options.json");
    let error = ToolOptionStore::new().save_to_path(&path).unwrap_err();
    assert!(format!("{error:#}").contains("hides trackable workspace path"));
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn global_persistence_keeps_no_follow_checks_and_preserves_outside_bytes() {
    let home = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), "OUTSIDE_OPTION_TOKEN").unwrap();
    let path = home.path().join(".kuzushi/v3/options.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(outside.path(), &path).unwrap();
    let error = ToolOptionStore::new()
        .save_persistent(&path, None)
        .unwrap_err();
    assert!(format!("{error:#}").contains("symlink"));
    assert!(ToolOptionStore::load_persistent(&path, None).is_err());
    assert_eq!(
        std::fs::read_to_string(outside.path()).unwrap(),
        "OUTSIDE_OPTION_TOKEN"
    );
}
