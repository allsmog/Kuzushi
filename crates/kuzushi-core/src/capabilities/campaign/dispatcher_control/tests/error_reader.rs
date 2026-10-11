use super::*;

fn log_path(root: &Path) -> PathBuf {
    let path = super::super::super::campaign_dir(root, "owned").join("logs/dispatcher.log");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    path
}

#[test]
fn last_failure_is_bounded_and_terminal_safe() {
    let root = tempfile::tempdir().unwrap();
    let path = log_path(root.path());
    let cause = format!("\u{1b}[31m{}", "é".repeat(800));
    std::fs::write(
        path,
        format!("Error: old failure\nprogress\nError: {cause}\n"),
    )
    .unwrap();
    let result = read_campaign_dispatcher_error(root.path(), "owned")
        .unwrap()
        .unwrap();
    assert!(result.starts_with("\\u{1b}[31m"), "{result}");
    assert!(!result.contains("old failure"));
    assert!(!result.chars().any(char::is_control));
    assert!(result.chars().count() <= crate::run_lifecycle::MAX_PREVIEW_LINE_CHARS);
}

#[test]
fn redaction_precedes_preview_truncation() {
    let root = tempfile::tempdir().unwrap();
    let text = format!(
        "Error: {} token={}\n",
        "x".repeat(480),
        "secret-value".repeat(50)
    );
    std::fs::write(log_path(root.path()), text).unwrap();
    let result = read_campaign_dispatcher_error(root.path(), "owned")
        .unwrap()
        .unwrap();
    assert!(!result.contains("secret-value"));
    assert!(result.chars().count() <= crate::run_lifecycle::MAX_PREVIEW_LINE_CHARS);
}

#[test]
fn missing_invalid_and_oversized_logs_are_explicit_errors() {
    let root = tempfile::tempdir().unwrap();
    assert!(read_campaign_dispatcher_error(root.path(), "owned").is_err());
    assert!(read_campaign_dispatcher_error(root.path(), "../outside").is_err());
    let path = log_path(root.path());
    std::fs::write(&path, [0xff]).unwrap();
    assert!(read_campaign_dispatcher_error(root.path(), "owned").is_err());
    std::fs::write(path, vec![b'x'; 2 * 1024 * 1024 + 1]).unwrap();
    assert!(read_campaign_dispatcher_error(root.path(), "owned").is_err());
}

#[test]
fn progress_without_an_error_is_not_a_failure_explanation() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(log_path(root.path()), "job complete\nnot Error: a failure").unwrap();
    assert_eq!(
        read_campaign_dispatcher_error(root.path(), "owned").unwrap(),
        None
    );
}

#[cfg(unix)]
#[test]
fn symlinked_logs_and_directories_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let path = log_path(root.path());
    let external = outside.path().join("dispatcher.log");
    std::fs::write(&external, "Error: outside").unwrap();
    std::os::unix::fs::symlink(&external, &path).unwrap();
    assert!(read_campaign_dispatcher_error(root.path(), "owned").is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(path.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(outside.path(), path.parent().unwrap()).unwrap();
    assert!(read_campaign_dispatcher_error(root.path(), "owned").is_err());
}
