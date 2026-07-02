use super::*;

#[test]
fn workspace_file_candidates_skip_state_and_dependency_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("README.md"), "readme").unwrap();
    fs::create_dir(tmp.path().join(".kuzushi")).unwrap();
    fs::write(tmp.path().join(".kuzushi").join("state.json"), "{}").unwrap();
    fs::create_dir(tmp.path().join("node_modules")).unwrap();
    fs::write(tmp.path().join("node_modules").join("dep.js"), "x").unwrap();

    let (files, truncated) = workspace_file_candidates(tmp.path(), 100);

    assert_eq!(files, vec!["README.md".to_string()]);
    assert!(!truncated);
}

#[test]
fn pasted_workspace_files_accept_absolute_quoted_paths_inside_root() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("docs");
    fs::create_dir(&dir).unwrap();
    let file = dir.join("design note.md");
    fs::write(&file, "notes").unwrap();

    let pasted = format!("\"{}\"", file.display());

    assert_eq!(
        pasted_workspace_files(&pasted, tmp.path()),
        Some(vec!["docs/design note.md".to_string()])
    );
}

#[test]
fn pasted_workspace_files_reject_paths_outside_root() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();

    assert_eq!(
        pasted_workspace_files(&outside.path().display().to_string(), root.path()),
        None
    );
}
