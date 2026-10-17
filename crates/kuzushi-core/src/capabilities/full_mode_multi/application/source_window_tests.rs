use super::chunk_prompt::render_chunk_prompt;
use super::plan::plan;
use crate::capabilities::full_mode_multi::{FullModeConfig, MAX_FILE_BYTES};
use std::path::PathBuf;

#[test]
fn explicit_source_membership_rejects_outside_missing_and_empty_lists() {
    let base = tempfile::tempdir().unwrap();
    let root = base.path().join("repository");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("owned.c"), "// Owned inert metadata.\n").unwrap();
    std::fs::write(
        base.path().join("outside.c"),
        "// Owned outside metadata.\n",
    )
    .unwrap();
    for paths in [
        vec![],
        vec![PathBuf::from("../outside.c")],
        vec![base.path().join("outside.c")],
        vec![PathBuf::from("missing.c")],
    ] {
        let cfg = FullModeConfig {
            workspace_root: root.clone(),
            scope_files: Some(paths),
            ..Default::default()
        };
        assert!(plan(&cfg).is_err());
    }
}

#[test]
fn contained_absolute_paths_share_relative_membership_and_empty_files_do_not_expand_it() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("owned.c"), "// Owned inert metadata.\n").unwrap();
    std::fs::write(root.path().join("empty.c"), "").unwrap();
    let mut cfg = FullModeConfig {
        workspace_root: root.path().into(),
        scope_files: Some(vec![PathBuf::from("owned.c"), root.path().join("owned.c")]),
        ..Default::default()
    };
    let value = plan(&cfg).unwrap();
    assert_eq!(value.total_files, 1);
    assert_eq!(value.chunks[0].files[0].path, "owned.c");
    cfg.scope_files = Some(vec![PathBuf::from("empty.c")]);
    assert!(plan(&cfg).unwrap().chunks.is_empty());
}

#[cfg(unix)]
#[test]
fn scoped_source_refuses_symlink_files_and_parent_directories() {
    use std::os::unix::fs::symlink;
    let base = tempfile::tempdir().unwrap();
    let root = base.path().join("repository");
    let outside = base.path().join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("owned.c"), "// Owned outside metadata.\n").unwrap();
    symlink(outside.join("owned.c"), root.join("link.c")).unwrap();
    symlink(&outside, root.join("linked")).unwrap();
    for path in ["link.c", "linked/owned.c"] {
        let cfg = FullModeConfig {
            workspace_root: root.clone(),
            scope_files: Some(vec![path.into()]),
            ..Default::default()
        };
        assert!(plan(&cfg).is_err());
    }
}

#[test]
fn every_large_file_window_supplies_its_exact_source_including_the_first() {
    let root = tempfile::tempdir().unwrap();
    let text = (0..MAX_FILE_BYTES / 8)
        .map(|line| format!("// Owned line {line:06} α.\n"))
        .collect::<String>();
    std::fs::write(root.path().join("large.c"), &text).unwrap();
    let cfg = FullModeConfig {
        workspace_root: root.path().into(),
        scope_files: Some(vec!["large.c".into()]),
        ..Default::default()
    };
    let value = plan(&cfg).unwrap();
    assert!(value.chunks.len() >= 3);
    for chunk in &value.chunks {
        let bucket = &chunk.files[0];
        let prompt = render_chunk_prompt(root.path(), chunk).unwrap();
        let expected = &text[bucket.start_byte..bucket.start_byte + bucket.bytes];
        assert!(prompt.contains(expected));
        assert!(prompt.contains(&format!("first line is line {}", bucket.start_line)));
        assert!(bucket.bytes <= MAX_FILE_BYTES);
    }
}

#[test]
fn missing_planned_source_is_an_error_instead_of_an_empty_prompt() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("owned.c");
    std::fs::write(&path, "// Owned inert metadata.\n").unwrap();
    let cfg = FullModeConfig {
        workspace_root: root.path().into(),
        ..Default::default()
    };
    let value = plan(&cfg).unwrap();
    std::fs::remove_file(path).unwrap();
    let error = render_chunk_prompt(root.path(), &value.chunks[0]).unwrap_err();
    assert!(format!("{error:#}").contains("could not read planned chunk file"));
}
