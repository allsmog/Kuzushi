use super::*;

#[test]
fn scanner_paths_outside_the_scope_are_not_relabelled_as_source_inside_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = ScanRoot {
        path: tmp.path().join("service"),
        prefix: Some("service".into()),
        files: None,
    };
    for path in [
        "../other/app.rs".to_string(),
        tmp.path().join("other/app.rs").display().to_string(),
    ] {
        assert!(
            prefixed_finding_path(&root, &path).is_err(),
            "outside path accepted: {path}"
        );
    }
    assert_eq!(
        prefixed_finding_path(&root, "src/app.rs").unwrap(),
        "service/src/app.rs"
    );
    assert_eq!(
        prefixed_finding_path(&root, "./service/src/app.rs").unwrap(),
        "service/src/app.rs"
    );
    let nested = root.path.join("service/app.rs");
    assert_eq!(
        prefixed_finding_path(&root, &nested.display().to_string()).unwrap(),
        "service/service/app.rs"
    );
}

#[test]
fn whole_repository_findings_still_require_contained_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let root = ScanRoot::workspace(tmp.path());
    assert_eq!(
        prefixed_finding_path(&root, "./src/app.rs").unwrap(),
        "src/app.rs"
    );
    assert!(prefixed_finding_path(&root, "../outside.rs").is_err());
    assert!(prefixed_finding_path(&root, "/outside/app.rs").is_err());
}

#[test]
fn overlapping_directory_roots_are_scanned_once_and_parent_files_stay_in_scope() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("service/nested")).unwrap();
    fs::write(tmp.path().join("service/parent.rs"), "fn parent() {}\n").unwrap();
    let options = ScanRunOptions {
        paths: vec![
            "service/nested".into(),
            "./service".into(),
            "service/".into(),
        ],
        ..Default::default()
    };
    let roots = scan_roots(tmp.path(), &options).unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(
        roots[0].path,
        fs::canonicalize(tmp.path()).unwrap().join("service")
    );
}

#[cfg(unix)]
#[test]
fn native_roots_reject_links_to_external_trees() {
    let tmp = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(external.path(), tmp.path().join("external")).unwrap();
    let options = ScanRunOptions {
        paths: vec!["external".into()],
        ..Default::default()
    };
    let error = scan_roots(tmp.path(), &options).unwrap_err();
    assert!(format!("{error:#}").contains("symlink"), "{error:#}");
}

#[test]
fn invalid_and_missing_scope_paths_fail_before_discovery() {
    let tmp = tempfile::tempdir().unwrap();
    for path in ["", ".", "../other", "/absolute", "missing"] {
        let options = ScanRunOptions {
            paths: vec![path.into()],
            ..Default::default()
        };
        assert!(
            scan_roots(tmp.path(), &options).is_err(),
            "invalid scope accepted: {path:?}"
        );
    }
}
