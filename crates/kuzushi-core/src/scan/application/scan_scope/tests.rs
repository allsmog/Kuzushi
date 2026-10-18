use super::*;

#[test]
fn literal_scan_path_normalization_preserves_names_instead_of_trimming_them() {
    for path in [" app ", " app /lib.py", "note.rs ", " . ", "  "] {
        assert_eq!(normalized_scan_path(path).unwrap(), path);
    }
    assert_eq!(normalized_scan_path("./app/").unwrap(), "app");
    for path in ["", ".", "../app", "/app"] {
        assert!(normalized_scan_path(path).is_err());
    }
}

#[test]
fn literal_scan_scope_resolves_only_the_requested_directory_and_file() {
    let root = tempfile::tempdir().unwrap();
    for name in ["app", " app "] {
        fs::create_dir(root.path().join(name)).unwrap();
        fs::write(
            root.path().join(name).join("lib.py"),
            "# Owned inert text\n",
        )
        .unwrap();
    }
    let scopes = resolve_scan_scopes(root.path(), &[" app /lib.py".into()]).unwrap();
    assert_eq!(scopes[0].relative, " app /lib.py");
    assert_eq!(
        scopes[0].path,
        fs::canonicalize(root.path()).unwrap().join(" app /lib.py")
    );
    assert!(!scopes[0].is_directory);
    assert!(resolve_scan_scopes(root.path(), &[" app/lib.py".into()]).is_err());
}
