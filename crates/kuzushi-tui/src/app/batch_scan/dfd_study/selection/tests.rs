use super::*;

#[test]
fn literal_members_preserve_spaces_punctuation_and_platform_separators() {
    let target = tempfile::tempdir().unwrap();
    for path in [
        " app / source.rs ",
        "src/a,b.rs",
        "src/`code`.rs",
        "src/a.rs:7",
        "src/a#L9.rs",
    ] {
        assert_eq!(literal_path(target.path(), path).unwrap(), path);
    }
    #[cfg(unix)]
    assert_eq!(
        literal_path(target.path(), "src/a\\b.rs").unwrap(),
        "src/a\\b.rs"
    );
    #[cfg(windows)]
    assert_eq!(
        literal_path(target.path(), "src\\a.rs").unwrap(),
        "src/a.rs"
    );
    assert_eq!(
        literal_path(
            target.path(),
            target.path().join(" app /a.rs").to_str().unwrap()
        )
        .unwrap(),
        " app /a.rs"
    );
    assert_eq!(
        literal_path(target.path(), "./src/a.rs").unwrap(),
        "src/a.rs"
    );
}

#[test]
fn invalid_or_root_evidence_never_expands_into_repository_work() {
    for path in [
        "",
        ".",
        "./",
        "/owned",
        "../outside.rs",
        "src/../file.rs",
        "/other/a.rs",
        "https://example.test/a.rs",
    ] {
        assert!(literal_path(Path::new("/owned"), path).is_err(), "{path:?}");
    }
}
