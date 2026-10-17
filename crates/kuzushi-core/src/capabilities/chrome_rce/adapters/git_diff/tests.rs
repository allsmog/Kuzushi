use super::*;

#[test]
fn nul_paths_preserve_newlines_unicode_and_whitespace() {
    let paths =
        parse_changed_paths(" name .cc\0docs/line\nbreak.md\0café.cc\0".as_bytes()).unwrap();
    assert_eq!(paths, [" name .cc", "docs/line\nbreak.md", "café.cc"]);
}

#[test]
fn invalid_framing_encoding_and_escaping_paths_are_withheld() {
    for body in [
        b"missing-terminator".as_slice(),
        b"bad\xff\0",
        b"../outside\0",
        b"/outside\0",
    ] {
        assert!(parse_changed_paths(body).is_err(), "{body:?}");
    }
    assert!(parse_changed_paths(b"").unwrap().is_empty());
}

#[test]
fn exact_commit_identity_accepts_both_git_hash_formats_and_rejects_ambiguity() {
    for length in [40, 64] {
        let commit = "a".repeat(length);
        assert_eq!(
            parse_commit(format!("{commit}\n").as_bytes()).unwrap(),
            commit
        );
    }
    for value in [
        "",
        "HEAD",
        "abc123",
        &"z".repeat(40),
        &format!("{}\n{}", "a".repeat(40), "b".repeat(40)),
    ] {
        assert!(parse_commit(value.as_bytes()).is_err());
    }
}

#[test]
fn canceled_comparison_stops_before_git() {
    let target = tempfile::tempdir().unwrap();
    let cancellation = ScanCancellation::default();
    cancellation.cancel();
    let limits = ChangedPathLimits {
        max_changed_files: 1,
        max_git_output_bytes: 256,
        git_timeout_ms: 1000,
    };
    let error =
        compare_committed_paths(target.path(), "HEAD", limits, Some(&cancellation)).unwrap_err();
    assert!(format!("{error:#}").contains("cancelled before"));
    assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
}

#[test]
fn explicit_target_comparison_discards_inherited_git_steering_and_remote_transport() {
    let command = comparison_command(Path::new("owned-target"), &["rev-parse", "HEAD"]);
    let env: std::collections::BTreeMap<_, _> = command.get_envs().collect();
    for key in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_COUNT",
    ] {
        assert_eq!(env[std::ffi::OsStr::new(key)], None);
    }
    assert_eq!(
        env[std::ffi::OsStr::new("GIT_NO_LAZY_FETCH")],
        Some(std::ffi::OsStr::new("1"))
    );
    assert_eq!(
        env[std::ffi::OsStr::new("GIT_ALLOW_PROTOCOL")],
        Some(std::ffi::OsStr::new(""))
    );
}
