use super::*;

fn git(root: &Path, args: &[&str]) {
    assert!(Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .unwrap()
        .success());
}

#[test]
fn tracked_paths_keep_only_the_processing_limit_and_one_overflow_witness() {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "--quiet"]);
    for name in ["a.rs", "b.rs", "c.rs", "d.rs"] {
        std::fs::write(root.path().join(name), "// owned inert fixture\n").unwrap();
    }
    git(root.path(), &["add", "."]);
    let result = git_tracked_relative_paths(root.path(), 2, &|| false).unwrap();
    let GitIndexEnumeration::Tracked { paths, .. } = result else {
        panic!("expected tracked paths")
    };
    assert_eq!(paths, ["a.rs", "b.rs", "c.rs"]);
}

#[test]
fn fingerprint_covers_paths_beyond_the_retained_processing_prefix() {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "--quiet"]);
    for name in ["a.rs", "z.rs"] {
        std::fs::write(root.path().join(name), "// owned inert source\n").unwrap();
    }
    git(root.path(), &["add", "a.rs"]);
    let GitIndexEnumeration::Tracked {
        paths: first,
        fingerprint: before,
    } = git_tracked_relative_paths(root.path(), 0, &|| false).unwrap()
    else {
        panic!("missing first index")
    };
    git(root.path(), &["add", "z.rs"]);
    let GitIndexEnumeration::Tracked {
        paths: second,
        fingerprint: after,
    } = git_tracked_relative_paths(root.path(), 0, &|| false).unwrap()
    else {
        panic!("missing second index")
    };
    assert_eq!(first, second);
    assert_eq!(first, ["a.rs"]);
    assert_ne!(before, after);
}

#[test]
fn empty_index_and_non_repository_allow_filesystem_enumeration() {
    let root = tempfile::tempdir().unwrap();
    assert!(matches!(
        git_tracked_relative_paths(root.path(), 10, &|| false).unwrap(),
        GitIndexEnumeration::Unavailable
    ));
    git(root.path(), &["init", "--quiet"]);
    assert!(matches!(
        git_tracked_relative_paths(root.path(), 10, &|| false).unwrap(),
        GitIndexEnumeration::Unavailable
    ));
}

#[test]
fn missing_git_preserves_the_runtime_free_fallback() {
    let root = tempfile::tempdir().unwrap();
    let result = acquire_index(
        Command::new(root.path().join("missing-git")),
        10,
        &|| false,
        INDEX_DEADLINE,
    )
    .unwrap();
    assert!(matches!(result, GitIndexEnumeration::Unavailable));
}

#[test]
fn pre_cancellation_never_launches_or_falls_back() {
    let root = tempfile::tempdir().unwrap();
    let result = acquire_index(
        Command::new(root.path().join("missing-git")),
        10,
        &|| true,
        INDEX_DEADLINE,
    )
    .unwrap();
    assert!(matches!(result, GitIndexEnumeration::Canceled));
}

#[test]
fn corrupt_index_is_an_error_not_an_expansion_to_untracked_source() {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "--quiet"]);
    std::fs::write(
        root.path().join(".git/index"),
        "owned invalid index fixture",
    )
    .unwrap();
    let result = git_tracked_relative_paths(root.path(), 10, &|| false);
    assert!(
        format!("{:#}", result.err().expect("must refuse damaged index"))
            .contains("filesystem fallback was not used")
    );
}

#[cfg(unix)]
fn fixture_command(script: &str) -> Command {
    let mut command = Command::new("sh");
    command.args(["-c", script]).stdin(Stdio::null());
    command
}

#[cfg(unix)]
#[test]
fn running_index_honors_a_non_send_cancellation_probe() {
    let started = std::time::Instant::now();
    let probes = std::cell::Cell::new(0);
    let cancel = || {
        probes.set(probes.get() + 1);
        started.elapsed() >= Duration::from_millis(80)
    };
    let result = acquire_index(fixture_command("sleep 60"), 10, &cancel, INDEX_DEADLINE).unwrap();
    assert!(matches!(result, GitIndexEnumeration::Canceled));
    assert!(probes.get() >= 3);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn stalled_index_stops_at_deadline_without_fallback() {
    let started = std::time::Instant::now();
    let result = acquire_index(
        fixture_command("sleep 60"),
        10,
        &|| false,
        Duration::from_millis(40),
    );
    let message = format!(
        "{:#}",
        result.err().expect("deadline must stop acquisition")
    );
    assert!(message.contains("deadline"), "{message}");
    assert!(
        message.contains("filesystem fallback was not used"),
        "{message}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn excessive_index_output_is_bounded_before_parsing() {
    let command = fixture_command("dd if=/dev/zero bs=1048576 count=65 2>/dev/null; sleep 60");
    let started = std::time::Instant::now();
    let result = acquire_index(command, 10, &|| false, INDEX_DEADLINE);
    let message = format!(
        "{:#}",
        result.err().expect("output limit must stop acquisition")
    );
    assert!(message.contains("capture limit"), "{message}");
    assert!(
        message.contains("filesystem fallback was not used"),
        "{message}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn unterminated_output_is_never_a_complete_inventory() {
    let result = acquire_index(
        fixture_command("printf a.rs"),
        10,
        &|| false,
        INDEX_DEADLINE,
    );
    assert!(
        format!("{:#}", result.err().expect("malformed output must fail"))
            .contains("incomplete path list")
    );
}
