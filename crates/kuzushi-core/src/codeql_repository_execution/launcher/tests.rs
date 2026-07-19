use super::*;
use serde_json::json;

fn binding(scope: &str) -> RepositorySourceBinding {
    RepositorySourceBinding {
        commit: "a".repeat(40),
        target_scope: scope.to_string(),
    }
}

#[test]
fn external_bundle_may_not_contain_the_live_repository() {
    let outer = tempfile::tempdir().unwrap();
    let repository = outer.path().join("repo");
    fs::create_dir(&repository).unwrap();

    let error = validate_external_bundle_root(outer.path(), &repository)
        .unwrap_err()
        .to_string();

    assert!(error.contains("overlaps the live repository"), "{error}");
}

#[test]
fn broad_bundle_roots_are_rejected() {
    let error = validate_external_bundle_root(Path::new("/usr/local/bin"), Path::new("/repo"))
        .unwrap_err()
        .to_string();

    assert!(error.contains("too broad or sensitive"), "{error}");
}

#[test]
fn repository_launcher_outside_nested_target_uses_bound_checkout_file() {
    let live = tempfile::tempdir().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    for root in [live.path(), checkout.path()] {
        fs::create_dir_all(root.join("packages/service")).unwrap();
        fs::create_dir_all(root.join("tools")).unwrap();
        fs::write(root.join("tools/codeql"), "trusted launcher").unwrap();
    }
    let source_binding = binding("packages/service");
    let launcher = PreparedCodeqlLauncher::Ready {
        path: live.path().join("tools/codeql"),
        bundle_root: None,
        repository_relative: Some(PathBuf::from("tools/codeql")),
        content_digest: launcher_digest(&live.path().join("tools/codeql")).unwrap(),
        bundle_identity: None,
    };

    let resolved = launcher
        .resolve_for_checkout(
            &live.path().join("packages/service"),
            &source_binding,
            &checkout.path().join("packages/service"),
        )
        .unwrap()
        .unwrap();

    assert_eq!(
        resolved.path(),
        fs::canonicalize(checkout.path().join("tools/codeql")).unwrap()
    );
    assert_eq!(resolved.read_scope(), &ProgramReadScope::IsolatedFile);
}

#[test]
fn prepared_launcher_rejects_content_mutation() {
    let repository = tempfile::tempdir().unwrap();
    let bundle = tempfile::tempdir().unwrap();
    let launcher = bundle.path().join("codeql");
    fs::write(&launcher, "first").unwrap();
    let mut input = json!({
        "__kuzushiPatchSourceCommit": "a".repeat(40),
        "__kuzushiRepositoryTargetScope": ".",
        "codeqlBin": launcher,
    });
    bind_codeql_launcher("codeql:create-db", repository.path(), &mut input).unwrap();
    fs::write(&launcher, "second").unwrap();

    let error = verify_codeql_launcher("codeql:create-db", repository.path(), &input)
        .unwrap_err()
        .to_string();

    assert!(error.contains("changed after preparation"), "{error}");
}

#[test]
fn prepared_launcher_rejects_sibling_runtime_mutation() {
    let repository = tempfile::tempdir().unwrap();
    let bundle = tempfile::tempdir().unwrap();
    let launcher = bundle.path().join("codeql");
    let runtime = bundle.path().join("runtime.bin");
    fs::write(&launcher, "launcher").unwrap();
    fs::write(&runtime, "trusted runtime").unwrap();
    let mut input = prepared_input(&launcher);
    bind_codeql_launcher("codeql:create-db", repository.path(), &mut input).unwrap();
    assert!(input
        .pointer("/__kuzushiCodeqlLauncher/bundleIdentity")
        .and_then(serde_json::Value::as_str)
        .is_some());

    fs::write(&runtime, "mutated runtime").unwrap();
    let error = verify_codeql_launcher("codeql:create-db", repository.path(), &input)
        .unwrap_err()
        .to_string();

    assert!(error.contains("changed after preparation"), "{error}");
}

#[test]
fn execution_rechecks_prepared_bundle_identity() {
    let repository = tempfile::tempdir().unwrap();
    let checkout = tempfile::tempdir().unwrap();
    let bundle = tempfile::tempdir().unwrap();
    let launcher_path = bundle.path().join("codeql");
    let runtime = bundle.path().join("runtime.bin");
    fs::write(&launcher_path, "launcher").unwrap();
    fs::write(&runtime, "trusted runtime").unwrap();
    let mut input = prepared_input(&launcher_path);
    bind_codeql_launcher("codeql:create-db", repository.path(), &mut input).unwrap();
    let launcher = prepared_codeql_launcher(&input).unwrap();

    fs::write(&runtime, "mutated runtime").unwrap();
    let error = launcher
        .resolve_for_checkout(repository.path(), &binding("."), checkout.path())
        .err()
        .unwrap()
        .to_string();

    assert!(error.contains("external bundle changed"), "{error}");
}

#[test]
fn bundle_identity_frames_directory_structure() {
    let nested = tempfile::tempdir().unwrap();
    fs::create_dir(nested.path().join("a")).unwrap();
    fs::write(nested.path().join("a/b"), b"payload").unwrap();
    fs::write(nested.path().join("c"), b"second").unwrap();
    let flattened = tempfile::tempdir().unwrap();
    fs::create_dir(flattened.path().join("a")).unwrap();
    fs::write(flattened.path().join("a/b"), b"payload").unwrap();
    fs::write(flattened.path().join("a/c"), b"second").unwrap();

    assert_ne!(
        external_bundle_identity(nested.path()).unwrap(),
        external_bundle_identity(flattened.path()).unwrap()
    );
}

#[cfg(unix)]
#[test]
fn bundle_identity_rejects_symbolic_links() {
    use std::os::unix::fs::symlink;

    let bundle = tempfile::tempdir().unwrap();
    fs::write(bundle.path().join("runtime.bin"), b"runtime").unwrap();
    symlink("runtime.bin", bundle.path().join("alias")).unwrap();

    let error = external_bundle_identity(bundle.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("symbolic link"), "{error}");
}

#[cfg(unix)]
#[test]
fn bundle_identity_rejects_special_files() {
    use std::os::unix::ffi::OsStrExt;

    let bundle = tempfile::tempdir().unwrap();
    let fifo = bundle.path().join("runtime.pipe");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);

    let error = external_bundle_identity(bundle.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("non-regular entry"), "{error}");
}

#[test]
fn bundle_identity_rejects_oversized_content_without_reading_it() {
    let bundle = tempfile::tempdir().unwrap();
    fs::File::create(bundle.path().join("oversized.bin"))
        .unwrap()
        .set_len(MAX_EXTERNAL_BUNDLE_BYTES + 1)
        .unwrap();

    let error = external_bundle_identity(bundle.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("maximum supported size"), "{error}");
}

#[test]
fn bundle_identity_rejects_excessive_depth() {
    let bundle = tempfile::tempdir().unwrap();
    let mut directory = bundle.path().to_path_buf();
    for level in 0..=MAX_EXTERNAL_BUNDLE_DEPTH {
        directory.push(format!("d{level}"));
        fs::create_dir(&directory).unwrap();
    }

    let error = external_bundle_identity(bundle.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("nesting exceeds"), "{error}");
}

fn prepared_input(launcher: &Path) -> serde_json::Value {
    json!({
        "__kuzushiPatchSourceCommit": "a".repeat(40),
        "__kuzushiRepositoryTargetScope": ".",
        "codeqlBin": launcher,
    })
}
