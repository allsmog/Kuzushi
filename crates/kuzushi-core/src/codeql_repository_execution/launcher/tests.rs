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
