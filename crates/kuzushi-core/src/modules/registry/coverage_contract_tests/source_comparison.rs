use super::*;

fn commit_owned_change(root: &Path) {
    std::fs::write(root.join("hello.txt"), "Owned changed metadata.\n").unwrap();
    git(root, &["add", "hello.txt"]);
    git(
        root,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "Owned metadata update",
        ],
    );
}

fn has_changed(value: &Value) -> bool {
    value["data"]["recommendations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["reason"] == "changed")
}

#[test]
fn saved_advice_needs_no_git_and_explicit_comparison_surfaces_git_failure() {
    let root = owned_repository();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    seed(&workspace);
    std::fs::rename(root.path().join(".git"), root.path().join("saved-git")).unwrap();
    let saved = dispatch(&workspace, "coverage:recommend", json!({})).unwrap();
    assert_eq!(saved["data"]["sourceComparisonPerformed"], false);
    assert_eq!(saved["data"]["sourceComparison"]["comparisons"], 0);
    assert!(saved["output"]
        .as_str()
        .unwrap()
        .contains("current source not checked"));
    assert!(dispatch(
        &workspace,
        "coverage:recommend",
        json!({"compareSource":true})
    )
    .is_err());
}

#[test]
fn explicit_comparison_adds_changed_evidence_and_never_silently_resets_the_limit() {
    let root = owned_repository();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    seed(&workspace);
    commit_owned_change(root.path());
    let saved = dispatch(&workspace, "coverage:recommend", json!({})).unwrap();
    let checked = dispatch(
        &workspace,
        "coverage:recommend",
        json!({"compareSource":true,"maxSourceComparisons":1,"maxDiffBytes":1024}),
    )
    .unwrap();
    assert!(!has_changed(&saved));
    assert!(has_changed(&checked));
    assert_eq!(checked["data"]["sourceComparison"]["comparisons"], 1);
    assert_eq!(checked["data"]["sourceComparison"]["diffBytes"], 10);
    assert!(dispatch(&workspace, "coverage:sweep", json!({"maxDiffBytes":1})).is_err());
    assert_eq!(
        CoverageLedger::open_if_exists(root.path())
            .unwrap()
            .unwrap()
            .all_baselines()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn source_limits_are_declared_and_validated_before_any_repository_work() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    for name in ["coverage:sweep", "coverage:recommend"] {
        for input in [
            json!({"maxSourceComparisons":0}),
            json!({"maxDiffBytes":67_108_865}),
        ] {
            assert!(dispatch(&workspace, name, input).is_err());
        }
    }
    assert!(!root.path().join(".kuzushi/coverage.sqlite3").exists());
}
