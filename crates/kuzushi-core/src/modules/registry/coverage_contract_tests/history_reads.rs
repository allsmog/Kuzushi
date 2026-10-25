use super::*;

fn second_source_baseline(root: &Path) -> BaselineRow {
    std::fs::write(root.join("hello.txt"), "Owned second source revision.\n").unwrap();
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
            "Owned second source revision",
        ],
    );
    BaselineRow {
        scope_id: "root".into(),
        phase: WorkflowPhase::Scan,
        mode: "newer-mode".into(),
        run_id: "newer-stored-baseline".into(),
        revision: RunTargetGitMetadata {
            sha: git(root, &["rev-parse", "HEAD"]),
            branch: Some("main".into()),
            dirty: false,
        },
        ts_unix: 1,
    }
}

#[test]
fn prepared_baseline_and_sweep_consumers_agree_on_the_last_stored_sha() {
    let root = owned_repository();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let first_sha = seed(&workspace);
    let row = second_source_baseline(root.path());
    let second_sha = row.revision.sha.clone();
    assert_ne!(first_sha, second_sha);
    CoverageLedger::open(root.path())
        .unwrap()
        .record_baseline(&row)
        .unwrap();
    let result = dispatch(&workspace, "coverage:baselines", json!({})).unwrap();
    assert_eq!(result["data"]["baselines"][0]["revisionSha"], second_sha);
    assert_eq!(result["data"]["baselines"][0]["runId"], row.run_id);
    assert_eq!(result["data"]["scopeCoverageVerified"], false);
    let sweep = dispatch(&workspace, "coverage:sweep", json!({})).unwrap();
    assert_eq!(
        sweep["data"]["report"]["entries"][0]["baselineSha"],
        second_sha
    );
    assert_eq!(
        sweep["data"]["report"]["entries"][0]["verdict"]["kind"],
        "current"
    );
    assert_eq!(sweep["data"]["findingFixVerified"], false);
}

#[test]
fn prepared_history_read_rejects_excessive_text_without_a_partial_success() {
    let root = owned_repository();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let sha = seed(&workspace);
    CoverageLedger::open(root.path())
        .unwrap()
        .record_baseline(&BaselineRow {
            scope_id: "root".into(),
            phase: WorkflowPhase::Map,
            mode: "oversized".into(),
            run_id: "x".repeat(8 * 1024 * 1024 + 1),
            revision: RunTargetGitMetadata {
                sha,
                branch: Some("main".into()),
                dirty: false,
            },
            ts_unix: 2,
        })
        .unwrap();
    for tool in ["coverage:baselines", "coverage:sweep"] {
        let result = dispatch(&workspace, tool, json!({}));
        assert!(
            result.is_err(),
            "Oversized history must fail without printing its payload"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("8388608-byte read limit"));
    }
}
