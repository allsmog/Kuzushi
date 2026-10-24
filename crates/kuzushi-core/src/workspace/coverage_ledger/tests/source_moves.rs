use super::*;

fn moved_source() -> tempfile::TempDir {
    let root = temp_git_workspace().expect("Git required for owned history tests");
    save_scope_tree(
        root.path(),
        &[("root", "."), ("source", "src"), ("docs", "docs")],
    );
    let sha = head_sha(root.path());
    let ledger = CoverageLedger::open(root.path()).unwrap();
    for scope in ["source", "docs"] {
        ledger
            .record_baseline(&baseline(scope, WorkflowPhase::Scan, &sha, 100))
            .unwrap();
    }
    fs::create_dir(root.path().join("docs")).unwrap();
    git(root.path(), &["mv", "src/lib.rs", "docs/lib.rs"]);
    git(
        root.path(),
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "Owned source move",
        ],
    );
    root
}

#[test]
fn moving_source_between_scopes_changes_both_boundaries_regardless_of_rename_config() {
    let root = moved_source();
    for setting in ["true", "copies", "false"] {
        git(root.path(), &["config", "diff.renames", setting]);
        let report = sweep_target(root.path()).unwrap();
        for scope in ["source", "docs"] {
            let row = report
                .entries
                .iter()
                .find(|row| row.scope_id == scope)
                .unwrap();
            assert_eq!(
                row.verdict,
                SweepVerdict::Changed { files: 1 },
                "{scope}: {setting}"
            );
        }
    }
}

#[test]
fn moving_source_out_of_a_scope_cannot_advance_its_baseline() {
    let root = moved_source();
    git(root.path(), &["config", "diff.renames", "true"]);
    let ledger = CoverageLedger::open(root.path()).unwrap();
    let before = ledger.all_baselines().unwrap();
    let report = sweep_target(root.path()).unwrap();
    assert_eq!(write_sweep_skips(root.path(), &report).unwrap(), 0);
    assert_eq!(ledger.all_baselines().unwrap(), before);
}
