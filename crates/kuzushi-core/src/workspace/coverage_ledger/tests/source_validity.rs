use super::*;

#[test]
fn same_sha_with_working_tree_edits_is_unverified_instead_of_current() {
    let Some(root) = temp_git_workspace() else {
        return;
    };
    let sha = head_sha(root.path());
    let ledger = CoverageLedger::open(root.path()).unwrap();
    ledger
        .record_baseline(&baseline("root", WorkflowPhase::Scan, &sha, 100))
        .unwrap();
    fs::write(
        root.path().join("src/lib.rs"),
        "// Owned changed source, never executed.\n",
    )
    .unwrap();
    let report = sweep_target(root.path()).unwrap();
    assert_eq!(report.head.sha, sha);
    assert_eq!(
        entry(&report, WorkflowPhase::Scan).verdict,
        SweepVerdict::SourceUnverified {
            reason: SourceCheckIssue::DirtyWorkingTree
        }
    );
    assert!(write_sweep_skips(root.path(), &report).is_err());
    assert_eq!(ledger.all_baselines().unwrap().len(), 1);
}

#[test]
fn dirty_baseline_and_missing_scope_are_never_promoted_to_current() {
    let Some(root) = temp_git_workspace() else {
        return;
    };
    let sha = head_sha(root.path());
    let ledger = CoverageLedger::open(root.path()).unwrap();
    let mut dirty = baseline("root", WorkflowPhase::Scan, &sha, 100);
    dirty.revision.dirty = true;
    ledger.record_baseline(&dirty).unwrap();
    ledger
        .record_baseline(&baseline("removed-scope", WorkflowPhase::Map, &sha, 101))
        .unwrap();
    let report = sweep_target(root.path()).unwrap();
    assert_eq!(
        entry(&report, WorkflowPhase::Scan).verdict,
        SweepVerdict::SourceUnverified {
            reason: SourceCheckIssue::DirtyBaseline
        }
    );
    assert_eq!(
        entry(&report, WorkflowPhase::Map).verdict,
        SweepVerdict::SourceUnverified {
            reason: SourceCheckIssue::ScopeUnavailable
        }
    );
    assert_eq!(write_sweep_skips(root.path(), &report).unwrap(), 0);
}

#[test]
fn stale_clean_report_cannot_advance_a_baseline_after_source_or_ledger_changes() {
    let Some(root) = temp_git_workspace() else {
        return;
    };
    let sha = head_sha(root.path());
    save_scope_tree(root.path(), &[("root", "."), ("docs", "docs")]);
    let ledger = CoverageLedger::open(root.path()).unwrap();
    ledger
        .record_baseline(&baseline("docs", WorkflowPhase::Scan, &sha, 100))
        .unwrap();
    commit_file(
        root.path(),
        "src/other.rs",
        "// inert\n",
        "fixture source change",
    );
    let report = sweep_target(root.path()).unwrap();
    assert_eq!(
        entry(&report, WorkflowPhase::Scan).verdict,
        SweepVerdict::Current
    );
    fs::write(root.path().join("src/lib.rs"), "// changed after report\n").unwrap();
    assert!(write_sweep_skips(root.path(), &report).is_err());
    git(root.path(), &["restore", "src/lib.rs"]);
    ledger
        .record_baseline(&baseline(
            "docs",
            WorkflowPhase::Scan,
            &head_sha(root.path()),
            200,
        ))
        .unwrap();
    assert!(write_sweep_skips(root.path(), &report).is_err());
    assert_eq!(ledger.all_baselines().unwrap().len(), 2);
}

#[test]
fn unbaselined_root_is_reported_and_unicode_scopes_use_exact_git_paths() {
    let Some(root) = temp_git_workspace() else {
        return;
    };
    assert!(sweep_target(root.path())
        .unwrap()
        .unbaselined_scopes
        .contains(&"root".to_string()));
    let sha = head_sha(root.path());
    save_scope_tree(root.path(), &[("root", "."), ("unicode", "données")]);
    CoverageLedger::open(root.path())
        .unwrap()
        .record_baseline(&baseline("unicode", WorkflowPhase::Scan, &sha, 100))
        .unwrap();
    commit_file(
        root.path(),
        "données/a\nb.txt",
        "Owned fixture metadata.\n",
        "fixture unicode source change",
    );
    assert_eq!(
        entry(&sweep_target(root.path()).unwrap(), WorkflowPhase::Scan).verdict,
        SweepVerdict::Changed { files: 1 }
    );
}

#[test]
fn operational_coverage_inspection_cannot_create_a_mapping_baseline() {
    let root = workspace_dir();
    for tool in ["coverage:baselines", "coverage:recommend", "coverage:sweep"] {
        assert!(
            record_baseline_from_summary(
                root.path(),
                &summary("completed", Some(tool), Some(revision("abc", false)))
            )
            .unwrap()
            .is_none(),
            "{tool}"
        );
    }
}
