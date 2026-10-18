use super::super::{
    sweep_target_with_budget, write_sweep_skips_with_budget, SourceComparisonBudget,
    SourceComparisonLimits,
};
use super::*;

fn budget(comparisons: usize, bytes: usize) -> SourceComparisonBudget {
    SourceComparisonBudget::new(SourceComparisonLimits {
        max_comparisons: comparisons,
        max_diff_bytes: bytes,
    })
    .unwrap()
}

fn advance(root: &Path) {
    git(
        root,
        &[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-m",
            "Owned metadata revision",
        ],
    );
}

#[test]
fn one_diff_is_shared_across_phases_but_skip_revalidation_uses_the_same_allowance() {
    let root = temp_git_workspace().expect("Git required for owned history tests");
    let sha = head_sha(root.path());
    let ledger = CoverageLedger::open(root.path()).unwrap();
    for phase in [WorkflowPhase::Map, WorkflowPhase::Scan] {
        ledger
            .record_baseline(&baseline("root", phase, &sha, 100))
            .unwrap();
    }
    advance(root.path());
    let mut allowance = budget(1, 1024);
    let report = sweep_target_with_budget(root.path(), None, &mut allowance).unwrap();
    assert_eq!(report.entries.len(), 2);
    let error =
        write_sweep_skips_with_budget(root.path(), &report, None, &mut allowance).unwrap_err();
    assert!(error.to_string().contains("maxSourceComparisons=1"));
    assert_eq!(ledger.all_baselines().unwrap().len(), 2);
    let mut revised = budget(2, 1024);
    let report = sweep_target_with_budget(root.path(), None, &mut revised).unwrap();
    assert_eq!(
        write_sweep_skips_with_budget(root.path(), &report, None, &mut revised).unwrap(),
        2
    );
}

#[test]
fn output_exhaustion_and_distinct_revision_exhaustion_leave_history_unchanged() {
    let root = temp_git_workspace().expect("Git required for owned history tests");
    let ledger = CoverageLedger::open(root.path()).unwrap();
    ledger
        .record_baseline(&baseline(
            "root",
            WorkflowPhase::Scan,
            &head_sha(root.path()),
            100,
        ))
        .unwrap();
    fs::write(
        root.path().join("src/lib.rs"),
        "// Owned inert changed bytes\n",
    )
    .unwrap();
    git(root.path(), &["add", "src/lib.rs"]);
    advance(root.path());
    ledger
        .record_baseline(&baseline(
            "root",
            WorkflowPhase::Review,
            &head_sha(root.path()),
            101,
        ))
        .unwrap();
    advance(root.path());
    let error = sweep_target_with_budget(root.path(), None, &mut budget(3, 1)).unwrap_err();
    assert!(
        format!("{error:#}").contains("stdout exceeded the 1-byte capture limit"),
        "{error:#}"
    );
    let error = sweep_target_with_budget(root.path(), None, &mut budget(1, 1024)).unwrap_err();
    assert!(error.to_string().contains("maxSourceComparisons=1"));
    assert_eq!(ledger.all_baselines().unwrap().len(), 2);
}
