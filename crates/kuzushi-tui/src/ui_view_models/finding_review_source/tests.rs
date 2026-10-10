use super::*;
use kuzushi_core::workspace::{WorkspaceObservedSource, WorkspaceReviewDecisionBasis};
use kuzushi_core::RunTargetGitMetadata;

fn source(comparison: WorkspaceReviewSourceComparison) -> FindingReviewSource {
    FindingReviewSource {
        basis: WorkspaceReviewDecisionBasis {
            run_id: "fixture-a".into(),
            snapshot_hash: "snapshot-a".into(),
            source_git: None,
            later_observation: Some(WorkspaceObservedSource {
                run_id: "fixture-b".into(),
                snapshot_hash: "snapshot-b".into(),
                source_git: None,
            }),
            source_changed_since_decision: comparison
                == WorkspaceReviewSourceComparison::DifferentCitedSource,
            source_comparison: comparison,
            source_applicability:
                kuzushi_core::workspace::WorkspaceReviewSourceApplicability::MatchingRecordedSource,
        },
        decided_revision: revision('1', "main"),
        later_revision: Some(revision('1', "main")),
    }
}

fn revision(digit: char, branch: &str) -> RecordedSourceRevision {
    RecordedSourceRevision::Known(RunTargetGitMetadata {
        sha: digit.to_string().repeat(40),
        branch: Some(branch.into()),
        dirty: false,
    })
}

#[test]
fn identical_cited_content_stays_qualified_and_full_hashes_remain_in_provenance() {
    let model = recorded_source_model(&source(WorkspaceReviewSourceComparison::SameCitedSource));
    assert!(!model.warning);
    assert!(model
        .notice
        .contains("Other repository changes still need review"));
    assert!(model.rows.iter().any(|row| row.contains("111111111111")));
    assert!(!model.rows.iter().any(|row| row.contains("snapshot-a")));
    assert!(model
        .provenance
        .iter()
        .any(|row| row.contains(&"1".repeat(40))));
    assert!(model
        .provenance
        .iter()
        .any(|row| row.contains("snapshot-a")));
}

#[test]
fn different_commits_are_visible_even_when_the_cited_file_is_identical() {
    let mut value = source(WorkspaceReviewSourceComparison::SameCitedSource);
    value.later_revision = Some(revision('2', "main"));
    let model = recorded_source_model(&value);
    assert!(model.warning);
    assert!(model
        .notice
        .contains("different commit, branch or dirty state"));
    assert!(model
        .rows
        .iter()
        .any(|row| row.contains("Later commit: 222222222222")));
}

#[test]
fn another_branch_does_not_silently_read_as_the_original_decision_source() {
    let mut value = source(WorkspaceReviewSourceComparison::SameCitedSource);
    value.later_revision = Some(revision('1', "release"));
    let model = recorded_source_model(&value);
    assert!(model.warning);
    assert!(model.rows.iter().any(|row| row == "Later branch: release"));
}

#[test]
fn changed_captured_file_requires_reassessment_without_changing_the_verdict() {
    let model = recorded_source_model(&source(
        WorkspaceReviewSourceComparison::DifferentCitedSource,
    ));
    assert!(model.warning);
    assert!(model.notice.contains("Cited source changed"));
    assert!(model.notice.contains("Reassess"));
}

#[test]
fn missing_captures_and_missing_later_observations_do_not_establish_a_fix() {
    let model = recorded_source_model(&source(WorkspaceReviewSourceComparison::Unknown));
    assert!(model.warning);
    assert!(model.notice.contains("unavailable"));
    let mut value = source(WorkspaceReviewSourceComparison::NotReobserved);
    value.basis.later_observation = None;
    value.later_revision = None;
    let model = recorded_source_model(&value);
    assert!(model
        .notice
        .contains("does not establish that the finding was fixed"));
    assert!(!model.rows.iter().any(|row| row.starts_with("Later")));
}
