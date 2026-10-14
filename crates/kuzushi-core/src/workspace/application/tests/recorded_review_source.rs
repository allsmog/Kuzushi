use super::*;
use crate::workspace::{WorkspaceObservedSource, WorkspaceReviewSourceComparison};
use crate::{write_run_summary, RunSummary};
use std::fs;

fn revision(digit: char, dirty: bool) -> RunTargetGitMetadata {
    RunTargetGitMetadata {
        sha: digit.to_string().repeat(40),
        branch: Some("main".into()),
        dirty,
    }
}

fn summary(workspace: &WorkspaceTarget, run: &str, git: RunTargetGitMetadata) {
    let mut summary = RunSummary::running(
        run,
        "owned:scan",
        None,
        workspace.root().display().to_string(),
    );
    summary.target_git = Some(git);
    write_run_summary(workspace.root(), &summary.complete()).unwrap();
}

fn basis() -> WorkspaceReviewDecisionBasis {
    WorkspaceReviewDecisionBasis {
        run_id: "before".into(),
        snapshot_hash: "snapshot-before".into(),
        source_git: None,
        later_observation: Some(WorkspaceObservedSource {
            run_id: "after".into(),
            snapshot_hash: "snapshot-after".into(),
            source_git: None,
        }),
        source_changed_since_decision: false,
        source_comparison: WorkspaceReviewSourceComparison::SameCitedSource,
        source_applicability: WorkspaceReviewSourceApplicability::LaterSourceUnverified,
    }
}

#[test]
fn attaches_full_recorded_git_and_dirty_state_without_current_checkout_inference() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let clean = revision('a', false);
    let dirty = revision('a', true);
    summary(&workspace, "before", clean.clone());
    summary(&workspace, "after", dirty.clone());
    let mut basis = basis();
    ReviewSourceReader::new(&workspace).attach_recorded_source(&mut basis);
    assert_eq!(basis.source_git, Some(clean));
    assert_eq!(
        basis.later_observation.as_ref().unwrap().source_git,
        Some(dirty)
    );
    assert_eq!(
        basis.source_applicability,
        WorkspaceReviewSourceApplicability::ReassessmentRequired
    );
    assert!(
        !basis.source_changed_since_decision,
        "cited-file equality stays separate from Git changes"
    );
    let value = serde_json::to_value(basis).unwrap();
    assert_eq!(value["sourceGit"]["sha"], "a".repeat(40));
    assert_eq!(value["laterObservation"]["sourceGit"]["dirty"], true);
}

#[test]
fn unavailable_invalid_and_foreign_source_metadata_remain_null_without_repair() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut invalid = revision('a', false);
    invalid.sha = "not-a-commit".into();
    summary(&workspace, "before", invalid);
    let foreign = tempfile::tempdir().unwrap();
    let mut later = RunSummary::running(
        "after",
        "owned:scan",
        None,
        foreign.path().display().to_string(),
    );
    later.target_git = Some(revision('b', false));
    write_run_summary(root.path(), &later.complete()).unwrap();
    let path = root.path().join(".kuzushi/v3/runs/after/run.json");
    let before = fs::read(&path).unwrap();
    let mut basis = basis();
    ReviewSourceReader::new(&workspace).attach_recorded_source(&mut basis);
    assert!(basis.source_git.is_none());
    assert!(basis
        .later_observation
        .as_ref()
        .unwrap()
        .source_git
        .is_none());
    assert_eq!(
        basis.source_applicability,
        WorkspaceReviewSourceApplicability::LaterSourceUnverified
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    fs::write(&path, "malformed").unwrap();
    ReviewSourceReader::new(&workspace).attach_recorded_source(&mut basis);
    assert!(basis
        .later_observation
        .as_ref()
        .unwrap()
        .source_git
        .is_none());
    assert_eq!(fs::read(&path).unwrap(), b"malformed");
}

#[test]
fn metadata_limit_leaves_unread_revisions_unknown_and_keeps_cached_ones() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    summary(&workspace, "after", revision('b', false));
    let mut reader = ReviewSourceReader::new(&workspace);
    reader
        .revisions
        .insert("before".into(), Some(revision('a', false)));
    for index in 1..128 {
        reader.revisions.insert(format!("retained-{index}"), None);
    }
    let mut basis = basis();
    reader.attach_recorded_source(&mut basis);
    assert_eq!(basis.source_git, Some(revision('a', false)));
    assert!(basis
        .later_observation
        .as_ref()
        .unwrap()
        .source_git
        .is_none());
    assert_eq!(reader.revisions.len(), 128);
}
