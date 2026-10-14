use super::export_decision_basis::{WorkspaceReviewDecisionBasis, WorkspaceReviewSourceComparison};
use crate::{RunTargetGitMetadata, WorkspaceTarget};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceReviewSourceApplicability {
    LatestObservation,
    MatchingRecordedSource,
    ReassessmentRequired,
    LaterSourceUnverified,
    UnrecordedSource,
}

impl WorkspaceReviewSourceApplicability {
    pub fn needs_reassessment(self) -> bool {
        matches!(
            self,
            Self::ReassessmentRequired | Self::LaterSourceUnverified | Self::UnrecordedSource
        )
    }
}

/// Compare recorded revisions without repairing metadata or inspecting source
/// again. Missing dirty/unversioned content identity never establishes reuse.
pub(super) struct ReviewSourceReader<'a> {
    workspace: &'a WorkspaceTarget,
    revisions: HashMap<String, Option<RunTargetGitMetadata>>,
}

impl<'a> ReviewSourceReader<'a> {
    pub(super) fn new(workspace: &'a WorkspaceTarget) -> Self {
        Self {
            workspace,
            revisions: HashMap::new(),
        }
    }

    pub(super) fn attach_recorded_source(&mut self, basis: &mut WorkspaceReviewDecisionBasis) {
        basis.source_git = self.revision(&basis.run_id);
        if let Some(later) = basis.later_observation.as_mut() {
            later.source_git = self.revision(&later.run_id);
        }
        basis.source_applicability = self.classify(basis);
    }

    pub(super) fn classify(
        &mut self,
        basis: &WorkspaceReviewDecisionBasis,
    ) -> WorkspaceReviewSourceApplicability {
        use WorkspaceReviewSourceApplicability::*;
        let Some(later) = &basis.later_observation else {
            return LatestObservation;
        };
        if basis.source_comparison == WorkspaceReviewSourceComparison::DifferentCitedSource {
            return ReassessmentRequired;
        }
        let before = self.revision(&basis.run_id);
        let after = self.revision(&later.run_id);
        classify_recorded_revisions(before.as_ref(), after.as_ref())
    }

    fn revision(&mut self, run_id: &str) -> Option<RunTargetGitMetadata> {
        if let Some(value) = self.revisions.get(run_id) {
            return value.clone();
        }
        if self.revisions.len() >= 128 {
            return None;
        }
        let value =
            crate::run_artifacts::load_run_summary_without_repair(self.workspace.root(), run_id)
                .ok()
                .filter(|summary| {
                    crate::workflow_attempts::canonical_target_identity(&summary.target)
                        == crate::workflow_attempts::canonical_target_identity(
                            self.workspace.root(),
                        )
                })
                .and_then(|summary| summary.target_git)
                .filter(|git| valid_commit(&git.sha));
        self.revisions.insert(run_id.to_owned(), value.clone());
        value
    }
}

fn classify_recorded_revisions(
    before: Option<&RunTargetGitMetadata>,
    after: Option<&RunTargetGitMetadata>,
) -> WorkspaceReviewSourceApplicability {
    use WorkspaceReviewSourceApplicability::*;
    let (Some(before), Some(after)) = (before, after) else {
        return LaterSourceUnverified;
    };
    if before != after {
        return ReassessmentRequired;
    }
    if !clean_recorded_commit(before) {
        return LaterSourceUnverified;
    }
    MatchingRecordedSource
}

fn clean_recorded_commit(revision: &RunTargetGitMetadata) -> bool {
    !revision.dirty && valid_commit(&revision.sha)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(sha: char, branch: &str, dirty: bool) -> RunTargetGitMetadata {
        RunTargetGitMetadata {
            sha: sha.to_string().repeat(40),
            branch: Some(branch.into()),
            dirty,
        }
    }

    #[test]
    fn matching_clean_revision_is_reusable_but_branch_changes_are_not() {
        let before = git('a', "main", false);
        assert_eq!(
            classify_recorded_revisions(Some(&before), Some(&before)),
            WorkspaceReviewSourceApplicability::MatchingRecordedSource
        );
        let branch = git('a', "other", false);
        assert_eq!(
            classify_recorded_revisions(Some(&before), Some(&branch)),
            WorkspaceReviewSourceApplicability::ReassessmentRequired
        );
    }

    #[test]
    fn missing_source_and_identical_dirty_metadata_do_not_prove_reuse() {
        let dirty = git('a', "main", true);
        assert_eq!(
            classify_recorded_revisions(None, Some(&dirty)),
            WorkspaceReviewSourceApplicability::LaterSourceUnverified
        );
        assert_eq!(
            classify_recorded_revisions(Some(&dirty), Some(&dirty)),
            WorkspaceReviewSourceApplicability::LaterSourceUnverified
        );
    }

    #[test]
    fn different_commits_require_reassessment_and_invalid_commit_is_unverified() {
        let before = git('a', "main", false);
        let after = git('b', "main", false);
        assert_eq!(
            classify_recorded_revisions(Some(&before), Some(&after)),
            WorkspaceReviewSourceApplicability::ReassessmentRequired
        );
        let invalid = RunTargetGitMetadata {
            sha: "unknown".into(),
            ..before
        };
        assert_eq!(
            classify_recorded_revisions(Some(&invalid), Some(&invalid)),
            WorkspaceReviewSourceApplicability::LaterSourceUnverified
        );
    }
}

fn valid_commit(commit: &str) -> bool {
    matches!(commit.len(), 40 | 64) && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
#[path = "tests/recorded_review_source.rs"]
mod recorded_source_tests;
