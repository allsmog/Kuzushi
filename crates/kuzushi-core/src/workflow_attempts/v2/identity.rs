use super::TargetContentIdentity;
use crate::run_artifacts::{RunArtifactRead, RunSummary, RunTargetGitMetadata};
use crate::run_lifecycle::SafeText;
use crate::workflow_attempts::{canonical_target_identity, PhaseTargetSnapshot};
use std::path::Path;

#[path = "identity/snapshot_evidence.rs"]
mod snapshot_evidence;
use snapshot_evidence::{read_snapshot_evidence, SnapshotEvidence};

const UNKNOWN_REFERENCED_TARGET: &str = "<unavailable:referenced-run-target>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReferencedRunState {
    pub target_snapshot: PhaseTargetSnapshot,
    pub content_identity: TargetContentIdentity,
}

#[derive(Debug, Clone)]
struct RunReferenceEvidence {
    target: Option<String>,
    target_git: Option<RunTargetGitMetadata>,
    content_identity: TargetContentIdentity,
}

pub fn referenced_run_content_identity(
    target: &Path,
    run_refs: &[String],
) -> TargetContentIdentity {
    referenced_run_state(target, run_refs).content_identity
}

pub(super) fn referenced_run_state(target: &Path, run_refs: &[String]) -> ReferencedRunState {
    let evidence = run_refs
        .iter()
        .map(|run_id| read_run_reference(target, run_id))
        .collect::<Vec<_>>();
    ReferencedRunState {
        target_snapshot: target_snapshot(&evidence),
        content_identity: shared_content_identity(&evidence),
    }
}

fn read_run_reference(target: &Path, run_id: &str) -> RunReferenceEvidence {
    let Some(summary) = read_initial_run_summary(target, run_id) else {
        return unavailable_run_reference("referenced run metadata is missing or invalid");
    };
    let content_identity = match read_snapshot_evidence(target, run_id) {
        SnapshotEvidence::Verified(identity) => identity,
        SnapshotEvidence::Absent | SnapshotEvidence::Unverified => {
            identity_from_initial_git(summary.target_git.as_ref())
        }
        SnapshotEvidence::Invalid => {
            unavailable_identity("referenced run snapshot identity is invalid or unreadable")
        }
    };
    RunReferenceEvidence {
        target: Some(canonical_referenced_target(&summary.target)),
        target_git: summary.target_git,
        content_identity,
    }
}

fn canonical_referenced_target(target: &str) -> String {
    SafeText::operator_visible(canonical_target_identity(target)).to_string()
}

fn read_initial_run_summary(target: &Path, run_id: &str) -> Option<RunSummary> {
    let RunArtifactRead::Ready { value, .. } =
        crate::read_run_artifact_text(target, run_id, "run.json")
    else {
        return None;
    };
    let summary: RunSummary = serde_json::from_str(&value).ok()?;
    (summary.run_id == run_id && !summary.target.trim().is_empty()).then_some(summary)
}

fn identity_from_initial_git(git: Option<&RunTargetGitMetadata>) -> TargetContentIdentity {
    match git {
        Some(git) if !git.dirty && valid_git_object_id(&git.sha) => {
            TargetContentIdentity::CleanGitCommit {
                commit: SafeText::operator_visible(git.sha.to_ascii_lowercase()),
            }
        }
        Some(git) if git.dirty => unavailable_identity("referenced run target was dirty at start"),
        _ => unavailable_identity("referenced run has no verifiable start-time content identity"),
    }
}

fn valid_git_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn shared_content_identity(evidence: &[RunReferenceEvidence]) -> TargetContentIdentity {
    let Some(first) = evidence.first() else {
        return unavailable_identity("phase attempt has no referenced runs");
    };
    if shared_target(evidence).is_none() {
        return unavailable_identity("referenced runs do not share one target");
    }
    if evidence
        .iter()
        .any(|run| !run.content_identity.permits_cross_attempt_reuse())
    {
        return unavailable_identity("one or more referenced runs have no verifiable identity");
    }
    if evidence
        .iter()
        .all(|run| run.content_identity == first.content_identity)
    {
        return first.content_identity.clone();
    }
    unavailable_identity("referenced runs do not share one content identity")
}

fn target_snapshot(evidence: &[RunReferenceEvidence]) -> PhaseTargetSnapshot {
    let Some(target) = shared_target(evidence) else {
        return unavailable_target_snapshot();
    };
    let Some(git) = shared_target_git(evidence) else {
        return PhaseTargetSnapshot {
            target,
            revision: None,
            dirty: true,
        };
    };
    target_snapshot_from_git(target, git.as_ref())
}

fn target_snapshot_from_git(
    target: String,
    git: Option<&RunTargetGitMetadata>,
) -> PhaseTargetSnapshot {
    match git {
        Some(git) if valid_git_object_id(&git.sha) => PhaseTargetSnapshot {
            target,
            revision: Some(git.sha.to_ascii_lowercase()),
            dirty: git.dirty,
        },
        Some(_) => PhaseTargetSnapshot {
            target,
            revision: None,
            dirty: true,
        },
        None => PhaseTargetSnapshot {
            target,
            revision: None,
            dirty: false,
        },
    }
}

fn shared_target(evidence: &[RunReferenceEvidence]) -> Option<String> {
    let first = evidence.first()?.target.as_ref()?;
    evidence
        .iter()
        .all(|run| run.target.as_ref() == Some(first))
        .then(|| first.clone())
}

fn shared_target_git(evidence: &[RunReferenceEvidence]) -> Option<Option<RunTargetGitMetadata>> {
    let first = evidence.first()?.target_git.clone();
    evidence
        .iter()
        .all(|run| compatible_target_git(run.target_git.as_ref(), first.as_ref()))
        .then_some(first)
}

fn compatible_target_git(
    left: Option<&RunTargetGitMetadata>,
    right: Option<&RunTargetGitMetadata>,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            left.dirty == right.dirty && left.sha.eq_ignore_ascii_case(&right.sha)
        }
        (None, None) => true,
        _ => false,
    }
}

fn unavailable_run_reference(reason: &str) -> RunReferenceEvidence {
    RunReferenceEvidence {
        target: None,
        target_git: None,
        content_identity: unavailable_identity(reason),
    }
}

fn unavailable_target_snapshot() -> PhaseTargetSnapshot {
    PhaseTargetSnapshot {
        target: UNKNOWN_REFERENCED_TARGET.to_string(),
        revision: None,
        dirty: true,
    }
}

fn unavailable_identity(reason: &str) -> TargetContentIdentity {
    TargetContentIdentity::Unavailable {
        reason: SafeText::operator_visible(reason),
    }
}
