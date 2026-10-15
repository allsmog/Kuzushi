use super::formatting::markdown_code_span;
use super::*;

/// Names the observation a decision was made against, so a later run on
/// different source never silently inherits the verdict.
pub(super) fn push_bundle_decision_basis(out: &mut String, record: &WorkspaceFindingExportRecord) {
    push_reviewed_source(out, record.reviewed_source.as_ref());
    let Some(basis) = record.review_decision_basis.as_ref() else {
        return;
    };
    out.push_str(&format!(
        "- **Decision applicability:** {}\n",
        decision_applicability_label(basis.source_applicability)
    ));
    out.push_str(&format!(
        "- **Decision basis:** run {} · source snapshot {}\n",
        markdown_code_span(&basis.run_id),
        markdown_code_span(&basis.snapshot_hash)
    ));
    push_bundle_recorded_git(out, "Decision", basis.source_git.as_ref());
    out.push_str("- **Current checkout:** applicability not assessed by this export\n");
    let Some(later) = basis.later_observation.as_ref() else {
        return;
    };
    out.push_str(&format!(
        "- **Seen again after the decision:** run {} · source snapshot {}{}\n",
        markdown_code_span(&later.run_id),
        markdown_code_span(&later.snapshot_hash),
        bundle_source_comparison_label(basis.source_comparison)
    ));
    push_bundle_recorded_git(out, "Later observation", later.source_git.as_ref());
}

fn push_reviewed_source(out: &mut String, capture: Option<&crate::findings::ReviewSourceCapture>) {
    let Some(capture) = capture else {
        return;
    };
    out.push_str(&format!(
        "- **Explicitly reviewed source:** captured {} · snapshot {} · content {}\n",
        markdown_code_span(&capture.captured_at),
        markdown_code_span(&capture.snapshot_hash),
        markdown_code_span(&capture.tree_hash)
    ));
    push_bundle_recorded_git(out, "Reviewed", capture.source_git.as_ref());
    out.push_str("- **Review limit:** human decision at the captured source; this export does not recheck the current checkout or establish a fix\n");
}

fn push_bundle_recorded_git(
    out: &mut String,
    label: &str,
    git: Option<&crate::RunTargetGitMetadata>,
) {
    let Some(git) = git else {
        out.push_str(&format!("- **{label} Git:** metadata unavailable\n"));
        return;
    };
    let state = if git.dirty { "dirty" } else { "clean" };
    out.push_str(&format!(
        "- **{label} Git:** {} · branch {} · {state}\n",
        markdown_code_span(&git.sha),
        markdown_code_span(git.branch.as_deref().unwrap_or("not recorded"))
    ));
}

fn decision_applicability_label(value: super::WorkspaceReviewSourceApplicability) -> &'static str {
    use super::WorkspaceReviewSourceApplicability::*;
    match value {
        LatestObservation => "latest recorded observation; absence never establishes a fix",
        MatchingRecordedSource => "matching recorded clean revision; coverage limits still apply",
        ReassessmentRequired => "source reassessment required; earlier verdict retained",
        LaterSourceUnverified => "later source unverified; source reassessment required",
        UnrecordedSource => "source linkage not recorded; source reassessment required",
    }
}

fn bundle_source_comparison_label(
    comparison: super::WorkspaceReviewSourceComparison,
) -> &'static str {
    use super::WorkspaceReviewSourceComparison;
    match comparison {
        WorkspaceReviewSourceComparison::DifferentCitedSource => {
            " · captured cited source changed; reassess the decision"
        }
        WorkspaceReviewSourceComparison::SameCitedSource => {
            " · captured cited source unchanged; other repository changes need review"
        }
        WorkspaceReviewSourceComparison::Unknown => {
            " · captured source unavailable; change status unknown"
        }
        WorkspaceReviewSourceComparison::NotReobserved => {
            " · no later observation; absence never establishes a fix"
        }
    }
}
