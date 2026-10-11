use super::review_state::{EffectiveReviewDecision, EffectiveReviewStateIndex};
use crate::ShellApp;
use crate::{FindingReviewSource, RecordedSourceRevision, ViewDataState, ViewHydrationKey};
use kuzushi_core::findings::{review_decision_history_for, ReviewDecisionRecord};
use kuzushi_core::workspace::WorkspaceReviewSourceComparison;
use kuzushi_core::Finding;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FindingReviewSourceModel {
    pub(crate) notice: String,
    pub(crate) warning: bool,
    pub(crate) rows: Vec<String>,
    pub(crate) provenance: Vec<String>,
}

pub(crate) fn selected_decision_record<'a>(
    finding: &Finding,
    records: &'a [ReviewDecisionRecord],
    effective: Option<&EffectiveReviewDecision>,
) -> Option<&'a ReviewDecisionRecord> {
    let effective = effective?;
    if let Some(id) = effective.record_id() {
        return records.iter().find(|record| record.id == id);
    }
    let decision = effective.review_decision();
    review_decision_history_for(finding, records)
        .into_iter()
        .find(|record| &record.decision == decision)
}

pub(crate) fn hydration_key(app: &ShellApp, finding: &Finding) -> Option<ViewHydrationKey> {
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(
        app.findings(),
        app.review_decisions(),
    );
    let effective = index.effective_decision_for(finding);
    let record = selected_decision_record(finding, app.review_decisions(), effective.as_ref())?;
    let decision_watermark = record.provenance.as_ref()?.read_watermark?;
    Some(ViewHydrationKey::FindingReviewSource {
        stable_fp: kuzushi_core::findings::finding_observation_identity(finding).to_owned(),
        decision_watermark,
        observation_watermark: app.domain().findings_read_watermark(),
    })
}

pub(crate) fn source_model(app: &ShellApp, finding: &Finding) -> FindingReviewSourceModel {
    let (Some(target), Some(key)) = (app.target(), hydration_key(app, finding)) else {
        return notice("Decision source was not recorded.", true);
    };
    let state = app
        .workbench_cache()
        .borrow()
        .cached_finding_review_source(target, &key);
    match state {
        ViewDataState::Ready(Ok(Some(source))) => recorded_source_model(&source),
        ViewDataState::Ready(Ok(None)) => notice("Recorded decision source is unavailable.", true),
        ViewDataState::Ready(Err(_)) => {
            notice("Decision source could not be read. Refresh to retry.", true)
        }
        _ => notice("Loading the source behind this decision…", false),
    }
}

fn notice(text: &str, warning: bool) -> FindingReviewSourceModel {
    FindingReviewSourceModel {
        notice: text.into(),
        warning,
        rows: Vec::new(),
        provenance: Vec::new(),
    }
}

fn recorded_source_model(source: &FindingReviewSource) -> FindingReviewSourceModel {
    let (text, warning) = comparison_notice(source);
    let mut model = notice(text, warning);
    model
        .rows
        .push(format!("Decision observation: {}", source.basis.run_id));
    model
        .rows
        .extend(revision_rows("Decision", &source.decided_revision));
    model
        .provenance
        .extend(full_revision_row("Decision", &source.decided_revision));
    model
        .provenance
        .push(format!("Decision snapshot: {}", source.basis.snapshot_hash));
    append_later_source(&mut model, source);
    model
}

fn comparison_notice(source: &FindingReviewSource) -> (&'static str, bool) {
    if revisions_differ(source) {
        return ("Later observation records a different commit, branch or dirty state. Reassess this verdict.", true);
    }
    if source.basis.source_applicability
        == kuzushi_core::workspace::WorkspaceReviewSourceApplicability::LaterSourceUnverified
    {
        return ("Later source identity is unverified. Reassess the verdict; cited-file equality does not establish repository stability.", true);
    }
    match source.basis.source_comparison {
        WorkspaceReviewSourceComparison::DifferentCitedSource => ("Cited source changed after this decision. Reassess the finding.", true),
        WorkspaceReviewSourceComparison::SameCitedSource => ("Captured cited file is unchanged. Other repository changes still need review.", false),
        WorkspaceReviewSourceComparison::NotReobserved => ("No later observation is recorded. This does not establish that the finding was fixed.", false),
        WorkspaceReviewSourceComparison::Unknown => ("Captured source comparison is unavailable. A new snapshot id does not establish a code change.", true),
    }
}

fn revisions_differ(source: &FindingReviewSource) -> bool {
    let (RecordedSourceRevision::Known(before), Some(RecordedSourceRevision::Known(after))) =
        (&source.decided_revision, &source.later_revision)
    else {
        return false;
    };
    before != after
}

fn revision_rows(label: &str, revision: &RecordedSourceRevision) -> Vec<String> {
    let RecordedSourceRevision::Known(git) = revision else {
        return vec![format!(
            "{label} revision: {}",
            missing_revision_label(revision)
        )];
    };
    let state = if git.dirty { "dirty" } else { "clean" };
    vec![
        format!(
            "{label} commit: {} · {state}",
            git.sha.chars().take(12).collect::<String>()
        ),
        format!(
            "{label} branch: {}",
            git.branch.as_deref().unwrap_or("not recorded")
        ),
    ]
}

fn missing_revision_label(revision: &RecordedSourceRevision) -> &'static str {
    match revision {
        RecordedSourceRevision::Unreadable => "metadata unreadable",
        _ => "commit not recorded",
    }
}

fn append_later_source(model: &mut FindingReviewSourceModel, source: &FindingReviewSource) {
    let Some(later) = &source.basis.later_observation else {
        return;
    };
    model
        .rows
        .push(format!("Later observation: {}", later.run_id));
    if let Some(revision) = &source.later_revision {
        model.rows.extend(revision_rows("Later", revision));
        model
            .provenance
            .extend(full_revision_row("Later", revision));
    }
    model
        .provenance
        .push(format!("Later snapshot: {}", later.snapshot_hash));
}

fn full_revision_row(label: &str, revision: &RecordedSourceRevision) -> Option<String> {
    match revision {
        RecordedSourceRevision::Known(git) => Some(format!("{label} full commit: {}", git.sha)),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
