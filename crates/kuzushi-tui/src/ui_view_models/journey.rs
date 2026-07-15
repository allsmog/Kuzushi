//! Durable engagement projection for Map -> Scan -> Review -> Prove -> Fix.
//!
//! The selected Workbench page is intentionally absent from this module.
//! Reality advances only from current-target evidence: accepted phase attempts,
//! persisted findings/review decisions/verifications, and compatible legacy
//! run artifacts.

use crate::app::{PlanningTaskId, ViewDataState, WorkflowPhase};
use crate::ui_view_models::review_state::{
    indexed_review_decision_complete, EffectiveReviewStateIndex,
};
use crate::{RunSummaryEntriesState, ShellApp};
use kuzushi_core::findings::ReviewDecisionVerdict;
use kuzushi_core::workflow_attempts::{PhaseAttemptDisposition, PhaseAttemptOutcome};
use kuzushi_core::{
    Finding, PatchLifecycleRecord, PatchLifecycleState, PersistedProofVerdict, RunSummary,
    RunSummaryEntryState, TriageVerdict,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JourneyModel {
    pub phases: Vec<JourneyPhaseStatus>,
    /// Reality phase used by the compact chip and VIEW/REALITY disclosure.
    /// When `destination` is Report this remains the last applicable phase.
    pub current: WorkflowPhase,
    pub destination: JourneyDestination,
    pub progress: JourneyProgress,
    pub next_action: String,
    pub next_tools: String,
    pub next_summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JourneyDestination {
    Phase(WorkflowPhase),
    Report(ReportReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportReason {
    CleanScan,
    NoActionableAfterReview,
    NoProofBackedActionable,
    RemediationComplete,
}

impl ReportReason {
    fn label(self) -> &'static str {
        match self {
            Self::CleanScan => "accepted scan found no candidates",
            Self::NoActionableAfterReview => "review left no actionable findings",
            Self::NoProofBackedActionable => "prove left no proof-backed findings",
            Self::RemediationComplete => "remediation is complete",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JourneyPhaseStatus {
    pub phase: WorkflowPhase,
    pub state: JourneyPhaseState,
    pub phase_label: &'static str,
    pub state_symbol: &'static str,
    pub tone: JourneyPhaseTone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JourneyPhaseState {
    Done,
    Current,
    Failed,
    Skipped,
    Pending,
}

impl JourneyPhaseState {
    pub fn glyph(self) -> &'static str {
        match self {
            Self::Done => "✓",
            Self::Current => "●",
            Self::Failed => "!",
            Self::Skipped => "⊘",
            Self::Pending => "·",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JourneyPhaseTone {
    Success,
    Warn,
    Danger,
    Muted,
    Subtle,
}

impl JourneyPhaseTone {
    fn from_state(state: JourneyPhaseState) -> Self {
        match state {
            JourneyPhaseState::Done => Self::Success,
            JourneyPhaseState::Current => Self::Warn,
            JourneyPhaseState::Failed => Self::Danger,
            JourneyPhaseState::Skipped => Self::Muted,
            JourneyPhaseState::Pending => Self::Subtle,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JourneyProgress {
    pub map_artifacts_built: bool,
    pub map_checkpoint: bool,
    pub scan_checkpoint: bool,
    pub scan_partial_acknowledged: bool,
    pub finding_total: usize,
    pub reviewed_findings: usize,
    /// Review-actionable findings (`confirmed` or `to_fix`). Kept under the
    /// historical field name for compatibility with existing view fixtures.
    pub confirmed_findings: usize,
    pub proven_findings: usize,
    pub proof_backed_findings: usize,
    pub remediated_findings: usize,
    pub remediation_projection_complete: bool,
    pub legacy_inferred: bool,
}

impl JourneyProgress {
    pub fn destination(self) -> JourneyDestination {
        if !self.map_checkpoint {
            return JourneyDestination::Phase(WorkflowPhase::Map);
        }
        if !self.scan_checkpoint {
            return JourneyDestination::Phase(WorkflowPhase::Scan);
        }
        self.destination_after_scan()
    }

    fn destination_after_scan(self) -> JourneyDestination {
        if self.finding_total == 0 {
            return JourneyDestination::Report(ReportReason::CleanScan);
        }
        if self.reviewed_findings < self.finding_total {
            return JourneyDestination::Phase(WorkflowPhase::Review);
        }
        self.destination_after_review()
    }

    fn destination_after_review(self) -> JourneyDestination {
        if self.confirmed_findings == 0 {
            return JourneyDestination::Report(ReportReason::NoActionableAfterReview);
        }
        if self.proven_findings < self.confirmed_findings {
            return JourneyDestination::Phase(WorkflowPhase::Prove);
        }
        self.destination_after_prove()
    }

    fn destination_after_prove(self) -> JourneyDestination {
        if self.proof_backed_findings == 0 {
            return JourneyDestination::Report(ReportReason::NoProofBackedActionable);
        }
        if self.remediation_projection_complete
            && self.remediated_findings >= self.proof_backed_findings
        {
            return JourneyDestination::Report(ReportReason::RemediationComplete);
        }
        JourneyDestination::Phase(WorkflowPhase::Fix)
    }

    pub fn current_phase(self) -> WorkflowPhase {
        match self.destination() {
            JourneyDestination::Phase(phase) => phase,
            JourneyDestination::Report(ReportReason::CleanScan) => WorkflowPhase::Scan,
            JourneyDestination::Report(ReportReason::NoActionableAfterReview) => {
                WorkflowPhase::Review
            }
            JourneyDestination::Report(ReportReason::NoProofBackedActionable) => {
                WorkflowPhase::Prove
            }
            JourneyDestination::Report(ReportReason::RemediationComplete) => WorkflowPhase::Fix,
        }
    }

    pub fn unreviewed_findings(self) -> usize {
        self.finding_total.saturating_sub(self.reviewed_findings)
    }

    fn unproven_findings(self) -> usize {
        self.confirmed_findings.saturating_sub(self.proven_findings)
    }
}

pub fn journey_model(app: &ShellApp) -> Option<JourneyModel> {
    let target = app.target()?;
    let map_artifacts_built = cached_map_artifacts_built(app, target);
    let progress = journey_progress(app, map_artifacts_built);
    let destination = progress.destination();
    let current = progress.current_phase();
    let failed = failed_phase_set(app);
    let explicitly_skipped = app.engagement.projected_skipped_phases();
    let next_action = projected_next_action(app, destination, progress);
    Some(JourneyModel {
        phases: phase_statuses(destination, &explicitly_skipped, &failed),
        current,
        destination,
        progress,
        next_summary: destination_next_summary(destination, progress, &next_action),
        next_action,
        next_tools: projected_next_tools(app, destination),
    })
}

fn cached_map_artifacts_built(app: &ShellApp, target: &std::path::Path) -> bool {
    match app
        .workbench_cache()
        .borrow()
        .cached_map_artifacts_built(Some(target))
    {
        ViewDataState::Ready(built) => built,
        ViewDataState::NotRequested | ViewDataState::Loading => false,
    }
}

fn journey_progress(app: &ShellApp, map_artifacts_built: bool) -> JourneyProgress {
    let review_index = EffectiveReviewStateIndex::from_findings_and_decisions(
        app.findings(),
        app.review_decisions(),
    );
    let mut progress =
        journey_progress_from_parts(map_artifacts_built, app.findings(), &review_index);
    if let Some(counts) = app.domain().finding_ledger_counts() {
        progress.finding_total = counts.total;
        progress.reviewed_findings = counts.reviewed;
        progress.confirmed_findings = counts.confirmed;
        progress.proven_findings = counts.proven.saturating_add(counts.proof_deferred);
        progress.proof_backed_findings = counts.proof_backed;
        progress.remediated_findings = counts.remediated;
        progress.remediation_projection_complete = counts.remediation_projection_complete;
    }
    let selected_map = selected_attempt_counts(app, WorkflowPhase::Map);
    let selected_scan = selected_attempt_counts(app, WorkflowPhase::Scan);
    let legacy = legacy_checkpoints(app, map_artifacts_built);
    progress.map_checkpoint =
        selected_map.is_some() || app.engagement.phase_is_skipped(WorkflowPhase::Map) || legacy.map;
    progress.scan_checkpoint = selected_scan.is_some() || legacy.scan;
    progress.scan_partial_acknowledged = selected_scan == Some(true);
    progress.legacy_inferred = legacy.map || legacy.scan;
    progress
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LegacyCheckpoints {
    map: bool,
    scan: bool,
}

fn legacy_checkpoints(app: &ShellApp, map_artifacts_built: bool) -> LegacyCheckpoints {
    let durable_finding_scan = app
        .domain()
        .finding_ledger_counts()
        .is_some_and(|counts| counts.durable_scan_evidence);
    let scan = !app
        .engagement
        .has_phase_attempt_for_target(WorkflowPhase::Scan)
        && (legacy_completed_scan(app) || durable_finding_scan);
    let map = !app
        .engagement
        .has_phase_attempt_for_target(WorkflowPhase::Map)
        && !app.engagement.phase_is_skipped(WorkflowPhase::Map)
        && (map_artifacts_built || scan);
    LegacyCheckpoints { map, scan }
}

/// Returns whether an accepted checkpoint was a partial result explicitly
/// acknowledged by the operator. Failed/canceled attempts are never selected
/// by the ledger validator and therefore cannot advance reality.
fn selected_attempt_counts(app: &ShellApp, phase: WorkflowPhase) -> Option<bool> {
    let record = app.engagement.selected_phase_attempt(phase)?;
    match record.completed.outcome {
        PhaseAttemptOutcome::Completed => Some(false),
        PhaseAttemptOutcome::Partial => {
            match record.disposition.as_ref().map(|value| &value.disposition) {
                Some(PhaseAttemptDisposition::Selected {
                    acknowledged_partial: true,
                }) => Some(true),
                _ => None,
            }
        }
        PhaseAttemptOutcome::Failed | PhaseAttemptOutcome::Canceled => None,
    }
}

fn legacy_completed_scan(app: &ShellApp) -> bool {
    let entries = app
        .workbench_cache()
        .borrow()
        .cached_run_summary_entries(app.target());
    let ViewDataState::Ready(RunSummaryEntriesState::Ready(entries)) = entries else {
        return false;
    };
    let current = app.engagement.phase_target_snapshot();
    entries.iter().any(|entry| {
        let RunSummaryEntryState::Ready(summary) = &entry.state else {
            return false;
        };
        legacy_summary_is_accepted_scan(summary, current)
    })
}

fn legacy_summary_is_accepted_scan(
    summary: &RunSummary,
    current: Option<&kuzushi_core::workflow_attempts::PhaseTargetSnapshot>,
) -> bool {
    let status = summary.status.trim().to_ascii_lowercase();
    let completed = matches!(
        status.as_str(),
        "completed" | "complete" | "succeeded" | "success"
    );
    let scan = summary.kind.eq_ignore_ascii_case("scan")
        || summary.tool.as_deref().is_some_and(|tool| {
            kuzushi_core::modules::tool_phase(tool) == Some(WorkflowPhase::Scan)
        });
    completed && scan && legacy_scan_is_fresh(summary, current)
}

fn legacy_scan_is_fresh(
    summary: &RunSummary,
    current: Option<&kuzushi_core::workflow_attempts::PhaseTargetSnapshot>,
) -> bool {
    let Some(recorded) = summary.target_git.as_ref() else {
        return true;
    };
    let Some(current) = current else {
        return true;
    };
    let Some(current_revision) = current.revision.as_deref() else {
        return true;
    };
    recorded.sha == current_revision && !recorded.dirty && !current.dirty
}

pub(crate) fn finding_ledger_counts(
    findings: &[Finding],
    decisions: &[kuzushi_core::findings::ReviewDecisionRecord],
    total: usize,
) -> crate::app::FindingLedgerCounts {
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(findings, decisions);
    let progress = journey_progress_from_parts(false, findings, &index);
    crate::app::FindingLedgerCounts {
        total: total.max(findings.len()),
        reviewed: progress.reviewed_findings,
        confirmed: progress.confirmed_findings,
        proven: progress.proven_findings,
        proof_deferred: 0,
        proof_backed: progress.proof_backed_findings,
        remediated: 0,
        remediation_projection_complete: false,
        durable_scan_evidence: findings.iter().any(|finding| {
            finding
                .scan_id
                .as_deref()
                .is_some_and(|scan_id| !scan_id.trim().is_empty())
        }),
    }
}

pub(crate) fn attach_remediation_counts(
    counts: &mut crate::app::FindingLedgerCounts,
    findings: &[Finding],
    decisions: &[kuzushi_core::findings::ReviewDecisionRecord],
    lifecycles: &[PatchLifecycleRecord],
) {
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(findings, decisions);
    counts.remediated = findings
        .iter()
        .filter(|finding| indexed_actionable_finding(&index, finding))
        .filter(|finding| finding_has_proof_backing(finding))
        .filter(|finding| finding_has_verified_remediation(finding, lifecycles))
        .count();
    counts.remediation_projection_complete = true;
}

pub(crate) fn attach_proof_deferral_counts(
    counts: &mut crate::app::FindingLedgerCounts,
    findings: &[Finding],
    decisions: &[kuzushi_core::findings::ReviewDecisionRecord],
    engagement: &crate::app::EngagementState,
) {
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(findings, decisions);
    counts.proof_deferred = findings
        .iter()
        .filter(|finding| indexed_actionable_finding(&index, finding))
        .filter(|finding| !finding_has_current_terminal_verification(finding))
        .filter(|finding| engagement.proof_is_deferred_for(finding))
        .count();
}

fn finding_has_proof_backing(finding: &Finding) -> bool {
    finding.verification.as_ref().is_some_and(|verification| {
        verification.is_current_for_scan(finding.scan_id.as_deref())
            && verification.proof_verdict == PersistedProofVerdict::Exploited
    })
}

fn finding_has_verified_remediation(
    finding: &Finding,
    lifecycles: &[PatchLifecycleRecord],
) -> bool {
    lifecycles.iter().any(|record| {
        record.state == PatchLifecycleState::Verified
            && record.finding_scan_id.as_deref() == finding.scan_id.as_deref()
            && (record.fingerprint == finding.fingerprint
                || finding
                    .identity_id
                    .as_deref()
                    .is_some_and(|identity| identity == record.stable_fp))
    })
}

fn journey_progress_from_parts(
    map_artifacts_built: bool,
    findings: &[Finding],
    index: &EffectiveReviewStateIndex,
) -> JourneyProgress {
    JourneyProgress {
        map_artifacts_built,
        map_checkpoint: false,
        scan_checkpoint: false,
        scan_partial_acknowledged: false,
        finding_total: findings.len(),
        reviewed_findings: findings
            .iter()
            .filter(|finding| indexed_review_decision_complete(index, finding))
            .count(),
        confirmed_findings: findings
            .iter()
            .filter(|finding| indexed_actionable_finding(index, finding))
            .count(),
        proven_findings: findings
            .iter()
            .filter(|finding| indexed_actionable_finding(index, finding))
            .filter(|finding| finding_has_current_terminal_verification(finding))
            .count(),
        proof_backed_findings: findings
            .iter()
            .filter(|finding| indexed_actionable_finding(index, finding))
            .filter(|finding| finding_has_proof_backing(finding))
            .count(),
        remediated_findings: 0,
        remediation_projection_complete: false,
        legacy_inferred: false,
    }
}

fn finding_has_current_terminal_verification(finding: &Finding) -> bool {
    finding
        .verification
        .as_ref()
        .is_some_and(|verification| verification.is_current_for_scan(finding.scan_id.as_deref()))
}

fn indexed_actionable_finding(index: &EffectiveReviewStateIndex, finding: &Finding) -> bool {
    if let Some(decision) = index.effective_decision_for(finding) {
        return matches!(
            decision.verdict(),
            ReviewDecisionVerdict::Confirmed | ReviewDecisionVerdict::ToFix
        );
    }
    finding
        .triage
        .as_ref()
        .is_some_and(|triage| triage.verdict == TriageVerdict::TruePositive)
}

pub(crate) fn finding_is_review_actionable(
    finding: &Finding,
    decisions: &[kuzushi_core::findings::ReviewDecisionRecord],
) -> bool {
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(
        std::slice::from_ref(finding),
        decisions,
    );
    indexed_actionable_finding(&index, finding)
}

fn failed_phase_set(app: &ShellApp) -> BTreeSet<WorkflowPhase> {
    app.engagement
        .failed_tasks()
        .iter()
        .map(|failed| failed.task.phase())
        .collect()
}

fn phase_statuses(
    destination: JourneyDestination,
    explicitly_skipped: &BTreeSet<WorkflowPhase>,
    failed: &BTreeSet<WorkflowPhase>,
) -> Vec<JourneyPhaseStatus> {
    WorkflowPhase::ORDER
        .iter()
        .map(|&phase| {
            let state = phase_state(phase, destination, explicitly_skipped, failed);
            JourneyPhaseStatus {
                phase,
                state,
                phase_label: phase_rail_label(phase),
                state_symbol: state.glyph(),
                tone: JourneyPhaseTone::from_state(state),
            }
        })
        .collect()
}

fn phase_state(
    phase: WorkflowPhase,
    destination: JourneyDestination,
    explicitly_skipped: &BTreeSet<WorkflowPhase>,
    failed: &BTreeSet<WorkflowPhase>,
) -> JourneyPhaseState {
    if failed.contains(&phase) {
        return JourneyPhaseState::Failed;
    }
    if explicitly_skipped.contains(&phase) {
        return JourneyPhaseState::Skipped;
    }
    match destination {
        JourneyDestination::Phase(current) if phase == current => JourneyPhaseState::Current,
        JourneyDestination::Phase(current) if phase < current => JourneyPhaseState::Done,
        JourneyDestination::Phase(_) => JourneyPhaseState::Pending,
        JourneyDestination::Report(reason) => report_phase_state(phase, reason),
    }
}

fn report_phase_state(phase: WorkflowPhase, reason: ReportReason) -> JourneyPhaseState {
    let last_applicable = match reason {
        ReportReason::CleanScan => WorkflowPhase::Scan,
        ReportReason::NoActionableAfterReview => WorkflowPhase::Review,
        ReportReason::NoProofBackedActionable => WorkflowPhase::Prove,
        ReportReason::RemediationComplete => WorkflowPhase::Fix,
    };
    if phase <= last_applicable {
        JourneyPhaseState::Done
    } else {
        JourneyPhaseState::Skipped
    }
}

fn phase_rail_label(phase: WorkflowPhase) -> &'static str {
    match phase {
        WorkflowPhase::Map => "組 map ",
        WorkflowPhase::Scan => "崩 scan ",
        WorkflowPhase::Review => "覧 review ",
        WorkflowPhase::Prove => "証 prove ",
        WorkflowPhase::Fix => "掛 fix ",
    }
}

fn destination_next_action(destination: JourneyDestination, progress: JourneyProgress) -> String {
    match destination {
        JourneyDestination::Phase(WorkflowPhase::Map) => {
            "build or explicitly skip the current-revision map".to_string()
        }
        JourneyDestination::Phase(WorkflowPhase::Scan) => {
            "run discovery-only scanners and select a completed attempt".to_string()
        }
        JourneyDestination::Phase(WorkflowPhase::Review) => format!(
            "record terminal dispositions for {} of {} remaining candidates",
            progress.unreviewed_findings(),
            progress.finding_total
        ),
        JourneyDestination::Phase(WorkflowPhase::Prove) => format!(
            "verify or explicitly defer {} remaining actionable findings",
            progress.unproven_findings()
        ),
        JourneyDestination::Phase(WorkflowPhase::Fix) => format!(
            "draft, approve, apply, and re-verify {} proof-backed findings",
            progress.proof_backed_findings
        ),
        JourneyDestination::Report(reason) => format!("open Report — {}", reason.label()),
    }
}

fn projected_next_action(
    app: &ShellApp,
    destination: JourneyDestination,
    progress: JourneyProgress,
) -> String {
    unresolved_partial_attempt(app, destination)
        .map(partial_attempt_action)
        .unwrap_or_else(|| destination_next_action(destination, progress))
}

fn unresolved_partial_attempt(
    app: &ShellApp,
    destination: JourneyDestination,
) -> Option<&kuzushi_core::workflow_attempts::PhaseAttemptRecord> {
    let JourneyDestination::Phase(phase) = destination else {
        return None;
    };
    let record = app.engagement.unresolved_phase_attempt(phase)?;
    (record.completed.outcome == PhaseAttemptOutcome::Partial).then_some(record)
}

fn partial_attempt_action(record: &kuzushi_core::workflow_attempts::PhaseAttemptRecord) -> String {
    record
        .completed
        .selection_blocked_reason
        .clone()
        .unwrap_or_else(|| partial_acknowledgement_action(record.completed.phase))
}

fn partial_acknowledgement_action(phase: WorkflowPhase) -> String {
    let mut chars = phase.word().chars();
    let first = chars.next().unwrap_or_default().to_ascii_uppercase();
    let title = format!("{first}{}", chars.as_str());
    format!("acknowledge the partial {title}")
}

fn projected_next_tools(app: &ShellApp, destination: JourneyDestination) -> String {
    if unresolved_partial_attempt(app, destination).is_some() {
        return String::new();
    }
    destination_tools(destination)
}

fn destination_next_summary(
    destination: JourneyDestination,
    progress: JourneyProgress,
    next_action: &str,
) -> String {
    let inferred = progress
        .legacy_inferred
        .then_some(" · legacy inferred")
        .unwrap_or("");
    match destination {
        JourneyDestination::Phase(phase) => format!(
            "{} {} · {next_action}{inferred}",
            phase.kanji(),
            phase.label()
        ),
        JourneyDestination::Report(reason) => format!("REPORT · {}{inferred}", reason.label()),
    }
}

fn destination_tools(destination: JourneyDestination) -> String {
    let JourneyDestination::Phase(phase) = destination else {
        return String::new();
    };
    let mut tools = Vec::new();
    for task in PlanningTaskId::in_phase(phase) {
        let tool = task.tool_name();
        if !tools.contains(&tool) {
            tools.push(tool);
        }
    }
    tools.join(", ")
}

pub(crate) fn journey_phase_segment(phase: WorkflowPhase) -> String {
    format!(
        "{} {} {}/{}",
        phase.kanji(),
        crate::app::WorkbenchPage::from_phase(phase)
            .title()
            .to_ascii_lowercase(),
        phase.position(),
        WorkflowPhase::ORDER.len()
    )
}

pub fn journey_footer_segment(app: &ShellApp) -> Option<String> {
    let journey = journey_model(app)?;
    Some(match journey.destination {
        JourneyDestination::Phase(_) => journey_phase_segment(journey.current),
        JourneyDestination::Report(_) => {
            format!("{} · report ready", journey_phase_segment(journey.current))
        }
    })
}

pub fn autonomy_footer_segment(app: &ShellApp) -> Option<String> {
    let journey = journey_model(app)?;
    let posture = app.autonomy();
    let mut segment = format!("⛭ {} {}", posture.kanji(), posture.label());
    if posture.ceiling() < journey.current {
        segment.push_str(" ⚠");
    }
    Some(segment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ViewHydrationKey;
    use kuzushi_core::workflow_attempts::{
        append_phase_attempt_completed, append_phase_attempt_disposition,
        append_phase_checkpoint_skipped, PhaseAttemptCompleted, PhaseAttemptDisposition,
        PhaseAttemptDispositionRecorded, PhaseAttemptLedger, PhaseAttemptOutcome,
        PhaseCheckpointSkipped, PhaseTargetSnapshot,
    };
    use kuzushi_core::{
        write_run_summary, PatchLifecycleRecord, PersistedProofVerdict, PersistedSandboxBackend,
        PersistedVerification, RunTargetGitMetadata, Severity, TriageOutcome, V2Config,
        WorkspaceTarget,
    };
    use std::path::Path;

    fn progress(
        map: bool,
        scan: bool,
        total: usize,
        reviewed: usize,
        actionable: usize,
        proven: usize,
        proof_backed: usize,
        remediated: usize,
    ) -> JourneyProgress {
        JourneyProgress {
            map_artifacts_built: map,
            map_checkpoint: map,
            scan_checkpoint: scan,
            scan_partial_acknowledged: false,
            finding_total: total,
            reviewed_findings: reviewed,
            confirmed_findings: actionable,
            proven_findings: proven,
            proof_backed_findings: proof_backed,
            remediated_findings: remediated,
            remediation_projection_complete: true,
            legacy_inferred: false,
        }
    }

    #[test]
    fn five_checkpoints_are_distinct() {
        assert_eq!(
            progress(false, false, 0, 0, 0, 0, 0, 0).current_phase(),
            WorkflowPhase::Map
        );
        assert_eq!(
            progress(true, false, 0, 0, 0, 0, 0, 0).current_phase(),
            WorkflowPhase::Scan
        );
        assert_eq!(
            progress(true, true, 2, 0, 0, 0, 0, 0).current_phase(),
            WorkflowPhase::Review
        );
        assert_eq!(
            progress(true, true, 2, 2, 1, 0, 0, 0).current_phase(),
            WorkflowPhase::Prove
        );
        assert_eq!(
            progress(true, true, 2, 2, 1, 1, 1, 0).current_phase(),
            WorkflowPhase::Fix
        );
        assert_eq!(
            progress(true, true, 2, 2, 1, 1, 1, 1).destination(),
            JourneyDestination::Report(ReportReason::RemediationComplete)
        );
    }

    #[test]
    fn clean_scan_and_empty_downstream_branches_offer_report() {
        assert_eq!(
            progress(true, true, 0, 0, 0, 0, 0, 0).destination(),
            JourneyDestination::Report(ReportReason::CleanScan)
        );
        assert_eq!(
            progress(true, true, 2, 2, 0, 0, 0, 0).destination(),
            JourneyDestination::Report(ReportReason::NoActionableAfterReview)
        );
        assert_eq!(
            progress(true, true, 2, 2, 1, 1, 0, 0).destination(),
            JourneyDestination::Report(ReportReason::NoProofBackedActionable)
        );
    }

    #[test]
    fn prove_reality_accepts_only_current_generation_terminal_verification() {
        let current = actionable_finding_with_verification("scan-2", "scan-2", "verify-2");
        let stale = actionable_finding_with_verification("scan-2", "scan-1", "verify-1");
        let missing_run = actionable_finding_with_verification("scan-2", "scan-2", "");

        for (finding, expected) in [(current, 1), (stale, 0), (missing_run, 0)] {
            let index = EffectiveReviewStateIndex::from_findings_and_decisions(
                std::slice::from_ref(&finding),
                &[],
            );
            let progress = journey_progress_from_parts(false, &[finding], &index);
            assert_eq!(progress.proven_findings, expected);
            assert_eq!(progress.proof_backed_findings, expected);
        }
    }

    #[test]
    fn human_proof_deferral_is_terminal_for_only_its_recorded_generation() {
        let snapshot = PhaseTargetSnapshot {
            target: "/target".to_string(),
            revision: Some("abc".to_string()),
            dirty: false,
        };
        let finding = actionable_finding("scan-1");
        let deferral = kuzushi_core::workflow_attempts::ProofDeferralRecorded::human(
            &finding.fingerprint,
            finding.identity_id.clone(),
            "scan-1",
            snapshot.clone(),
            "runtime environment is intentionally unavailable",
        );
        let ledger = PhaseAttemptLedger::from_events([
            kuzushi_core::workflow_attempts::PhaseAttemptEvent::ProofDeferralRecorded(deferral),
        ])
        .unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.engagement
            .set_phase_attempt_projection(Some(snapshot), ledger);

        let mut counts = finding_ledger_counts(std::slice::from_ref(&finding), &[], 1);
        attach_proof_deferral_counts(
            &mut counts,
            std::slice::from_ref(&finding),
            &[],
            &app.engagement,
        );
        assert_eq!(counts.proof_deferred, 1);

        let stale = actionable_finding("scan-2");
        let mut stale_counts = finding_ledger_counts(std::slice::from_ref(&stale), &[], 1);
        attach_proof_deferral_counts(
            &mut stale_counts,
            std::slice::from_ref(&stale),
            &[],
            &app.engagement,
        );
        assert_eq!(stale_counts.proof_deferred, 0);
    }

    #[test]
    fn fix_completion_requires_verified_lifecycle_for_current_generation() {
        let finding = actionable_finding_with_verification("scan-2", "scan-2", "verify-2");
        let mut lifecycle = lifecycle_for_generation(&finding, "scan-1");
        let mut counts = finding_ledger_counts(std::slice::from_ref(&finding), &[], 1);

        attach_remediation_counts(
            &mut counts,
            std::slice::from_ref(&finding),
            &[],
            std::slice::from_ref(&lifecycle),
        );
        assert_eq!(counts.remediated, 0);

        lifecycle.finding_scan_id = Some("scan-2".to_string());
        attach_remediation_counts(
            &mut counts,
            std::slice::from_ref(&finding),
            &[],
            &[lifecycle],
        );
        assert_eq!(counts.remediated, 1);
    }

    fn actionable_finding(scan_id: &str) -> Finding {
        let mut finding = finding_with_scan_id(scan_id);
        finding.triage = Some(TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 1.0,
            rationale: "human-confirmed".to_string(),
            ..TriageOutcome::default()
        });
        finding
    }

    fn actionable_finding_with_verification(
        scan_id: &str,
        verified_scan_id: &str,
        verification_run_id: &str,
    ) -> Finding {
        let mut finding = actionable_finding(scan_id);
        finding.verification = Some(PersistedVerification {
            proof_level: 3,
            proof_verdict: PersistedProofVerdict::Exploited,
            backend: PersistedSandboxBackend::Plain,
            language: None,
            harness_path: None,
            crash_evidence: Some("reproduced".to_string()),
            duration_ms: 1,
            cost_usd: 0.0,
            notes: Vec::new(),
            verification_run_id: Some(verification_run_id.to_string()),
            verified_scan_id: Some(verified_scan_id.to_string()),
            created_at: "1".to_string(),
        });
        finding
    }

    fn lifecycle_for_generation(finding: &Finding, scan_id: &str) -> PatchLifecycleRecord {
        PatchLifecycleRecord {
            application_id: "application-1".to_string(),
            stable_fp: finding
                .identity_id
                .clone()
                .unwrap_or_else(|| finding.fingerprint.clone()),
            fingerprint: finding.fingerprint.clone(),
            finding_scan_id: Some(scan_id.to_string()),
            patch_run_id: "patch-run-1".to_string(),
            target: "/target".to_string(),
            diff_hash: "diff".to_string(),
            base_commit: Some("base".to_string()),
            touched_files: Vec::new(),
            state: PatchLifecycleState::Verified,
            reverify_run_id: Some("reverify-1".to_string()),
            detail: None,
            actor: "operator".to_string(),
            application_started_at: "1".to_string(),
            applied_at: Some("1".to_string()),
            updated_at: "2".to_string(),
        }
    }

    #[test]
    fn report_marks_not_applicable_future_phases_skipped() {
        let statuses = phase_statuses(
            JourneyDestination::Report(ReportReason::CleanScan),
            &BTreeSet::new(),
            &BTreeSet::new(),
        );
        assert_eq!(statuses[0].state, JourneyPhaseState::Done);
        assert_eq!(statuses[1].state, JourneyPhaseState::Done);
        assert!(statuses[2..]
            .iter()
            .all(|status| status.state == JourneyPhaseState::Skipped));
    }

    #[test]
    fn modern_map_attempts_suppress_legacy_artifact_inference() {
        for discarded in [false, true] {
            let target = tempfile::tempdir().unwrap();
            let workspace = WorkspaceTarget::new(target.path()).unwrap();
            write_map_artifact(target.path());
            record_attempt(target.path(), WorkflowPhase::Map, "map-run", discarded);

            let app = hydrated_app(&workspace, vec![ViewHydrationKey::MapArtifacts]);
            let journey = journey_model(&app).expect("journey");

            assert!(!journey.progress.map_checkpoint, "discarded={discarded}");
            assert!(!journey.progress.legacy_inferred, "discarded={discarded}");
            assert_eq!(journey.current, WorkflowPhase::Map);
        }
    }

    #[test]
    fn modern_scan_attempts_suppress_legacy_summary_inference() {
        for discarded in [false, true] {
            let target = tempfile::tempdir().unwrap();
            let workspace = WorkspaceTarget::new(target.path()).unwrap();
            let snapshot = PhaseTargetSnapshot::capture(target.path());
            append_phase_checkpoint_skipped(
                target.path(),
                PhaseCheckpointSkipped::new(WorkflowPhase::Map, snapshot),
            )
            .unwrap();
            write_run_summary(
                target.path(),
                &completed_scan_summary(target.path(), "scan-run"),
            )
            .unwrap();
            record_attempt(target.path(), WorkflowPhase::Scan, "scan-run", discarded);

            let mut app = hydrated_app(&workspace, vec![ViewHydrationKey::RunSummaryEntries]);
            let finding = finding_with_scan_id("legacy-scan");
            let counts = finding_ledger_counts(std::slice::from_ref(&finding), &[], 1);
            app.set_findings(vec![finding]);
            app.domain_mut().set_finding_ledger_counts(counts);
            let journey = journey_model(&app).expect("journey");

            assert!(!journey.progress.scan_checkpoint, "discarded={discarded}");
            assert!(!journey.progress.legacy_inferred, "discarded={discarded}");
            assert_eq!(journey.current, WorkflowPhase::Scan);
        }
    }

    #[test]
    fn unresolved_partial_scan_acknowledgement_outranks_generic_next_action() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let snapshot = PhaseTargetSnapshot::capture(target.path());
        append_phase_checkpoint_skipped(
            target.path(),
            PhaseCheckpointSkipped::new(WorkflowPhase::Map, snapshot.clone()),
        )
        .unwrap();
        let partial = PhaseAttemptCompleted::new(
            WorkflowPhase::Scan,
            vec!["scan-partial".to_string()],
            snapshot,
            PhaseAttemptOutcome::Partial,
        );
        append_phase_attempt_completed(target.path(), partial).unwrap();

        let journey = journey_model(&hydrated_app(&workspace, Vec::new())).unwrap();

        assert_eq!(
            journey.destination,
            JourneyDestination::Phase(WorkflowPhase::Scan)
        );
        assert_eq!(journey.next_action, "acknowledge the partial Scan");
        assert!(journey.next_tools.is_empty());
        assert!(journey.next_summary.contains(&journey.next_action));
    }

    #[test]
    fn evidence_blocked_map_names_the_target_instead_of_offering_acknowledgement() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let reason =
            kuzushi_core::workflow_attempts::insufficient_map_evidence_message(target.path());
        let partial = PhaseAttemptCompleted::new(
            WorkflowPhase::Map,
            vec!["map-empty".to_string()],
            PhaseTargetSnapshot::capture(target.path()),
            PhaseAttemptOutcome::Partial,
        )
        .with_selection_blocked(reason.clone());
        append_phase_attempt_completed(target.path(), partial).unwrap();

        let journey = journey_model(&hydrated_app(&workspace, Vec::new())).unwrap();

        assert_eq!(
            journey.destination,
            JourneyDestination::Phase(WorkflowPhase::Map)
        );
        assert_eq!(journey.next_action, reason);
        assert!(journey.next_tools.is_empty());
    }

    #[test]
    fn accepted_clean_scan_keeps_report_destination() {
        for outcome in [PhaseAttemptOutcome::Completed, PhaseAttemptOutcome::Partial] {
            let target = tempfile::tempdir().unwrap();
            let workspace = WorkspaceTarget::new(target.path()).unwrap();
            record_selected_scan_attempt(target.path(), outcome);

            let journey = journey_model(&hydrated_app(&workspace, Vec::new())).unwrap();

            assert_eq!(
                journey.destination,
                JourneyDestination::Report(ReportReason::CleanScan)
            );
            assert_eq!(
                journey.next_action,
                "open Report — accepted scan found no candidates"
            );
        }
    }

    #[test]
    fn genuinely_legacy_artifacts_still_infer_map_and_scan() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        write_map_artifact(target.path());
        write_run_summary(
            target.path(),
            &completed_scan_summary(target.path(), "legacy-scan"),
        )
        .unwrap();

        let app = hydrated_app(
            &workspace,
            vec![
                ViewHydrationKey::MapArtifacts,
                ViewHydrationKey::RunSummaryEntries,
            ],
        );
        let journey = journey_model(&app).expect("journey");

        assert!(journey.progress.map_checkpoint);
        assert!(journey.progress.scan_checkpoint);
        assert!(journey.progress.legacy_inferred);
        assert_eq!(
            journey.destination,
            JourneyDestination::Report(ReportReason::CleanScan)
        );
    }

    #[test]
    fn evidence_empty_legacy_artifact_does_not_advance_map() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        write_empty_map_artifact(target.path());

        let app = hydrated_app(&workspace, vec![ViewHydrationKey::MapArtifacts]);
        let journey = journey_model(&app).expect("journey");

        assert!(!journey.progress.map_artifacts_built);
        assert!(!journey.progress.map_checkpoint);
        assert!(!journey.progress.legacy_inferred);
        assert_eq!(
            journey.destination,
            JourneyDestination::Phase(WorkflowPhase::Map)
        );
    }

    #[test]
    fn legacy_store_findings_infer_scan_from_unfiltered_durable_provenance() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let finding = finding_with_scan_id("legacy-import");
        let counts = finding_ledger_counts(std::slice::from_ref(&finding), &[], 1);
        let mut app = hydrated_app(&workspace, Vec::new());
        app.set_findings(vec![finding]);
        app.domain_mut().set_finding_ledger_counts(counts);

        let journey = journey_model(&app).expect("journey");

        assert!(journey.progress.map_checkpoint);
        assert!(journey.progress.scan_checkpoint);
        assert!(journey.progress.legacy_inferred);
        assert_eq!(journey.current, WorkflowPhase::Review);
    }

    #[test]
    fn bare_in_memory_findings_do_not_invent_an_imported_scan_attempt() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        append_phase_checkpoint_skipped(
            target.path(),
            PhaseCheckpointSkipped::new(
                WorkflowPhase::Map,
                PhaseTargetSnapshot::capture(target.path()),
            ),
        )
        .unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "legacy.rule",
            "src/lib.rs",
            1,
            None,
            Severity::High,
            "candidate",
        );
        let counts = finding_ledger_counts(std::slice::from_ref(&finding), &[], 1);
        let mut app = hydrated_app(&workspace, Vec::new());
        app.set_findings(vec![finding]);
        app.domain_mut().set_finding_ledger_counts(counts);

        let journey = journey_model(&app).expect("journey");

        assert!(journey.progress.map_checkpoint);
        assert!(!journey.progress.scan_checkpoint);
        assert!(!journey.progress.legacy_inferred);
        assert_eq!(journey.current, WorkflowPhase::Scan);
    }

    #[test]
    fn stale_legacy_scan_does_not_advance_reality() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        write_map_artifact(target.path());
        let summary = completed_scan_summary(target.path(), "stale-scan").with_target_git(Some(
            RunTargetGitMetadata {
                sha: "old-revision".to_string(),
                branch: Some("main".to_string()),
                dirty: false,
            },
        ));
        write_run_summary(target.path(), &summary).unwrap();
        let mut app = hydrated_app(
            &workspace,
            vec![
                ViewHydrationKey::MapArtifacts,
                ViewHydrationKey::RunSummaryEntries,
            ],
        );
        let mut current = PhaseTargetSnapshot::capture(target.path());
        current.revision = Some("current-revision".to_string());
        current.dirty = false;
        app.engagement
            .set_phase_attempt_projection(Some(current), PhaseAttemptLedger::default());

        let journey = journey_model(&app).expect("journey");

        assert!(journey.progress.map_checkpoint);
        assert!(!journey.progress.scan_checkpoint);
        assert_eq!(journey.current, WorkflowPhase::Scan);
    }

    #[test]
    fn dirty_git_metadata_cannot_prove_a_legacy_scan_is_fresh() {
        let current = PhaseTargetSnapshot {
            target: "/target".to_string(),
            revision: Some("same-revision".to_string()),
            dirty: false,
        };
        let recorded_dirty = completed_scan_summary(Path::new("/target"), "dirty-scan")
            .with_target_git(Some(RunTargetGitMetadata {
                sha: "same-revision".to_string(),
                branch: None,
                dirty: true,
            }));
        assert!(!legacy_summary_is_accepted_scan(
            &recorded_dirty,
            Some(&current)
        ));

        let current_dirty = PhaseTargetSnapshot {
            dirty: true,
            ..current
        };
        let recorded_clean = completed_scan_summary(Path::new("/target"), "clean-scan")
            .with_target_git(Some(RunTargetGitMetadata {
                sha: "same-revision".to_string(),
                branch: None,
                dirty: false,
            }));
        assert!(!legacy_summary_is_accepted_scan(
            &recorded_clean,
            Some(&current_dirty)
        ));
    }

    fn hydrated_app(workspace: &WorkspaceTarget, keys: Vec<ViewHydrationKey>) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), Some(workspace));
        app.refresh_phase_attempt_projection();
        app.hydrate_view_keys_blocking(workspace.root(), keys);
        app
    }

    fn write_map_artifact(target: &Path) {
        let artifact = target.join(".kuzushi/context-snapshot.json");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        std::fs::write(artifact, r#"{"filesIndexed":1}"#).unwrap();
    }

    fn write_empty_map_artifact(target: &Path) {
        let artifact = target.join(".kuzushi/context-snapshot.json");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        std::fs::write(artifact, r#"{"filesIndexed":0}"#).unwrap();
    }

    fn completed_scan_summary(target: &Path, run_id: &str) -> RunSummary {
        RunSummary::running(
            run_id,
            "scan",
            Some("sast:scan".to_string()),
            target.display().to_string(),
        )
        .complete()
    }

    fn finding_with_scan_id(scan_id: &str) -> Finding {
        let mut finding = Finding::new_tool(
            "semgrep",
            "legacy.rule",
            "src/lib.rs",
            1,
            None,
            Severity::High,
            "candidate",
        );
        finding.scan_id = Some(scan_id.to_string());
        finding
    }

    fn record_attempt(target: &Path, phase: WorkflowPhase, run_id: &str, discarded: bool) {
        let completed = PhaseAttemptCompleted::new(
            phase,
            vec![run_id.to_string()],
            PhaseTargetSnapshot::capture(target),
            PhaseAttemptOutcome::Completed,
        );
        append_phase_attempt_completed(target, completed.clone()).unwrap();
        if discarded {
            append_phase_attempt_disposition(
                target,
                PhaseAttemptDispositionRecorded::new(
                    completed.attempt_id,
                    PhaseAttemptDisposition::Discarded,
                ),
            )
            .unwrap();
        }
    }

    fn record_selected_scan_attempt(target: &Path, outcome: PhaseAttemptOutcome) {
        let snapshot = PhaseTargetSnapshot::capture(target);
        append_phase_checkpoint_skipped(
            target,
            PhaseCheckpointSkipped::new(WorkflowPhase::Map, snapshot.clone()),
        )
        .unwrap();
        let completed = PhaseAttemptCompleted::new(
            WorkflowPhase::Scan,
            vec!["scan-clean".to_string()],
            snapshot,
            outcome,
        );
        append_phase_attempt_completed(target, completed.clone()).unwrap();
        append_phase_attempt_disposition(
            target,
            PhaseAttemptDispositionRecorded::new(
                completed.attempt_id,
                PhaseAttemptDisposition::Selected {
                    acknowledged_partial: outcome == PhaseAttemptOutcome::Partial,
                },
            ),
        )
        .unwrap();
    }
}
