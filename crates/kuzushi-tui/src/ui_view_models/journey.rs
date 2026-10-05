//! Durable investigation projection for Map -> Scan -> Review -> Report.
//!
//! The selected Workbench page is intentionally absent from this module.
//! Reality advances only from current-target evidence: accepted phase attempts,
//! persisted findings/review decisions/verifications, and compatible legacy
//! run artifacts.

use crate::app::{FindingLedgerCounts, PlanningTaskId, ViewDataState, WorkflowPhase};
use crate::ui_view_models::review_state::{
    decision_is_review_actionable, indexed_review_decision_complete, EffectiveReviewStateIndex,
};
use crate::{RunSummaryEntriesState, ShellApp};
use kuzushi_core::findings::ReviewDecisionVerdict;
use kuzushi_core::workflow_attempts::{PhaseAttemptDisposition, PhaseAttemptOutcome};
use kuzushi_core::{
    Finding, PatchLifecycleRecord, PatchLifecycleState, RunSummary, RunSummaryEntryState,
    TriageVerdict,
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
    /// Same-target selected checkpoint that is intentionally not reusable for
    /// the current revision/dirty snapshot.
    pub checkpoint_drift: Option<CheckpointDrift>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointDrift {
    pub phase: WorkflowPhase,
    pub accepted_revision: Option<String>,
    pub current_revision: Option<String>,
    pub dirty_changed: bool,
    pub relationship: Option<kuzushi_core::workspace::RevisionRelationship>,
}

/// Cached and in-memory journey truth needed by routing and hydration.
///
/// Keep this projection and [`journey_model`] free of filesystem reads. Full
/// phase-result cards own durable run replay outside the journey projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JourneyRealityProjection {
    pub(crate) current: WorkflowPhase,
    pub(crate) destination: JourneyDestination,
    pub(crate) progress: JourneyProgress,
    pub(crate) checkpoint_drift: Option<CheckpointDrift>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JourneyDestination {
    Phase(WorkflowPhase),
    Report(ReportReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportReason {
    ReviewComplete,
    CleanScan,
    NoActionableAfterReview,
}

impl ReportReason {
    fn label(self) -> &'static str {
        match self {
            Self::ReviewComplete => "review decisions are recorded",
            Self::CleanScan => "accepted scan found no candidates",
            Self::NoActionableAfterReview => "review left no actionable findings",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JourneyPhaseStatus {
    pub phase: WorkflowPhase,
    pub state: JourneyPhaseState,
    pub(crate) access: JourneyPhaseAccess,
    pub phase_label: &'static str,
    pub state_symbol: &'static str,
    pub tone: JourneyPhaseTone,
}

impl JourneyPhaseStatus {
    pub(crate) fn navigation_symbol(self) -> &'static str {
        match self.access {
            JourneyPhaseAccess::Available => self.state_symbol,
            JourneyPhaseAccess::Locked { .. } => "×",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JourneyPhaseAccess {
    Available,
    Locked { reason: &'static str },
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
            // "○" not "·": the rail joins segments with " · ", and a
            // middle-dot pending glyph collides into "scan · ·".
            Self::Pending => "○",
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
        JourneyDestination::Report(ReportReason::ReviewComplete)
    }

    pub fn current_phase(self) -> WorkflowPhase {
        match self.destination() {
            JourneyDestination::Phase(phase) => phase,
            JourneyDestination::Report(ReportReason::CleanScan) => WorkflowPhase::Scan,
            JourneyDestination::Report(
                ReportReason::NoActionableAfterReview | ReportReason::ReviewComplete,
            ) => WorkflowPhase::Review,
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
    let reality = journey_reality_projection(app)?;
    let JourneyRealityProjection {
        current,
        destination,
        progress,
        checkpoint_drift,
    } = reality;
    let failed = failed_phase_set(app);
    let explicitly_skipped = app.engagement.projected_skipped_phases();
    let next_action = projected_next_action(app, destination, progress);
    Some(JourneyModel {
        phases: phase_statuses(app, destination, progress, &explicitly_skipped, &failed),
        current,
        destination,
        progress,
        next_summary: destination_next_summary(destination, progress, &next_action),
        next_action,
        next_tools: projected_next_tools(app, destination),
        checkpoint_drift,
    })
}

pub(crate) fn journey_reality_projection(app: &ShellApp) -> Option<JourneyRealityProjection> {
    let target = app.target()?;
    let map_artifacts_built = cached_map_artifacts_built(app, target);
    let progress = journey_progress(app, map_artifacts_built);
    let unresolved_phase = earliest_unresolved_phase(app);
    let destination = journey_destination(progress, unresolved_phase);
    let current = match destination {
        JourneyDestination::Phase(phase) => phase,
        JourneyDestination::Report(_) => progress.current_phase(),
    };
    Some(JourneyRealityProjection {
        current,
        destination,
        progress,
        checkpoint_drift: checkpoint_drift(app, current),
    })
}

fn journey_destination(
    progress: JourneyProgress,
    unresolved_phase: Option<WorkflowPhase>,
) -> JourneyDestination {
    let required = progress.destination();
    let unresolved_phase =
        unresolved_phase.filter(|phase| WorkflowPhase::INVESTIGATION_ORDER.contains(phase));
    match (required, unresolved_phase) {
        (JourneyDestination::Phase(required), Some(unresolved)) if required <= unresolved => {
            JourneyDestination::Phase(required)
        }
        (_, Some(unresolved)) => JourneyDestination::Phase(unresolved),
        (required, None) => required,
    }
}

fn earliest_unresolved_phase(app: &ShellApp) -> Option<WorkflowPhase> {
    WorkflowPhase::INVESTIGATION_ORDER
        .iter()
        .copied()
        .find(|phase| app.engagement.unresolved_phase_attempt(*phase).is_some())
}

/// Review and Prove selection accepts existing evidence; it does not create
/// Map/Scan checkpoints. Predict the same destination routing will derive
/// after this pending result is selected, retaining other pending results.
pub(crate) fn journey_destination_after_selection(
    app: &ShellApp,
    phase: WorkflowPhase,
) -> Option<JourneyDestination> {
    if !matches!(phase, WorkflowPhase::Review | WorkflowPhase::Prove) {
        return None;
    }
    let progress = journey_reality_projection(app)?.progress;
    let unresolved = WorkflowPhase::INVESTIGATION_ORDER
        .iter()
        .copied()
        .filter(|other| *other != phase)
        .find(|other| app.engagement.unresolved_phase_attempt(*other).is_some());
    Some(journey_destination(progress, unresolved))
}

fn checkpoint_drift(app: &ShellApp, phase: WorkflowPhase) -> Option<CheckpointDrift> {
    if app.engagement.phase_attempt_projection_is_degraded() {
        return None;
    }
    let accepted = app.engagement.stale_selected_phase_attempt(phase)?;
    let current = app.engagement.phase_target_snapshot()?;
    let accepted_snapshot = &accepted.completed.target_snapshot;
    let relationship = accepted_snapshot
        .revision
        .as_deref()
        .zip(current.revision.as_deref())
        .and_then(|(accepted, current_revision)| {
            if accepted == current_revision {
                return Some(kuzushi_core::workspace::RevisionRelationship::Same);
            }
            match app.workbench_cache().borrow().cached_revision_relationship(
                app.target(),
                accepted,
                current_revision,
            ) {
                ViewDataState::Ready(relationship) => Some(relationship),
                ViewDataState::NotRequested | ViewDataState::Loading => None,
            }
        });
    Some(CheckpointDrift {
        phase,
        accepted_revision: accepted_snapshot.revision.clone(),
        current_revision: current.revision.clone(),
        dirty_changed: accepted_snapshot.dirty != current.dirty,
        relationship,
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
    let mut progress = journey_finding_progress(
        map_artifacts_built,
        app.domain().finding_ledger_counts(),
        || {
            let review_index = EffectiveReviewStateIndex::from_findings_and_decisions(
                app.findings(),
                app.review_decisions(),
            );
            journey_progress_from_parts(map_artifacts_built, app.findings(), &review_index)
        },
    );
    let selected_map = selected_attempt_counts(app, WorkflowPhase::Map);
    let selected_scan = selected_attempt_counts(app, WorkflowPhase::Scan);
    let legacy = legacy_checkpoints(app, map_artifacts_built);
    progress.map_checkpoint =
        selected_map.is_some() || app.engagement.phase_is_skipped(WorkflowPhase::Map) || legacy.map;
    progress.scan_checkpoint = selected_scan.is_some()
        && app
            .engagement
            .selected_attempt_completed_after(WorkflowPhase::Map, WorkflowPhase::Scan)
        || legacy.scan && selected_map.is_none();
    progress.scan_partial_acknowledged = selected_scan == Some(true);
    progress.legacy_inferred = legacy.map || legacy.scan;
    progress
}

fn journey_finding_progress<F>(
    map_artifacts_built: bool,
    counts: Option<FindingLedgerCounts>,
    findings_fallback: F,
) -> JourneyProgress
where
    F: FnOnce() -> JourneyProgress,
{
    match counts {
        Some(counts) => journey_progress_from_counts(map_artifacts_built, counts),
        None => findings_fallback(),
    }
}

fn journey_progress_from_counts(
    map_artifacts_built: bool,
    counts: FindingLedgerCounts,
) -> JourneyProgress {
    JourneyProgress {
        map_artifacts_built,
        map_checkpoint: false,
        scan_checkpoint: false,
        scan_partial_acknowledged: false,
        finding_total: counts.total,
        reviewed_findings: counts.reviewed,
        confirmed_findings: counts.confirmed,
        proven_findings: counts.proven.saturating_add(counts.proof_deferred),
        proof_backed_findings: counts.proof_backed,
        remediated_findings: counts.remediated,
        remediation_projection_complete: counts.remediation_projection_complete,
        legacy_inferred: false,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LegacyCheckpoints {
    map: bool,
    scan: bool,
}

fn legacy_checkpoints(app: &ShellApp, map_artifacts_built: bool) -> LegacyCheckpoints {
    if app.engagement.phase_attempt_projection_is_degraded() {
        return LegacyCheckpoints::default();
    }
    let durable_finding_scan = app
        .domain()
        .finding_ledger_counts()
        .is_some_and(|counts| counts.durable_scan_evidence);
    let scan = legacy_inference_applies(app, WorkflowPhase::Scan)
        && (legacy_completed_scan(app) || durable_finding_scan);
    let map = legacy_inference_applies(app, WorkflowPhase::Map)
        && !app.engagement.phase_is_skipped(WorkflowPhase::Map)
        && (map_artifacts_built || scan);
    LegacyCheckpoints { map, scan }
}

/// Pre-ledger inference is only meaningful for a phase this engagement has
/// never attempted as a first-class attempt — and only while no such attempt
/// is running.
fn legacy_inference_applies(app: &ShellApp, phase: WorkflowPhase) -> bool {
    !app.engagement.has_phase_attempt_for_target(phase) && !phase_attempt_in_flight(app, phase)
}

/// Returns whether a first-class attempt for `phase` is still in flight.
///
/// Attempt records are appended at completion, while Map tools such as
/// `context:build` and `entry-points:extract` write their `.kuzushi/`
/// artifacts as they go. Without this guard the legacy inference reads those
/// half-written artifacts as a finished Map and advances the phase chip to
/// Scan mid-run, only to fall back once the attempt record lands.
///
/// Liveness is the live Run Focus session's launch phase plus its terminal
/// stamp, corroborated by the shared single-slot `JobHub`. Every path that
/// finishes a slot (`ShellApp::apply_job_event`) stamps `completed_at` through
/// `mark_run_focus_terminal_pending` before the hub slot is cleared, so a
/// finished, canceled, or interrupted run stops suppressing immediately. A
/// backgrounded run keeps both signals, which is correct: it is still in
/// flight. Requiring the hub as well means a session that was seeded but never
/// dispatched cannot suppress inference forever.
fn phase_attempt_in_flight(app: &ShellApp, phase: WorkflowPhase) -> bool {
    app.jobs().has_running_job()
        && (run_focus_phase_in_flight(app, phase) || running_tool_serves_phase(app, phase))
}

fn run_focus_phase_in_flight(app: &ShellApp, phase: WorkflowPhase) -> bool {
    app.activity().is_some_and(|session| {
        session.origin_phase == Some(phase) && session.completed_at.is_none()
    })
}

/// An ad-hoc run (`run context:build`, an agent launch) carries no origin
/// phase, yet its tool still writes that phase's artifacts while it runs.
fn running_tool_serves_phase(app: &ShellApp, phase: WorkflowPhase) -> bool {
    app.running_tool_name()
        .and_then(kuzushi_core::modules::autonomy::tool_phase)
        == Some(phase)
}

/// Returns whether an accepted checkpoint was a partial result explicitly
/// acknowledged by the operator. Blocked/failed/canceled attempts are never
/// selected by the ledger validator and therefore cannot advance reality.
fn selected_attempt_counts(app: &ShellApp, phase: WorkflowPhase) -> Option<bool> {
    if app.engagement.phase_attempt_projection_is_degraded() {
        return None;
    }
    let record = app.engagement.selected_phase_attempt(phase)?;
    match app.effective_phase_attempt_outcome(&record.completed) {
        PhaseAttemptOutcome::Completed => Some(false),
        PhaseAttemptOutcome::Partial => {
            match record.disposition.as_ref().map(|value| &value.disposition) {
                Some(PhaseAttemptDisposition::Selected {
                    acknowledged_partial: true,
                }) => Some(true),
                _ => None,
            }
        }
        PhaseAttemptOutcome::Blocked
        | PhaseAttemptOutcome::Failed
        | PhaseAttemptOutcome::Canceled => None,
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
            && verification.is_empirically_verified()
    })
}

fn finding_has_verified_remediation(
    finding: &Finding,
    lifecycles: &[PatchLifecycleRecord],
) -> bool {
    lifecycles.iter().any(|record| {
        record.is_empirically_verified()
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
    finding.verification.as_ref().is_some_and(|verification| {
        verification.is_current_for_scan(finding.scan_id.as_deref())
            && verification.has_terminal_runtime_verification()
    })
}

fn indexed_actionable_finding(index: &EffectiveReviewStateIndex, finding: &Finding) -> bool {
    decision_is_review_actionable(finding, index.effective_decision_for(finding).as_ref())
}

fn failed_phase_set(app: &ShellApp) -> BTreeSet<WorkflowPhase> {
    let mut failed: BTreeSet<WorkflowPhase> = app
        .engagement
        .failed_tasks()
        .iter()
        .map(|failed| failed.task.phase())
        .collect();
    for &phase in WorkflowPhase::INVESTIGATION_ORDER {
        let Some(record) = app.engagement.unresolved_phase_attempt(phase) else {
            continue;
        };
        if matches!(
            app.effective_phase_attempt_outcome(&record.completed),
            PhaseAttemptOutcome::Blocked
                | PhaseAttemptOutcome::Failed
                | PhaseAttemptOutcome::Canceled
        ) {
            failed.insert(phase);
        }
    }
    failed
}

fn phase_statuses(
    app: &ShellApp,
    destination: JourneyDestination,
    progress: JourneyProgress,
    explicitly_skipped: &BTreeSet<WorkflowPhase>,
    failed: &BTreeSet<WorkflowPhase>,
) -> Vec<JourneyPhaseStatus> {
    let access = phase_access(app, progress);
    WorkflowPhase::INVESTIGATION_ORDER
        .iter()
        .zip(access)
        .map(|(&phase, access)| {
            let state = phase_state(phase, destination, explicitly_skipped, failed);
            JourneyPhaseStatus {
                phase,
                state,
                access,
                phase_label: phase_rail_label(phase),
                state_symbol: state.glyph(),
                tone: JourneyPhaseTone::from_state(state),
            }
        })
        .collect()
}

fn phase_access(app: &ShellApp, progress: JourneyProgress) -> [JourneyPhaseAccess; 3] {
    [
        JourneyPhaseAccess::Available,
        available_for(
            app,
            WorkflowPhase::Scan,
            scan_view_has_material(app, progress),
            "complete or skip Map first",
        ),
        available_for(
            app,
            WorkflowPhase::Review,
            app.findings_total_count() > 0,
            "no vulnerabilities to review; complete Scan or import findings",
        ),
    ]
}

fn available_for(
    app: &ShellApp,
    phase: WorkflowPhase,
    has_material: bool,
    reason: &'static str,
) -> JourneyPhaseAccess {
    if has_material || app.engagement.unresolved_phase_attempt(phase).is_some() {
        JourneyPhaseAccess::Available
    } else {
        JourneyPhaseAccess::Locked { reason }
    }
}

fn scan_view_has_material(app: &ShellApp, progress: JourneyProgress) -> bool {
    progress.map_checkpoint
        || progress.scan_checkpoint
        || app
            .engagement
            .has_phase_attempt_for_target(WorkflowPhase::Scan)
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

/// Whether the engagement has completed or moved past `phase`. A direct phase
/// verb then opens the durable Workbench page instead of that phase's planner;
/// a phase the journey has not reached yet keeps the planner, since that is
/// how its work starts.
pub(crate) fn phase_complete_or_passed(
    phase: WorkflowPhase,
    destination: JourneyDestination,
) -> bool {
    match destination {
        JourneyDestination::Phase(current) => phase < current,
        JourneyDestination::Report(reason) => {
            report_phase_state(phase, reason) == JourneyPhaseState::Done
        }
    }
}

/// [`phase_complete_or_passed`] over the app's cached reality projection;
/// false without a target.
pub(crate) fn phase_verb_opens_page(app: &ShellApp, phase: WorkflowPhase) -> bool {
    journey_reality_projection(app)
        .is_some_and(|reality| phase_complete_or_passed(phase, reality.destination))
}

fn report_phase_state(phase: WorkflowPhase, reason: ReportReason) -> JourneyPhaseState {
    let last_applicable = match reason {
        ReportReason::CleanScan => WorkflowPhase::Scan,
        ReportReason::NoActionableAfterReview | ReportReason::ReviewComplete => {
            WorkflowPhase::Review
        }
    };
    if phase <= last_applicable {
        JourneyPhaseState::Done
    } else {
        JourneyPhaseState::Skipped
    }
}

fn phase_rail_label(phase: WorkflowPhase) -> &'static str {
    // English word carries the phase; the state glyph that follows accents it.
    match phase {
        WorkflowPhase::Map => "Map ",
        WorkflowPhase::Scan => "Scan ",
        WorkflowPhase::Review => "Review ",
        WorkflowPhase::Prove => "Prove ",
        WorkflowPhase::Fix => "Fix ",
    }
}

fn destination_next_action(destination: JourneyDestination, progress: JourneyProgress) -> String {
    match destination {
        JourneyDestination::Phase(WorkflowPhase::Map) if progress.map_artifacts_built => {
            "choose whether to reuse, run, or skip current-revision Map evidence".to_string()
        }
        JourneyDestination::Phase(WorkflowPhase::Map) => {
            "build or explicitly skip the current-revision map".to_string()
        }
        JourneyDestination::Phase(WorkflowPhase::Scan) => {
            "run discovery-only scanners and select a completed attempt".to_string()
        }
        // "ledger candidates" names the population: these counts come from
        // the durable candidate ledger, which can be far larger than the
        // findings loaded into this session's list.
        JourneyDestination::Phase(WorkflowPhase::Review) => format!(
            "review {} remaining findings ({} total)",
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
    unresolved_attempt(app, destination)
        .map(|record| unresolved_attempt_action(app, record))
        .unwrap_or_else(|| destination_next_action(destination, progress))
}

fn unresolved_attempt(
    app: &ShellApp,
    destination: JourneyDestination,
) -> Option<&kuzushi_core::workflow_attempts::PhaseAttemptRecord> {
    let destination_attempt = match destination {
        JourneyDestination::Phase(phase) => app.engagement.unresolved_phase_attempt(phase),
        JourneyDestination::Report(_) => None,
    };
    destination_attempt.or_else(|| {
        WorkflowPhase::INVESTIGATION_ORDER
            .iter()
            .find_map(|phase| app.engagement.unresolved_phase_attempt(*phase))
    })
}

pub(super) fn unresolved_attempt_action(
    app: &ShellApp,
    record: &kuzushi_core::workflow_attempts::PhaseAttemptRecord,
) -> String {
    let completed = &record.completed;
    if let Some(reason) = app.phase_recovery_prerequisite_blocker(completed.phase) {
        return reason;
    }
    if let Some(reason) = app.effective_phase_attempt_blocker(completed) {
        return reason;
    }
    let outcome = match app.cached_authoritative_phase_attempt_outcome(completed) {
        ViewDataState::Ready(outcome) => outcome,
        ViewDataState::NotRequested | ViewDataState::Loading => {
            return format!(
                "inspect the {} result while its receipt loads",
                completed.phase.title()
            );
        }
    };
    match outcome {
        PhaseAttemptOutcome::Completed => format!(
            "accept, continue with, or discard the completed {} result",
            completed.phase.title()
        ),
        PhaseAttemptOutcome::Partial => partial_acknowledgement_action(completed.phase),
        outcome => format!(
            "inspect, rerun, or discard the {} {} result",
            phase_attempt_outcome_label(outcome),
            completed.phase.title()
        ),
    }
}

fn phase_attempt_outcome_label(outcome: PhaseAttemptOutcome) -> &'static str {
    match outcome {
        PhaseAttemptOutcome::Completed => "completed",
        PhaseAttemptOutcome::Partial => "partial",
        PhaseAttemptOutcome::Blocked => "blocked",
        PhaseAttemptOutcome::Failed => "failed",
        PhaseAttemptOutcome::Canceled => "canceled",
    }
}

fn partial_acknowledgement_action(phase: WorkflowPhase) -> String {
    let mut chars = phase.word().chars();
    let first = chars.next().unwrap_or_default().to_ascii_uppercase();
    let title = format!("{first}{}", chars.as_str());
    format!("acknowledge the partial {title}")
}

fn projected_next_tools(app: &ShellApp, destination: JourneyDestination) -> String {
    if unresolved_attempt(app, destination).is_some() {
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
        JourneyDestination::Phase(phase) => {
            format!("{} · {next_action}{inferred}", phase.title())
        }
        JourneyDestination::Report(reason) if next_action.starts_with("open Report") => {
            format!("REPORT · {}{inferred}", reason.label())
        }
        JourneyDestination::Report(_) => format!("ATTENTION · {next_action}{inferred}"),
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
    if !WorkflowPhase::INVESTIGATION_ORDER.contains(&phase) {
        return format!("{} · compatibility", phase.title());
    }
    format!(
        "{} {}/{}",
        phase.title(),
        phase.position(),
        WorkflowPhase::INVESTIGATION_ORDER.len()
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
    let mut segment = format!("⛭ autonomy:{}", posture.label());
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
        PhaseAttemptRecord, PhaseCheckpointSkipped, PhaseTargetSnapshot,
    };
    use kuzushi_core::{
        write_run_summary, PatchLifecycleRecord, PersistedProofVerdict, PersistedSandboxBackend,
        PersistedVerification, RunTargetGitMetadata, Severity, TriageOutcome, V2Config,
        WorkspaceTarget,
    };
    use std::cell::Cell;
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
    fn phase_complete_or_passed_opens_pages_only_behind_the_journey() {
        let review = JourneyDestination::Phase(WorkflowPhase::Review);
        assert!(phase_complete_or_passed(WorkflowPhase::Map, review));
        assert!(phase_complete_or_passed(WorkflowPhase::Scan, review));
        assert!(!phase_complete_or_passed(WorkflowPhase::Review, review));
        assert!(!phase_complete_or_passed(WorkflowPhase::Fix, review));

        let clean = JourneyDestination::Report(ReportReason::CleanScan);
        assert!(phase_complete_or_passed(WorkflowPhase::Scan, clean));
        assert!(!phase_complete_or_passed(WorkflowPhase::Review, clean));

        let remediated = JourneyDestination::Report(ReportReason::ReviewComplete);
        assert!(WorkflowPhase::INVESTIGATION_ORDER
            .iter()
            .all(|phase| phase_complete_or_passed(*phase, remediated)));
    }

    #[test]
    fn guided_checkpoints_end_at_review_without_proof_or_patching() {
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
            WorkflowPhase::Review
        );
        assert_eq!(
            progress(true, true, 2, 2, 1, 1, 1, 0).current_phase(),
            WorkflowPhase::Review
        );
        assert_eq!(
            progress(true, true, 2, 2, 1, 1, 1, 1).destination(),
            JourneyDestination::Report(ReportReason::ReviewComplete)
        );
    }

    #[test]
    fn authoritative_ledger_counts_skip_the_findings_fallback() {
        let fallback_calls = Cell::new(0);
        let counts = FindingLedgerCounts {
            total: 401,
            reviewed: 307,
            confirmed: 29,
            proven: 11,
            proof_deferred: 3,
            proof_backed: 7,
            remediated: 5,
            remediation_projection_complete: true,
            durable_scan_evidence: true,
        };

        let progress = journey_finding_progress(true, Some(counts), || {
            fallback_calls.set(fallback_calls.get() + 1);
            progress(false, false, 1, 1, 1, 1, 1, 1)
        });

        assert_eq!(fallback_calls.get(), 0);
        assert_eq!(progress.finding_total, 401);
        assert_eq!(progress.reviewed_findings, 307);
        assert_eq!(progress.confirmed_findings, 29);
        assert_eq!(progress.proven_findings, 14);
        assert_eq!(progress.proof_backed_findings, 7);
        assert_eq!(progress.remediated_findings, 5);
        assert!(progress.map_artifacts_built);
        assert!(progress.remediation_projection_complete);
    }

    #[test]
    fn missing_ledger_counts_preserve_the_findings_fallback() {
        let fallback = progress(false, false, 2, 1, 1, 0, 0, 0);

        assert_eq!(journey_finding_progress(false, None, || fallback), fallback);
    }

    #[test]
    fn unresolved_action_uses_durable_fallback_without_building_presentation() {
        let app = ShellApp::new(V2Config::default(), None);
        let snapshot = PhaseTargetSnapshot {
            target: "/target".to_string(),
            revision: None,
            dirty: false,
        };
        let cases = [
            (
                PhaseAttemptOutcome::Completed,
                "accept, continue with, or discard the completed Map result",
            ),
            (PhaseAttemptOutcome::Partial, "acknowledge the partial Map"),
            (
                PhaseAttemptOutcome::Blocked,
                "inspect, rerun, or discard the blocked Map result",
            ),
            (
                PhaseAttemptOutcome::Failed,
                "inspect, rerun, or discard the failed Map result",
            ),
            (
                PhaseAttemptOutcome::Canceled,
                "inspect, rerun, or discard the canceled Map result",
            ),
        ];
        crate::app::take_phase_result_presentation_calls();

        for (outcome, expected) in cases {
            let record = PhaseAttemptRecord {
                completed: PhaseAttemptCompleted::new(
                    WorkflowPhase::Map,
                    vec!["run-must-not-be-read".to_string()],
                    snapshot.clone(),
                    outcome,
                ),
                disposition: None,
            };
            assert_eq!(unresolved_attempt_action(&app, &record), expected);
        }

        assert_eq!(crate::app::take_phase_result_presentation_calls(), 0);

        let counter_probe = PhaseAttemptCompleted::new(
            WorkflowPhase::Map,
            vec!["missing-counter-probe".to_string()],
            snapshot,
            PhaseAttemptOutcome::Completed,
        );
        app.phase_result_presentation_for(&counter_probe);
        assert_eq!(crate::app::take_phase_result_presentation_calls(), 1);
    }

    #[test]
    fn unresolved_action_prefers_hydrated_typed_receipt_when_outcomes_disagree() {
        crate::app::take_phase_result_presentation_calls();
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        crate::test_support::record_indexed_run(
            target.path(),
            "receipt-authority",
            "sast:scan",
            serde_json::json!({
                "ok": true,
                "status": "completed",
                "summary": "scan completed",
                "data": {"count": 0}
            }),
        );
        let mut completed = crate::test_support::append_typed_attempt(
            target.path(),
            WorkflowPhase::Scan,
            "receipt-authority",
            PhaseAttemptOutcome::Failed,
        );
        completed.outcome = PhaseAttemptOutcome::Completed;
        let attempt_id = completed.attempt_id.clone();
        let snapshot = completed.target_snapshot.clone();
        let ledger = PhaseAttemptLedger::from_events([
            kuzushi_core::workflow_attempts::PhaseAttemptEvent::PhaseAttemptCompleted(completed),
        ])
        .unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.engagement
            .set_phase_attempt_projection(Some(snapshot), ledger);
        app.hydrate_view_keys_blocking(
            workspace.root(),
            vec![ViewHydrationKey::PhaseReceiptOutcome {
                attempt_id: attempt_id.clone(),
            }],
        );
        let receipt_state = app
            .workbench_cache()
            .borrow()
            .cached_phase_receipt_outcome(workspace.root(), &attempt_id);
        assert!(
            matches!(receipt_state, ViewDataState::Ready(Ok(Some(_)))),
            "{receipt_state:?}"
        );
        let record = app
            .engagement
            .unresolved_phase_attempt(WorkflowPhase::Scan)
            .expect("contradictory unresolved attempt");

        assert_eq!(record.completed.outcome, PhaseAttemptOutcome::Completed);
        assert_eq!(
            unresolved_attempt_action(&app, record),
            "inspect, rerun, or discard the failed Scan result"
        );
        assert_eq!(crate::app::take_phase_result_presentation_calls(), 0);
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
            JourneyDestination::Report(ReportReason::ReviewComplete)
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

        let mut model_assessed =
            actionable_finding_with_verification("scan-2", "scan-2", "model-2");
        model_assessed.verification.as_mut().unwrap().backend = PersistedSandboxBackend::Model;
        for verdict in [
            PersistedProofVerdict::Exploited,
            PersistedProofVerdict::NotAttempted,
        ] {
            model_assessed.verification.as_mut().unwrap().proof_verdict = verdict;
            let index = EffectiveReviewStateIndex::from_findings_and_decisions(
                std::slice::from_ref(&model_assessed),
                &[],
            );
            let progress =
                journey_progress_from_parts(false, std::slice::from_ref(&model_assessed), &index);
            assert_eq!(progress.proven_findings, 0);
            assert_eq!(progress.proof_backed_findings, 0);
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
        // A deferral is a decision, never proof: the proven and proof-backed
        // folds must stay at zero for the very generation it was recorded on.
        assert_eq!(counts.proven, 0);
        assert_eq!(counts.proof_backed, 0);
        // The same decision projects for display, so a selected finding can
        // disclose it instead of reading as merely unproven.
        let view = app
            .engagement
            .proof_deferral_for(&finding)
            .map(kuzushi_core::workflow_attempts::ProofDeferralView::from_record)
            .expect("projected proof deferral");
        assert_eq!(view.scan_id, "scan-1");
        assert_eq!(view.actor, "operator");
        assert_eq!(
            view.reason,
            "runtime environment is intentionally unavailable"
        );

        let stale = actionable_finding("scan-2");
        let mut stale_counts = finding_ledger_counts(std::slice::from_ref(&stale), &[], 1);
        attach_proof_deferral_counts(
            &mut stale_counts,
            std::slice::from_ref(&stale),
            &[],
            &app.engagement,
        );
        assert_eq!(stale_counts.proof_deferred, 0);
        assert!(app.engagement.proof_deferral_for(&stale).is_none());
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
        lifecycle.reverify_evidence = None;
        attach_remediation_counts(
            &mut counts,
            std::slice::from_ref(&finding),
            &[],
            std::slice::from_ref(&lifecycle),
        );
        assert_eq!(counts.remediated, 0);

        lifecycle.reverify_evidence = Some(crate::test_support::test_reverify_evidence_ref());
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
        let mut verification = crate::test_support::test_empirical_verification(3);
        verification.verification_run_id = Some(verification_run_id.to_string());
        verification.verified_scan_id = Some(verified_scan_id.to_string());
        finding.verification = Some(verification);
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
            reverify_evidence: Some(crate::test_support::test_reverify_evidence_ref()),
            detail: None,
            actor: "operator".to_string(),
            application_started_at: "1".to_string(),
            applied_at: Some("1".to_string()),
            updated_at: "2".to_string(),
        }
    }

    #[test]
    fn report_marks_not_applicable_future_phases_skipped() {
        let app = ShellApp::new(V2Config::default(), None);
        let statuses = phase_statuses(
            &app,
            JourneyDestination::Report(ReportReason::CleanScan),
            progress(true, true, 0, 0, 0, 0, 0, 0),
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
            let expected = if discarded {
                "choose whether to reuse, run, or skip current-revision Map evidence"
            } else {
                "accept, continue with, or discard the completed Map result"
            };
            assert_eq!(journey.next_action, expected);
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
    fn newer_selected_map_reopens_scan_without_dropping_findings() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        record_selected_scan_attempt(target.path(), PhaseAttemptOutcome::Completed);
        crate::test_support::record_indexed_run(
            target.path(),
            "map-new",
            "threat-model:build",
            serde_json::json!({
                "ok": true,
                "status": "completed",
                "summary": "new map",
                "warnings": [],
                "data": {"components": 4}
            }),
        );
        let map = crate::test_support::append_typed_attempt(
            target.path(),
            WorkflowPhase::Map,
            "map-new",
            PhaseAttemptOutcome::Completed,
        );
        crate::test_support::select_typed_attempt(target.path(), &map);

        let mut app = hydrated_app(&workspace, Vec::new());
        let finding = finding_with_scan_id("scan-clean");
        let counts = finding_ledger_counts(std::slice::from_ref(&finding), &[], 1);
        app.set_findings(vec![finding]);
        app.domain_mut().set_finding_ledger_counts(counts);

        let journey = journey_model(&app).unwrap();
        assert!(journey.progress.map_checkpoint);
        assert!(!journey.progress.scan_checkpoint);
        assert_eq!(journey.progress.finding_total, 1);
        assert_eq!(journey.current, WorkflowPhase::Scan);
    }

    #[test]
    fn unresolved_partial_scan_acknowledgement_outranks_generic_next_action() {
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
        record_phase_source(
            target.path(),
            WorkflowPhase::Scan,
            "scan-partial",
            "partial",
        );
        let partial = PhaseAttemptCompleted::new(
            WorkflowPhase::Scan,
            vec!["scan-partial".to_string()],
            PhaseTargetSnapshot::capture(target.path()),
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
    fn unresolved_completed_map_outranks_later_reality_guidance() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        record_selected_scan_attempt(target.path(), PhaseAttemptOutcome::Completed);
        record_phase_source(target.path(), WorkflowPhase::Map, "map-new", "completed");
        let map = PhaseAttemptCompleted::new(
            WorkflowPhase::Map,
            vec!["map-new".to_string()],
            PhaseTargetSnapshot::capture(target.path()),
            PhaseAttemptOutcome::Completed,
        );
        append_phase_attempt_completed(target.path(), map).unwrap();

        let journey = journey_model(&hydrated_app(&workspace, Vec::new())).unwrap();

        assert_eq!(
            journey.next_action,
            "accept, continue with, or discard the completed Map result"
        );
        assert!(journey.next_tools.is_empty());
        assert!(journey.next_summary.contains(&journey.next_action));
    }

    #[test]
    fn failed_map_stays_the_current_failed_phase_until_resolved() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let map = PhaseAttemptCompleted::new(
            WorkflowPhase::Map,
            vec!["map-failed".to_string()],
            PhaseTargetSnapshot::capture(target.path()),
            PhaseAttemptOutcome::Failed,
        );
        append_phase_attempt_completed(target.path(), map).unwrap();

        let journey = journey_model(&hydrated_app(&workspace, Vec::new())).unwrap();
        let map_status = journey
            .phases
            .iter()
            .find(|status| status.phase == WorkflowPhase::Map)
            .unwrap();

        assert_eq!(
            journey.destination,
            JourneyDestination::Phase(WorkflowPhase::Map)
        );
        assert_eq!(journey.current, WorkflowPhase::Map);
        assert_eq!(map_status.state, JourneyPhaseState::Failed);
        assert_eq!(map_status.state_symbol, "!");
        assert_eq!(
            journey.next_action,
            "inspect, rerun, or discard the failed Map result"
        );
    }

    #[test]
    fn unresolved_blocked_scan_outranks_missing_map_guidance() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let scan = PhaseAttemptCompleted::new(
            WorkflowPhase::Scan,
            vec!["scan-blocked".to_string()],
            PhaseTargetSnapshot::capture(target.path()),
            PhaseAttemptOutcome::Blocked,
        );
        append_phase_attempt_completed(target.path(), scan).unwrap();

        let journey = journey_model(&hydrated_app(&workspace, Vec::new())).unwrap();

        assert_eq!(
            journey.destination,
            JourneyDestination::Phase(WorkflowPhase::Map)
        );
        assert_eq!(journey.current, WorkflowPhase::Map);
        assert_eq!(
            journey
                .phases
                .iter()
                .find(|status| status.phase == WorkflowPhase::Scan)
                .map(|status| status.state),
            Some(JourneyPhaseState::Failed)
        );
        assert_eq!(
            journey.next_action,
            "inspect, rerun, or discard the blocked Scan result"
        );
        assert!(journey.next_tools.is_empty());
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
        assert_eq!(
            journey.next_action,
            "build or explicitly skip the current-revision map"
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
    fn stale_selected_map_is_disclosed_without_advancing_reality() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let current = PhaseTargetSnapshot::capture(target.path());
        let accepted = PhaseAttemptCompleted::new(
            WorkflowPhase::Map,
            vec!["map-old".to_string()],
            PhaseTargetSnapshot {
                target: current.target.clone(),
                revision: Some("accepted-revision".to_string()),
                dirty: false,
            },
            PhaseAttemptOutcome::Completed,
        );
        let ledger = PhaseAttemptLedger::from_events([
            kuzushi_core::workflow_attempts::PhaseAttemptEvent::PhaseAttemptCompleted(
                accepted.clone(),
            ),
            kuzushi_core::workflow_attempts::PhaseAttemptEvent::PhaseAttemptDispositionRecorded(
                PhaseAttemptDispositionRecorded::new(
                    accepted.attempt_id,
                    PhaseAttemptDisposition::Selected {
                        acknowledged_partial: false,
                    },
                ),
            ),
        ])
        .unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.engagement
            .set_phase_attempt_projection(Some(current), ledger);

        let journey = journey_model(&app).expect("journey");

        assert!(!journey.progress.map_checkpoint);
        assert_eq!(journey.current, WorkflowPhase::Map);
        let drift = journey.checkpoint_drift.expect("stale checkpoint");
        assert_eq!(drift.phase, WorkflowPhase::Map);
        assert_eq!(
            drift.accepted_revision.as_deref(),
            Some("accepted-revision")
        );
    }

    #[test]
    fn stale_selected_map_outranks_failed_scan_recovery_guidance() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut current = PhaseTargetSnapshot::capture(target.path());
        current.revision = Some("current-revision".to_string());
        let mut stale = current.clone();
        stale.revision = Some("accepted-revision".to_string());
        let map = PhaseAttemptCompleted::new(
            WorkflowPhase::Map,
            vec!["map-old".to_string()],
            stale,
            PhaseAttemptOutcome::Completed,
        );
        let scan = PhaseAttemptCompleted::new(
            WorkflowPhase::Scan,
            vec!["scan-failed".to_string()],
            current.clone(),
            PhaseAttemptOutcome::Failed,
        );
        let ledger = PhaseAttemptLedger::from_events([
            kuzushi_core::workflow_attempts::PhaseAttemptEvent::PhaseAttemptCompleted(map.clone()),
            kuzushi_core::workflow_attempts::PhaseAttemptEvent::PhaseAttemptDispositionRecorded(
                PhaseAttemptDispositionRecorded::new(
                    map.attempt_id,
                    PhaseAttemptDisposition::Selected {
                        acknowledged_partial: false,
                    },
                ),
            ),
            kuzushi_core::workflow_attempts::PhaseAttemptEvent::PhaseAttemptCompleted(scan),
        ])
        .unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.engagement
            .set_phase_attempt_projection(Some(current), ledger);

        let journey = journey_model(&app).unwrap();

        assert_eq!(
            journey.destination,
            JourneyDestination::Phase(WorkflowPhase::Map)
        );
        assert_eq!(
            journey.next_action,
            "rerun Map because the accepted Map is stale, then retry Scan"
        );
        assert!(journey.next_tools.is_empty());
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

    /// Fixture for issue #172: a first-ever Map run on a target whose Map
    /// tools have already written `.kuzushi/` artifacts, with no ledger
    /// attempt yet (the attempt record is appended at completion).
    fn app_with_map_run_in_flight(workspace: &WorkspaceTarget) -> ShellApp {
        let mut app = hydrated_app(workspace, vec![ViewHydrationKey::MapArtifacts]);
        let _ticket = app.jobs_mut().start(crate::app::JobKind::Run, "map");
        app.set_activity(Some(crate::app::ActivitySession::for_phase(
            "map-run-1",
            WorkflowPhase::Map,
        )));
        app
    }

    #[test]
    fn in_flight_first_map_run_does_not_infer_a_legacy_map_checkpoint() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        write_map_artifact(target.path());

        let app = app_with_map_run_in_flight(&workspace);
        let journey = journey_model(&app).expect("journey");

        assert!(journey.progress.map_artifacts_built);
        assert!(
            !journey.progress.map_checkpoint,
            "a running Map attempt has completed nothing"
        );
        assert!(!journey.progress.legacy_inferred);
        assert_eq!(journey.current, WorkflowPhase::Map);
        assert_eq!(
            journey_footer_segment(&app).as_deref(),
            Some("Map 1/3"),
            "the phase chip must not flip to Scan mid-run"
        );
    }

    #[test]
    fn ad_hoc_map_tool_run_keeps_the_phase_chip_on_map() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        write_map_artifact(target.path());
        let tool = "entry-points:extract";
        assert_eq!(
            kuzushi_core::modules::autonomy::tool_phase(tool),
            Some(WorkflowPhase::Map)
        );
        let mut app = hydrated_app(&workspace, vec![ViewHydrationKey::MapArtifacts]);
        let _ticket = app.jobs_mut().start(crate::app::JobKind::Run, tool);
        // A direct `run` carries no Run Focus origin phase.
        app.runtime_state.tool_run_mut().start(
            tool.to_string(),
            kuzushi_core::ScanCancellation::default(),
            "adhoc-run-1".to_string(),
            target.path().to_path_buf(),
            None,
        );

        let journey = journey_model(&app).expect("journey");

        assert!(!journey.progress.map_checkpoint);
        assert_eq!(journey.current, WorkflowPhase::Map);
    }

    #[test]
    fn backgrounded_map_run_still_suppresses_legacy_inference() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        write_map_artifact(target.path());

        let mut app = app_with_map_run_in_flight(&workspace);
        app.activity_mut().unwrap().run_focus_backgrounded = true;

        let journey = journey_model(&app).expect("journey");

        assert!(!journey.progress.map_checkpoint);
        assert_eq!(journey.current, WorkflowPhase::Map);
    }

    #[test]
    fn finished_and_cleared_map_session_does_not_suppress_legacy_inference() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        write_map_artifact(target.path());

        let mut app = app_with_map_run_in_flight(&workspace);
        // Terminal receipt: `mark_run_focus_terminal_pending` stamps
        // `completed_at`, then the hub slot is finished.
        app.activity_mut().unwrap().mark_terminal();
        app.jobs_mut().finish(crate::app::JobKind::Run);

        let journey = journey_model(&app).expect("journey");

        assert!(journey.progress.map_checkpoint);
        assert!(journey.progress.legacy_inferred);
    }

    #[test]
    fn completed_map_attempt_stays_on_map_until_the_operator_accepts_it() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        write_map_artifact(target.path());
        crate::test_support::record_indexed_run(
            target.path(),
            "map-run-1",
            "context:build",
            serde_json::json!({
                "ok": true,
                "status": "completed",
                "summary": "context snapshot built",
                "data": {"filesIndexed": 1}
            }),
        );
        let completed = crate::test_support::append_typed_attempt(
            target.path(),
            WorkflowPhase::Map,
            "map-run-1",
            PhaseAttemptOutcome::Completed,
        );

        let unresolved = hydrated_app(&workspace, vec![ViewHydrationKey::MapArtifacts]);
        assert_eq!(
            journey_model(&unresolved).expect("journey").current,
            WorkflowPhase::Map,
            "an unresolved attempt keeps reality on Map"
        );

        crate::test_support::select_typed_attempt(target.path(), &completed);
        let accepted = hydrated_app(&workspace, vec![ViewHydrationKey::MapArtifacts]);

        assert_eq!(
            journey_model(&accepted).expect("journey").current,
            WorkflowPhase::Scan
        );
    }

    fn hydrated_app(workspace: &WorkspaceTarget, mut keys: Vec<ViewHydrationKey>) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), Some(workspace));
        app.refresh_phase_attempt_projection();
        let receipt_keys = WorkflowPhase::ORDER.iter().filter_map(|phase| {
            app.engagement
                .unresolved_phase_attempt(*phase)
                .map(|record| ViewHydrationKey::PhaseReceiptOutcome {
                    attempt_id: record.completed.attempt_id.clone(),
                })
        });
        keys.extend(receipt_keys);
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

    fn record_phase_source(target: &Path, phase: WorkflowPhase, run: &str, status: &str) {
        let tool = if phase == WorkflowPhase::Map {
            "recon:scan"
        } else {
            "sast:scan"
        };
        crate::test_support::record_indexed_run(
            target,
            run,
            tool,
            serde_json::json!({
                "ok": true, "status": status, "data": {}
            }),
        );
    }

    fn record_attempt(target: &Path, phase: WorkflowPhase, run_id: &str, discarded: bool) {
        record_phase_source(target, phase, run_id, "completed");
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
        let status = if outcome == PhaseAttemptOutcome::Partial {
            "partial"
        } else {
            "completed"
        };
        crate::test_support::record_indexed_run(
            target,
            "scan-clean",
            "sast:scan",
            serde_json::json!({
                "ok": true,
                "status": status,
                "summary": "clean scan",
                "warnings": if status == "partial" { vec!["incomplete engine"] } else { Vec::<&str>::new() },
                "data": {"count": 0}
            }),
        );
        let completed = crate::test_support::append_typed_attempt(
            target,
            WorkflowPhase::Scan,
            "scan-clean",
            outcome,
        );
        crate::test_support::select_typed_attempt(target, &completed);
    }
}
