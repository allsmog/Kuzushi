//! The persistent engagement spine: where the operator is in the
//! 組 map → 崩 hunt → 作 confirm → 掛 fix journey, derived from workspace
//! reality (artifacts on disk, findings, triage/verification state) rather
//! than from the launch walker's transient state. The walker finishing
//! doesn't end the journey — the workspace always *is* somewhere.

use crate::app::{PlanningTaskId, WorkflowPhase};
use crate::ShellApp;
use kuzushi_core::{Finding, TriageVerdict};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JourneyModel {
    /// One entry per phase in canonical order, each marked done/current/pending.
    pub phases: Vec<JourneyPhaseStatus>,
    pub current: WorkflowPhase,
    pub progress: JourneyProgress,
    /// The home view's primary NEXT action: one concrete action for the
    /// current phase, without command mechanics or tuning hints.
    pub next_action: String,
    /// Concrete tools the `next` walker may dispatch for the current phase.
    pub next_tools: String,
    /// A compact Workbench header summary that keeps the engagement spine
    /// visible without competing with pane content.
    pub next_summary: String,
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
            JourneyPhaseState::Done => "✓",
            JourneyPhaseState::Current => "●",
            JourneyPhaseState::Failed => "!",
            JourneyPhaseState::Skipped => "⊘",
            JourneyPhaseState::Pending => "·",
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
            JourneyPhaseState::Done => JourneyPhaseTone::Success,
            JourneyPhaseState::Current => JourneyPhaseTone::Warn,
            JourneyPhaseState::Failed => JourneyPhaseTone::Danger,
            JourneyPhaseState::Skipped => JourneyPhaseTone::Muted,
            JourneyPhaseState::Pending => JourneyPhaseTone::Subtle,
        }
    }
}

/// What the workspace has actually produced, independent of any view state.
/// Pure with respect to derivation — the filesystem probe happens once at
/// the adapter boundary (`journey_model`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JourneyProgress {
    pub map_artifacts_built: bool,
    pub finding_total: usize,
    /// Findings dispositioned by triage or empirical verification. A
    /// `needs_review` triage result still belongs in 作 confirm.
    pub reviewed_findings: usize,
    /// Findings that should flow into 掛 fix work.
    pub confirmed_findings: usize,
}

impl JourneyProgress {
    /// First phase whose exit criterion isn't met. Findings outrank map
    /// artifacts: an imported-findings workspace (bounty HAR intake) is
    /// already confirming even though map was skipped. Fix is terminal — a
    /// fully confirmed workspace sits in fix until patches/reports ship.
    pub fn current_phase(self) -> WorkflowPhase {
        if self.finding_total > 0 {
            return if self.reviewed_findings < self.finding_total {
                WorkflowPhase::Confirm
            } else {
                WorkflowPhase::Fix
            };
        }
        if self.map_artifacts_built {
            WorkflowPhase::Hunt
        } else {
            WorkflowPhase::Map
        }
    }

    pub fn unreviewed_findings(self) -> usize {
        self.finding_total.saturating_sub(self.reviewed_findings)
    }
}

/// Derive the journey for the active workspace. `None` without a target —
/// there is no engagement to walk. A live walker phase can be highlighted, but
/// previous phases only become `Done` when workspace evidence proves progress.
pub fn journey_model(app: &ShellApp) -> Option<JourneyModel> {
    let target = app.target.as_deref()?;
    let progress = journey_progress_from_parts(
        app.workbench_cache
            .borrow_mut()
            .map_artifacts_built(Some(target)),
        &app.findings,
    );
    let derived_current = progress.current_phase();
    let current = app.engagement.current_phase().unwrap_or(derived_current);
    let failed_phases = failed_phase_set(app);
    Some(JourneyModel {
        phases: phase_statuses(
            current,
            derived_current,
            app.engagement.skipped_phases(),
            &failed_phases,
        ),
        current,
        progress,
        next_action: phase_next_action(current, progress),
        next_tools: phase_tool_hint(current),
        next_summary: phase_next_summary(current, progress),
    })
}

fn journey_progress_from_parts(map_artifacts_built: bool, findings: &[Finding]) -> JourneyProgress {
    JourneyProgress {
        map_artifacts_built,
        finding_total: findings.len(),
        reviewed_findings: findings.iter().filter(|f| is_reviewed_finding(f)).count(),
        confirmed_findings: findings.iter().filter(|f| is_confirmed(f)).count(),
    }
}

pub(crate) fn is_reviewed_finding(finding: &Finding) -> bool {
    finding.verification.is_some()
        || finding.triage.as_ref().is_some_and(|triage| {
            matches!(
                triage.verdict,
                TriageVerdict::TruePositive
                    | TriageVerdict::FalsePositive
                    | TriageVerdict::ByDesign
            )
        })
}

fn is_confirmed(finding: &Finding) -> bool {
    finding.verification.is_some()
        || finding
            .triage
            .as_ref()
            .is_some_and(|triage| triage.verdict == TriageVerdict::TruePositive)
}

fn failed_phase_set(app: &ShellApp) -> BTreeSet<WorkflowPhase> {
    app.engagement
        .failed_tasks()
        .iter()
        .map(|failed| failed.task.phase())
        .collect()
}

fn phase_statuses(
    current: WorkflowPhase,
    derived_current: WorkflowPhase,
    skipped_phases: &BTreeSet<WorkflowPhase>,
    failed_phases: &BTreeSet<WorkflowPhase>,
) -> Vec<JourneyPhaseStatus> {
    WorkflowPhase::ORDER
        .iter()
        .map(|&phase| {
            let state = phase_state(
                phase,
                current,
                derived_current,
                skipped_phases,
                failed_phases,
            );
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

fn phase_rail_label(phase: WorkflowPhase) -> &'static str {
    match phase {
        WorkflowPhase::Map => "組 map ",
        WorkflowPhase::Hunt => "崩 hunt ",
        WorkflowPhase::Confirm => "作 confirm ",
        WorkflowPhase::Fix => "掛 fix ",
    }
}

fn phase_state(
    phase: WorkflowPhase,
    current: WorkflowPhase,
    derived_current: WorkflowPhase,
    skipped_phases: &BTreeSet<WorkflowPhase>,
    failed_phases: &BTreeSet<WorkflowPhase>,
) -> JourneyPhaseState {
    if failed_phases.contains(&phase) {
        JourneyPhaseState::Failed
    } else if skipped_phases.contains(&phase) {
        JourneyPhaseState::Skipped
    } else if phase == current {
        JourneyPhaseState::Current
    } else if phase < derived_current {
        JourneyPhaseState::Done
    } else {
        JourneyPhaseState::Pending
    }
}

fn phase_next_action(current: WorkflowPhase, progress: JourneyProgress) -> String {
    match current {
        WorkflowPhase::Map => format!(
            "build context & analysis artifacts — 組 map, {} of {}",
            current.position(),
            WorkflowPhase::ORDER.len()
        ),
        WorkflowPhase::Hunt => format!(
            "hunt for findings — map artifacts ready (崩 hunt, {} of {})",
            current.position(),
            WorkflowPhase::ORDER.len()
        ),
        WorkflowPhase::Confirm => format!(
            "triage & verify — {} of {} findings need review",
            progress.unreviewed_findings(),
            progress.finding_total
        ),
        WorkflowPhase::Fix => format!(
            "patch & report — {} confirmed, {} reviewed",
            progress.confirmed_findings, progress.reviewed_findings
        ),
    }
}

fn phase_next_summary(current: WorkflowPhase, progress: JourneyProgress) -> String {
    match current {
        WorkflowPhase::Map => {
            "組 map · build context and analysis artifacts — next to continue".to_string()
        }
        WorkflowPhase::Hunt => {
            "崩 hunt · map artifacts ready — scan for the full hunt or next to choose tools"
                .to_string()
        }
        WorkflowPhase::Confirm => format!(
            "作 confirm · {} findings need review — next to continue",
            progress.unreviewed_findings()
        ),
        WorkflowPhase::Fix => format!(
            "掛 fix · {} confirmed findings — next to patch and report",
            progress.confirmed_findings
        ),
    }
}

fn phase_tool_hint(phase: WorkflowPhase) -> String {
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
        phase.word(),
        phase.position(),
        WorkflowPhase::ORDER.len()
    )
}

/// Compact journey chip for the idle status footer — ambient orientation on
/// every view, not just home.
pub fn journey_footer_segment(app: &ShellApp) -> Option<String> {
    let journey = journey_model(app)?;
    Some(journey_phase_segment(journey.current))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress(map: bool, total: usize, reviewed: usize, confirmed: usize) -> JourneyProgress {
        JourneyProgress {
            map_artifacts_built: map,
            finding_total: total,
            reviewed_findings: reviewed,
            confirmed_findings: confirmed,
        }
    }

    #[test]
    fn fresh_workspace_is_in_map() {
        assert_eq!(progress(false, 0, 0, 0).current_phase(), WorkflowPhase::Map);
    }

    #[test]
    fn artifacts_without_findings_is_hunt() {
        assert_eq!(progress(true, 0, 0, 0).current_phase(), WorkflowPhase::Hunt);
    }

    #[test]
    fn unreviewed_findings_is_confirm() {
        assert_eq!(
            progress(true, 5, 2, 1).current_phase(),
            WorkflowPhase::Confirm
        );
        assert_eq!(progress(true, 5, 2, 1).unreviewed_findings(), 3);
    }

    #[test]
    fn fully_reviewed_findings_is_fix() {
        assert_eq!(progress(true, 5, 5, 3).current_phase(), WorkflowPhase::Fix);
    }

    #[test]
    fn needs_review_triage_does_not_count_as_reviewed() {
        use kuzushi_core::{Severity, TriageOutcome};

        let mut finding = Finding::new_tool(
            "demo",
            "demo.rule",
            "src/lib.rs",
            7,
            None,
            Severity::Medium,
            "needs human review",
        );
        finding.triage = Some(TriageOutcome {
            verdict: TriageVerdict::NeedsReview,
            confidence: 0.4,
            rationale: "unclear".to_string(),
            cost_usd: 0.0,
        });

        let progress = journey_progress_from_parts(true, &[finding]);

        assert_eq!(progress.reviewed_findings, 0);
        assert_eq!(progress.confirmed_findings, 0);
        assert_eq!(progress.current_phase(), WorkflowPhase::Confirm);
    }

    #[test]
    fn dismissed_findings_are_reviewed_but_not_confirmed() {
        use kuzushi_core::{Severity, TriageOutcome};

        let mut finding = Finding::new_tool(
            "demo",
            "demo.rule",
            "src/lib.rs",
            7,
            None,
            Severity::Medium,
            "dismissed finding",
        );
        finding.triage = Some(TriageOutcome {
            verdict: TriageVerdict::FalsePositive,
            confidence: 0.92,
            rationale: "guarded".to_string(),
            cost_usd: 0.0,
        });

        let progress = journey_progress_from_parts(true, &[finding]);

        assert_eq!(progress.reviewed_findings, 1);
        assert_eq!(progress.confirmed_findings, 0);
        assert_eq!(progress.current_phase(), WorkflowPhase::Fix);
    }

    #[test]
    fn findings_outrank_missing_map_artifacts() {
        // An imported-findings workspace (e.g. bounty HAR intake) skipped
        // map entirely; the journey must not strand it there.
        assert_eq!(
            progress(false, 3, 0, 0).current_phase(),
            WorkflowPhase::Confirm
        );
    }

    #[test]
    fn phase_statuses_mark_done_current_pending() {
        let statuses = phase_statuses(
            WorkflowPhase::Confirm,
            WorkflowPhase::Confirm,
            &BTreeSet::new(),
            &BTreeSet::new(),
        );
        assert_eq!(statuses[0].state, JourneyPhaseState::Done);
        assert_eq!(statuses[1].state, JourneyPhaseState::Done);
        assert_eq!(statuses[2].state, JourneyPhaseState::Current);
        assert_eq!(statuses[3].state, JourneyPhaseState::Pending);
    }

    #[test]
    fn walker_ahead_of_progress_does_not_forge_done_marks() {
        let statuses = phase_statuses(
            WorkflowPhase::Confirm,
            WorkflowPhase::Map,
            &BTreeSet::new(),
            &BTreeSet::new(),
        );
        assert_eq!(statuses[0].state, JourneyPhaseState::Pending);
        assert_eq!(statuses[1].state, JourneyPhaseState::Pending);
        assert_eq!(statuses[2].state, JourneyPhaseState::Current);
    }

    #[test]
    fn skipped_and_failed_phases_have_distinct_states() {
        let skipped = BTreeSet::from([WorkflowPhase::Map]);
        let failed = BTreeSet::from([WorkflowPhase::Hunt]);
        let statuses = phase_statuses(
            WorkflowPhase::Confirm,
            WorkflowPhase::Map,
            &skipped,
            &failed,
        );
        assert_eq!(statuses[0].state, JourneyPhaseState::Skipped);
        assert_eq!(statuses[1].state, JourneyPhaseState::Failed);
        assert_eq!(statuses[2].state, JourneyPhaseState::Current);
    }

    #[test]
    fn next_action_counts_unreviewed_findings() {
        let action = phase_next_action(WorkflowPhase::Confirm, progress(true, 4, 1, 1));
        assert!(action.contains("3 of 4 findings need review"));
        assert!(!action.contains("Type 'next'"));

        let summary = phase_next_summary(WorkflowPhase::Confirm, progress(true, 4, 1, 1));
        assert!(summary.contains("作 confirm · 3 findings need review"));
        assert!(summary.contains("next to continue"));
    }

    #[test]
    fn next_action_names_concrete_phase_tools() {
        let hunt = phase_tool_hint(WorkflowPhase::Hunt);
        assert!(hunt.contains("secret-scan:scan"));
        assert!(hunt.contains("taint-iris-next:hunt"));

        let confirm = phase_tool_hint(WorkflowPhase::Confirm);
        assert!(confirm.contains("triage:run"));
        assert!(confirm.contains("verify:finding"));
    }
}
