//! The persistent engagement spine: where the operator is in the
//! 組 map → 崩 hunt → 作 confirm → 掛 fix journey, derived from workspace
//! reality (artifacts on disk, findings, triage/verification state) rather
//! than from the launch walker's transient state. The walker finishing
//! doesn't end the journey — the workspace always *is* somewhere.

use std::path::Path;

use crate::app::{PlanningTaskId, WorkflowPhase};
use crate::ShellApp;
use kuzushi_core::Finding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JourneyModel {
    /// One entry per phase in canonical order, each marked done/current/pending.
    pub phases: Vec<JourneyPhaseStatus>,
    pub current: WorkflowPhase,
    /// The home view's `▸ NEXT` line: one concrete action for the current
    /// phase. Text after ` — ` renders muted (see `next_action_line`).
    pub next_action: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JourneyPhaseStatus {
    pub phase: WorkflowPhase,
    pub state: JourneyPhaseState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JourneyPhaseState {
    Done,
    Current,
    Pending,
}

impl JourneyPhaseState {
    pub fn glyph(self) -> &'static str {
        match self {
            JourneyPhaseState::Done => "✓",
            JourneyPhaseState::Current => "●",
            JourneyPhaseState::Pending => "○",
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
    /// Findings with a triage outcome or an empirical verification.
    pub confirmed_findings: usize,
}

impl JourneyProgress {
    /// First phase whose exit criterion isn't met. Findings outrank map
    /// artifacts: an imported-findings workspace (bounty HAR intake) is
    /// already confirming even though map was skipped. Fix is terminal — a
    /// fully confirmed workspace sits in fix until patches/reports ship.
    pub fn current_phase(self) -> WorkflowPhase {
        if self.finding_total > 0 {
            return if self.confirmed_findings < self.finding_total {
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

    pub fn unconfirmed_findings(self) -> usize {
        self.finding_total.saturating_sub(self.confirmed_findings)
    }
}

/// Derive the journey for the active workspace. `None` without a target —
/// there is no engagement to walk. A live walker phase takes precedence so
/// the rail tracks the picker the operator is actually inside.
pub fn journey_model(app: &ShellApp) -> Option<JourneyModel> {
    let target = app.target.as_deref()?;
    let progress = journey_progress(target, &app.findings);
    let current = app
        .workflow_phase
        .unwrap_or_else(|| progress.current_phase());
    Some(JourneyModel {
        phases: phase_statuses(current),
        current,
        next_action: phase_next_action(current, progress),
    })
}

pub fn journey_progress(target: &Path, findings: &[Finding]) -> JourneyProgress {
    JourneyProgress {
        map_artifacts_built: any_map_artifact_exists(target),
        finding_total: findings.len(),
        confirmed_findings: findings.iter().filter(|f| is_confirmed(f)).count(),
    }
}

fn is_confirmed(finding: &Finding) -> bool {
    finding.triage.is_some() || finding.verification.is_some()
}

fn any_map_artifact_exists(target: &Path) -> bool {
    PlanningTaskId::in_phase(WorkflowPhase::Map)
        .into_iter()
        .filter_map(PlanningTaskId::artifact_relative_path)
        .any(|relative| target.join(relative).exists())
}

fn phase_statuses(current: WorkflowPhase) -> Vec<JourneyPhaseStatus> {
    WorkflowPhase::ORDER
        .iter()
        .map(|&phase| JourneyPhaseStatus {
            phase,
            state: phase_state(phase, current),
        })
        .collect()
}

fn phase_state(phase: WorkflowPhase, current: WorkflowPhase) -> JourneyPhaseState {
    if phase == current {
        JourneyPhaseState::Current
    } else if phase < current {
        JourneyPhaseState::Done
    } else {
        JourneyPhaseState::Pending
    }
}

fn phase_next_action(current: WorkflowPhase, progress: JourneyProgress) -> String {
    match current {
        WorkflowPhase::Map => {
            "Run next to establish the grip — build context & analysis artifacts (組 map, 1 of 4)."
                .to_string()
        }
        WorkflowPhase::Hunt => {
            "Run next to hunt for vulnerabilities — map artifacts ready (崩 hunt, 2 of 4)."
                .to_string()
        }
        WorkflowPhase::Confirm => format!(
            "Run next to triage & verify — {} of {} findings unconfirmed (作 confirm, 3 of 4).",
            progress.unconfirmed_findings(),
            progress.finding_total
        ),
        WorkflowPhase::Fix => format!(
            "Run next to patch & report — {} findings confirmed (掛 fix, 4 of 4).",
            progress.confirmed_findings
        ),
    }
}

/// Compact `phase:hunt 2/4` chip for the idle status footer — ambient
/// orientation on every view, not just home.
pub fn journey_footer_segment(app: &ShellApp) -> Option<String> {
    let journey = journey_model(app)?;
    Some(format!(
        "phase:{} {}/{}",
        journey.current.word(),
        journey.current.position(),
        WorkflowPhase::ORDER.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress(map: bool, total: usize, confirmed: usize) -> JourneyProgress {
        JourneyProgress {
            map_artifacts_built: map,
            finding_total: total,
            confirmed_findings: confirmed,
        }
    }

    #[test]
    fn fresh_workspace_is_in_map() {
        assert_eq!(progress(false, 0, 0).current_phase(), WorkflowPhase::Map);
    }

    #[test]
    fn artifacts_without_findings_is_hunt() {
        assert_eq!(progress(true, 0, 0).current_phase(), WorkflowPhase::Hunt);
    }

    #[test]
    fn unconfirmed_findings_is_confirm() {
        assert_eq!(progress(true, 5, 2).current_phase(), WorkflowPhase::Confirm);
        assert_eq!(progress(true, 5, 2).unconfirmed_findings(), 3);
    }

    #[test]
    fn fully_confirmed_findings_is_fix() {
        assert_eq!(progress(true, 5, 5).current_phase(), WorkflowPhase::Fix);
    }

    #[test]
    fn findings_outrank_missing_map_artifacts() {
        // An imported-findings workspace (e.g. bounty HAR intake) skipped
        // map entirely; the journey must not strand it there.
        assert_eq!(
            progress(false, 3, 0).current_phase(),
            WorkflowPhase::Confirm
        );
    }

    #[test]
    fn phase_statuses_mark_done_current_pending() {
        let statuses = phase_statuses(WorkflowPhase::Confirm);
        assert_eq!(statuses[0].state, JourneyPhaseState::Done);
        assert_eq!(statuses[1].state, JourneyPhaseState::Done);
        assert_eq!(statuses[2].state, JourneyPhaseState::Current);
        assert_eq!(statuses[3].state, JourneyPhaseState::Pending);
    }

    #[test]
    fn next_action_counts_unconfirmed_findings() {
        let action = phase_next_action(WorkflowPhase::Confirm, progress(true, 4, 1));
        assert!(action.contains("3 of 4 findings unconfirmed"));
    }
}
