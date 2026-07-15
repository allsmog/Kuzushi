use crossterm::event::KeyCode;
use kuzushi_core::workflow_attempts::{
    PhaseAttemptCompleted, PhaseAttemptOutcome, PhaseResultAction,
};
use kuzushi_core::WorkflowPhase;

use super::{RunFocusReceipt, RunSummaryEntriesState, ShellApp, ViewDataState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhaseResultPolicy {
    pub(crate) actions: Vec<PhaseResultAction>,
    pub(crate) recommended_next: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhaseResultCommand {
    Select,
    Continue,
    Open,
    Refine,
    RunAgain,
    Regenerate,
    Discard,
}

impl PhaseResultCommand {
    pub(crate) const fn from_action(action: PhaseResultAction) -> Self {
        match action {
            PhaseResultAction::Select => Self::Select,
            PhaseResultAction::SelectAndContinue | PhaseResultAction::SelectAndReport => {
                Self::Continue
            }
            PhaseResultAction::Open => Self::Open,
            PhaseResultAction::Refine => Self::Refine,
            PhaseResultAction::RunAgain => Self::RunAgain,
            PhaseResultAction::Regenerate => Self::Regenerate,
            PhaseResultAction::Discard => Self::Discard,
        }
    }

    pub(crate) const fn action_id(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Continue => "continue",
            Self::Open => "open",
            Self::Refine => "refine",
            Self::RunAgain => "run_again",
            Self::Regenerate => "regenerate",
            Self::Discard => "discard",
        }
    }

    pub(crate) const fn default_hint(self) -> &'static str {
        match self {
            Self::Select => "u",
            Self::Continue => "n",
            Self::Open => "o",
            Self::Refine => "f",
            Self::RunAgain => "r",
            Self::Regenerate => "g",
            Self::Discard => "d",
        }
    }

    pub(crate) fn from_default_key(code: KeyCode) -> Option<Self> {
        match code {
            KeyCode::Char('u') => Some(Self::Select),
            KeyCode::Char('n') => Some(Self::Continue),
            KeyCode::Char('o') => Some(Self::Open),
            KeyCode::Char('f') => Some(Self::Refine),
            KeyCode::Char('r') => Some(Self::RunAgain),
            KeyCode::Char('g') => Some(Self::Regenerate),
            KeyCode::Char('d') => Some(Self::Discard),
            _ => None,
        }
    }

    pub(crate) fn matches(self, action: PhaseResultAction) -> bool {
        self == Self::from_action(action)
    }
}

pub(crate) fn phase_result_policy(
    phase: Option<WorkflowPhase>,
    outcome: PhaseAttemptOutcome,
    routes_to_report: bool,
) -> PhaseResultPolicy {
    use PhaseAttemptOutcome::{Canceled, Failed};
    use PhaseResultAction::{Discard, Open, RunAgain};

    if matches!(outcome, Failed | Canceled) {
        return PhaseResultPolicy {
            actions: vec![Open, RunAgain, Discard],
            recommended_next: Some(failed_result_recommendation(outcome).to_string()),
        };
    }
    let Some(phase) = phase else {
        return PhaseResultPolicy {
            actions: vec![Open, RunAgain],
            recommended_next: None,
        };
    };
    PhaseResultPolicy {
        actions: successful_result_actions(phase, routes_to_report),
        recommended_next: Some(successful_result_recommendation(phase, routes_to_report).into()),
    }
}

pub(crate) fn phase_attempt_outcome_from_label(value: &str) -> PhaseAttemptOutcome {
    match value.trim().to_ascii_lowercase().as_str() {
        "completed" | "complete" | "success" => PhaseAttemptOutcome::Completed,
        "partial" => PhaseAttemptOutcome::Partial,
        "canceled" | "cancelled" => PhaseAttemptOutcome::Canceled,
        _ => PhaseAttemptOutcome::Failed,
    }
}

#[cfg(test)]
pub(crate) fn completed_attempt_actions(
    completed: &PhaseAttemptCompleted,
) -> Vec<PhaseResultAction> {
    completed.receipt.as_ref().map_or_else(
        || phase_result_policy(Some(completed.phase), completed.outcome, false).actions,
        |receipt| receipt.actions.clone(),
    )
}

impl ShellApp {
    pub(crate) fn projected_phase_result_policy(
        &self,
        phase: WorkflowPhase,
    ) -> Option<PhaseResultPolicy> {
        let record = self.engagement.unresolved_phase_attempt(phase)?;
        if let Some(reason) = record.completed.selection_blocked_reason.as_deref() {
            return Some(selection_blocked_result_policy(reason));
        }
        if self.verified_remediation_result_is_open(phase) {
            return Some(verified_remediation_result_policy());
        }
        let live = self.matching_live_result_receipt(&record.completed.attempt_id);
        Some(receipt_result_policy(&record.completed, live))
    }

    pub(crate) fn verified_remediation_result_is_open(&self, phase: WorkflowPhase) -> bool {
        self.engagement
            .unresolved_phase_attempt(phase)
            .is_some_and(|record| {
                self.verified_remediation_run_refs(
                    phase,
                    record.completed.outcome,
                    &record.completed.run_refs,
                )
            })
    }

    pub(crate) fn terminal_phase_result_policy(
        &self,
        phase: WorkflowPhase,
        outcome: PhaseAttemptOutcome,
        routes_to_report: bool,
        run_refs: &[String],
    ) -> PhaseResultPolicy {
        if self.verified_remediation_run_refs(phase, outcome, run_refs) {
            return verified_remediation_result_policy();
        }
        phase_result_policy(Some(phase), outcome, routes_to_report)
    }

    fn verified_remediation_run_refs(
        &self,
        phase: WorkflowPhase,
        outcome: PhaseAttemptOutcome,
        run_refs: &[String],
    ) -> bool {
        if phase != WorkflowPhase::Fix || outcome != PhaseAttemptOutcome::Completed {
            return false;
        }
        self.domain()
            .matching_verified_reverify_run(run_refs)
            .is_some_and(|run_id| self.cached_run_is_reverify_or_unavailable(run_id))
    }

    fn cached_run_is_reverify_or_unavailable(&self, run_id: &str) -> bool {
        let state = self
            .workbench_cache()
            .borrow()
            .cached_run_summary_entries(self.target());
        let ViewDataState::Ready(RunSummaryEntriesState::Ready(entries)) = state else {
            return true;
        };
        entries
            .iter()
            .find(|entry| entry.run_id == run_id)
            .is_none_or(|entry| match &entry.state {
                kuzushi_core::RunSummaryEntryState::Ready(summary) => {
                    summary.tool.as_deref() == Some("patch:reverify")
                }
                kuzushi_core::RunSummaryEntryState::Issue(_) => false,
            })
    }

    fn matching_live_result_receipt(&self, attempt_id: &str) -> Option<&RunFocusReceipt> {
        self.activity()
            .and_then(|session| session.run_focus_receipt.as_ref())
            .filter(|receipt| receipt.attempt_id.as_deref() == Some(attempt_id))
    }
}

fn receipt_result_policy(
    completed: &PhaseAttemptCompleted,
    live: Option<&RunFocusReceipt>,
) -> PhaseResultPolicy {
    let fallback = phase_result_policy(Some(completed.phase), completed.outcome, false);
    let actions = live
        .map(|receipt| receipt.actions.clone())
        .or_else(|| {
            completed
                .receipt
                .as_ref()
                .map(|receipt| receipt.actions.clone())
        })
        .unwrap_or(fallback.actions);
    let recommended_next = live
        .and_then(|receipt| receipt.recommended_next.clone())
        .or_else(|| {
            completed
                .receipt
                .as_ref()
                .and_then(|receipt| receipt.recommended_next.clone())
        })
        .or(fallback.recommended_next);
    PhaseResultPolicy {
        actions,
        recommended_next,
    }
}

fn selection_blocked_result_policy(reason: &str) -> PhaseResultPolicy {
    use PhaseResultAction::{Discard, Open, RunAgain};
    PhaseResultPolicy {
        actions: vec![Open, RunAgain, Discard],
        recommended_next: Some(reason.to_string()),
    }
}

fn verified_remediation_result_policy() -> PhaseResultPolicy {
    use PhaseResultAction::{Discard, Open, RunAgain, Select};
    PhaseResultPolicy {
        actions: vec![Select, Open, RunAgain, Discard],
        recommended_next: Some(
            "re-verification passed; acknowledge this verified remediation".to_string(),
        ),
    }
}

pub(crate) fn ordered_phase_result_actions(
    phase: WorkflowPhase,
    outcome: PhaseAttemptOutcome,
    actions: &[PhaseResultAction],
) -> Vec<PhaseResultAction> {
    let preferred = preferred_phase_result_action(phase, outcome, actions);
    let mut ordered = actions.to_vec();
    if let Some(index) = preferred.and_then(|action| ordered.iter().position(|row| *row == action))
    {
        ordered.swap(0, index);
    }
    ordered
}

fn preferred_phase_result_action(
    phase: WorkflowPhase,
    outcome: PhaseAttemptOutcome,
    actions: &[PhaseResultAction],
) -> Option<PhaseResultAction> {
    use PhaseAttemptOutcome::{Canceled, Failed, Partial};
    use PhaseResultAction::{Open, Select, SelectAndContinue, SelectAndReport};

    if matches!(outcome, Failed | Canceled) {
        return actions.contains(&Open).then_some(Open);
    }
    if outcome == Partial || phase == WorkflowPhase::Fix {
        return actions.contains(&Select).then_some(Select);
    }
    [SelectAndContinue, SelectAndReport, Select]
        .into_iter()
        .find(|action| actions.contains(action))
}

fn successful_result_actions(
    phase: WorkflowPhase,
    routes_to_report: bool,
) -> Vec<PhaseResultAction> {
    use PhaseResultAction::{Discard, Open, Refine, Regenerate, RunAgain, Select};

    let mut actions = vec![Select];
    if phase != WorkflowPhase::Fix {
        actions.push(continuation_action(routes_to_report));
    }
    actions.extend([Open, Refine]);
    match phase {
        WorkflowPhase::Map | WorkflowPhase::Scan => actions.push(RunAgain),
        WorkflowPhase::Review | WorkflowPhase::Prove | WorkflowPhase::Fix => {
            actions.push(Regenerate)
        }
    }
    if phase != WorkflowPhase::Prove {
        actions.push(Discard);
    }
    actions
}

fn continuation_action(routes_to_report: bool) -> PhaseResultAction {
    if routes_to_report {
        PhaseResultAction::SelectAndReport
    } else {
        PhaseResultAction::SelectAndContinue
    }
}

fn failed_result_recommendation(outcome: PhaseAttemptOutcome) -> &'static str {
    match outcome {
        PhaseAttemptOutcome::Canceled => "open the canceled run or run it again",
        _ => "open the failed run, adjust its input, or run it again",
    }
}

fn successful_result_recommendation(phase: WorkflowPhase, routes_to_report: bool) -> &'static str {
    match (phase, routes_to_report) {
        (WorkflowPhase::Map, _) => "select this Map, then open Scan",
        (WorkflowPhase::Scan, false) => "select this Scan, then open Review",
        (WorkflowPhase::Scan, true) => "select this clean Scan, then open Report",
        (WorkflowPhase::Review, false) => "commit decisions, then open Prove",
        (WorkflowPhase::Review, true) => "commit decisions, then open Report",
        (WorkflowPhase::Prove, false) => "select this proof set, then open Fix",
        (WorkflowPhase::Prove, true) => "select this proof set, then open Report",
        (WorkflowPhase::Fix, _) => "review the candidate; Apply remains separately authorized",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified_lifecycle(run_id: &str) -> kuzushi_core::PatchLifecycleRecord {
        kuzushi_core::PatchLifecycleRecord {
            application_id: "application-1".to_string(),
            stable_fp: "stable-finding".to_string(),
            fingerprint: "finding-1".to_string(),
            finding_scan_id: Some("scan-1".to_string()),
            patch_run_id: "patch-run".to_string(),
            target: "/target".to_string(),
            diff_hash: "diff-hash".to_string(),
            base_commit: None,
            touched_files: Vec::new(),
            state: kuzushi_core::PatchLifecycleState::Verified,
            reverify_run_id: Some(run_id.to_string()),
            detail: Some("re-verification passed".to_string()),
            actor: "operator".to_string(),
            application_started_at: "1".to_string(),
            applied_at: Some("2".to_string()),
            updated_at: "3".to_string(),
        }
    }

    #[test]
    fn successful_policies_have_one_truthful_continuation() {
        for phase in WorkflowPhase::ORDER {
            for report in [false, true] {
                let policy =
                    phase_result_policy(Some(*phase), PhaseAttemptOutcome::Completed, report);
                let continuations = policy
                    .actions
                    .iter()
                    .filter(|action| PhaseResultCommand::Continue.matches(**action))
                    .count();
                assert_eq!(continuations, usize::from(*phase != WorkflowPhase::Fix));
            }
        }
    }

    #[test]
    fn failed_and_canceled_attempts_offer_only_recovery_actions() {
        for outcome in [PhaseAttemptOutcome::Failed, PhaseAttemptOutcome::Canceled] {
            let policy = phase_result_policy(Some(WorkflowPhase::Prove), outcome, false);
            assert_eq!(
                policy.actions,
                vec![
                    PhaseResultAction::Open,
                    PhaseResultAction::RunAgain,
                    PhaseResultAction::Discard,
                ]
            );
        }
    }

    #[test]
    fn terminal_receipt_uses_verified_policy_only_for_the_matching_reverify_run() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.domain_mut()
            .set_patch_lifecycle_records(&[verified_lifecycle("reverify-run")]);

        let verified = app.terminal_phase_result_policy(
            WorkflowPhase::Fix,
            PhaseAttemptOutcome::Completed,
            false,
            &["reverify-run".to_string()],
        );
        let unrelated = app.terminal_phase_result_policy(
            WorkflowPhase::Fix,
            PhaseAttemptOutcome::Completed,
            false,
            &["patch-run".to_string()],
        );

        assert_eq!(
            verified.recommended_next.as_deref(),
            Some("re-verification passed; acknowledge this verified remediation")
        );
        assert!(verified.actions.contains(&PhaseResultAction::RunAgain));
        assert!(unrelated.actions.contains(&PhaseResultAction::Refine));
        assert!(!unrelated.actions.contains(&PhaseResultAction::RunAgain));
    }

    #[test]
    fn commands_are_the_only_default_key_mapping() {
        for command in [
            PhaseResultCommand::Select,
            PhaseResultCommand::Continue,
            PhaseResultCommand::Open,
            PhaseResultCommand::Refine,
            PhaseResultCommand::RunAgain,
            PhaseResultCommand::Regenerate,
            PhaseResultCommand::Discard,
        ] {
            let key = KeyCode::Char(command.default_hint().chars().next().unwrap());
            assert_eq!(PhaseResultCommand::from_default_key(key), Some(command));
        }
    }

    #[test]
    fn attention_order_puts_the_recommended_decision_first() {
        let successful = successful_result_actions(WorkflowPhase::Map, false);
        assert_eq!(
            ordered_phase_result_actions(
                WorkflowPhase::Map,
                PhaseAttemptOutcome::Completed,
                &successful,
            )[0],
            PhaseResultAction::SelectAndContinue
        );

        let partial = ordered_phase_result_actions(
            WorkflowPhase::Scan,
            PhaseAttemptOutcome::Partial,
            &successful_result_actions(WorkflowPhase::Scan, false),
        );
        assert_eq!(partial[0], PhaseResultAction::Select);

        let failed =
            phase_result_policy(Some(WorkflowPhase::Map), PhaseAttemptOutcome::Failed, false);
        assert_eq!(
            ordered_phase_result_actions(
                WorkflowPhase::Map,
                PhaseAttemptOutcome::Failed,
                &failed.actions,
            )[0],
            PhaseResultAction::Open
        );
    }
}
