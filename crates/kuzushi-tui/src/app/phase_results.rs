use crossterm::event::KeyCode;
use kuzushi_core::workflow_attempts::{
    PhaseAttemptCompleted, PhaseAttemptOutcome, PhaseResultAction,
};
use kuzushi_core::WorkflowPhase;

use super::{RunFocusReceipt, RunSummaryEntriesState, ShellApp, ViewDataState};

#[cfg(test)]
thread_local! {
    static PHASE_RESULT_PRESENTATION_CALLS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
pub(crate) fn take_phase_result_presentation_calls() -> usize {
    PHASE_RESULT_PRESENTATION_CALLS.with(|calls| calls.replace(0))
}

#[cfg(test)]
fn record_phase_result_presentation_call() {
    PHASE_RESULT_PRESENTATION_CALLS.with(|calls| calls.set(calls.get() + 1));
}

mod continuation;
#[path = "phase_results/finding_delta_label.rs"]
mod finding_delta_label;
#[path = "phase_results/typed_receipt.rs"]
mod typed_receipt;
use finding_delta_label::{attributed_findings_label, finding_delta_label};
use typed_receipt::TypedReceiptResolution;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhaseResultPolicy {
    pub(crate) actions: Vec<PhaseResultAction>,
    pub(crate) recommended_next: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhaseResultPresentation {
    pub(crate) attempt_id: String,
    pub(crate) outcome: String,
    pub(crate) emphasis: PhaseResultEmphasis,
    pub(crate) compact_summary: PhaseResultCompactSummary,
    pub(crate) detail_lines: Vec<String>,
    pub(crate) detail_rows: Vec<PhaseResultDetailRow>,
    pub(crate) semantic_keys: std::collections::BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
    pub(crate) actions: Vec<PhaseResultAction>,
    pub(crate) recommended_next: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhaseResultEmphasis {
    CompactDisposition,
    DominantDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhaseResultCompactSummary {
    pub(crate) phase: WorkflowPhase,
    pub(crate) outcome: PhaseAttemptOutcome,
    pub(crate) run_count: usize,
    pub(crate) artifact_count: usize,
    pub(crate) changed_findings: u64,
    /// See `PhaseAttemptReceipt::finding_delta_observed`.
    pub(crate) finding_delta_observed: Option<bool>,
    /// Distinct findings the loaded ledger attributes to this attempt's runs,
    /// set when the ledger backs the claim. Scan keeps recorded changes separate
    /// from this distinct count. `changed_findings` is the recorded total, which
    /// the ledger's same-issue fold can exceed, so the label states this count
    /// instead of a total the rest of the frame contradicts.
    pub(crate) attributed_findings: Option<u64>,
    pub(crate) cost: Option<String>,
    pub(crate) revision_recorded: bool,
    pub(crate) receipt_recorded: bool,
}

impl PhaseResultCompactSummary {
    /// `findings +N`, or `findings unmeasured` when no typed finding delta
    /// backs the count. A ledger-measured count reads as `findings N distinct`
    /// instead, because it is not a delta.
    pub(crate) fn findings_label(&self) -> String {
        if let Some(distinct) = self.attributed_findings {
            return attributed_findings_label(distinct);
        }
        if self.phase == WorkflowPhase::Scan && self.finding_delta_observed == Some(true) {
            return format!("finding changes {}", self.changed_findings);
        }
        finding_delta_label(
            &format!("+{}", self.changed_findings),
            self.changed_findings,
            self.finding_delta_observed,
        )
    }

    /// The card's findings segment, or `None` for a Map attempt that touched
    /// no findings: Map tools never persist findings, so "unmeasured" there
    /// would suggest an unknown where the phase makes no finding claim.
    pub(crate) fn findings_segment(&self) -> Option<String> {
        let unmeasured_map = self.phase == WorkflowPhase::Map
            && self.changed_findings == 0
            && self.attributed_findings.is_none()
            && self.finding_delta_observed != Some(true);
        (!unmeasured_map).then(|| self.findings_label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhaseResultDetailRow {
    pub(crate) key: Option<kuzushi_core::run_lifecycle::RunCellKey>,
    pub(crate) disclosed_keys: std::collections::BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
    pub(crate) text: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PhaseRerunReview {
    pub(crate) phase: WorkflowPhase,
    pub(crate) parent_attempt_id: String,
    pub(crate) tool: String,
    pub(crate) tool_description: String,
    pub(crate) original_input: serde_json::Value,
    pub(crate) prepared_input: serde_json::Value,
    pub(crate) changed_options: Vec<PhaseRerunOptionReview>,
    pub(crate) option_editor_open: bool,
    pub(crate) option_cursor: usize,
    pub(crate) option_edit: Option<PhaseRerunOptionEdit>,
    pub(crate) option_error: Option<String>,
    /// Why the last Enter refused to launch this draft. The review stays open
    /// on a refusal, so the reason has to survive on the card the operator is
    /// still looking at, not only in the transcript.
    pub(crate) dispatch_error: Option<String>,
    pub(crate) draft_modified: bool,
    pub(crate) derivation: Option<kuzushi_core::workflow_attempts::PhaseAttemptDerivation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhaseRerunOptionEdit {
    pub(crate) option_name: String,
    pub(crate) draft: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhaseRerunOptionReview {
    pub(crate) label: String,
    pub(crate) value: String,
    pub(crate) description: String,
}

impl PhaseResultDetailRow {
    fn unkeyed(text: impl Into<String>) -> Self {
        Self {
            key: None,
            disclosed_keys: std::collections::BTreeSet::new(),
            text: text.into(),
        }
    }

    fn disclosure(
        text: impl Into<String>,
        disclosed_keys: std::collections::BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
    ) -> Self {
        Self {
            key: None,
            disclosed_keys,
            text: text.into(),
        }
    }

    fn accounted_keys(&self) -> impl Iterator<Item = &kuzushi_core::run_lifecycle::RunCellKey> {
        self.key.iter().chain(self.disclosed_keys.iter())
    }
}

#[derive(Debug, Default)]
struct PhaseResultDetails {
    rows: Vec<PhaseResultDetailRow>,
}

#[derive(Debug)]
struct TypedRunResultDetails {
    is_problem: bool,
    rows: Vec<PhaseResultDetailRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhaseResultCommand {
    Select,
    Continue,
    ContinueRun,
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
            PhaseResultAction::ContinueRun => Self::ContinueRun,
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
            Self::ContinueRun => "continue_run",
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
            Self::ContinueRun => "c",
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
            KeyCode::Char('c') => Some(Self::ContinueRun),
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
    use PhaseAttemptOutcome::{Blocked, Canceled, Failed};
    use PhaseResultAction::{Discard, Open, RunAgain};

    if matches!(
        (phase, outcome),
        (Some(WorkflowPhase::Prove), PhaseAttemptOutcome::Partial)
    ) {
        return selection_blocked_result_policy(
            "inspect the inconclusive assessment and missing evidence before retrying",
        );
    }
    if matches!(outcome, Blocked | Failed | Canceled) {
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
        "completed" | "complete" | "success" | "skipped" => PhaseAttemptOutcome::Completed,
        "partial" | "pending" | "running" => PhaseAttemptOutcome::Partial,
        "blocked" | "refused" => PhaseAttemptOutcome::Blocked,
        "canceled" | "cancelled" => PhaseAttemptOutcome::Canceled,
        _ => PhaseAttemptOutcome::Failed,
    }
}

pub(crate) fn phase_attempt_outcome_from_run_status(
    status: kuzushi_core::run_lifecycle::RunItemStatus,
) -> PhaseAttemptOutcome {
    phase_attempt_outcome_from_label(status.label())
}

fn receipt_outcome_state(
    state: ViewDataState<Result<Option<PhaseAttemptOutcome>, String>>,
    fallback: PhaseAttemptOutcome,
) -> ViewDataState<PhaseAttemptOutcome> {
    match state {
        ViewDataState::Ready(Ok(Some(outcome))) => ViewDataState::Ready(outcome),
        ViewDataState::Ready(Ok(None) | Err(_)) => ViewDataState::Ready(fallback),
        ViewDataState::Loading => ViewDataState::Loading,
        ViewDataState::NotRequested => ViewDataState::NotRequested,
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
    pub(crate) fn phase_result_presentation(
        &self,
        phase: WorkflowPhase,
    ) -> Option<PhaseResultPresentation> {
        let record = self.engagement.unresolved_phase_attempt(phase)?;
        Some(self.phase_result_presentation_for(&record.completed))
    }

    pub(crate) fn phase_result_presentation_for(
        &self,
        completed: &PhaseAttemptCompleted,
    ) -> PhaseResultPresentation {
        #[cfg(test)]
        record_phase_result_presentation_call();
        let typed_receipt = TypedReceiptResolution::resolve(completed);
        let policy = self.phase_result_policy_with_receipt(completed, &typed_receipt);
        let live = self.matching_live_result_receipt(&completed.attempt_id);
        let effective_outcome = typed_receipt.outcome();
        let outcome = format!("{effective_outcome:?}").to_ascii_lowercase();
        let actions =
            ordered_phase_result_actions(completed.phase, effective_outcome, &policy.actions);
        let emphasis = phase_result_emphasis(completed.phase, effective_outcome, &actions);
        let compact_summary = self.phase_result_compact_summary(completed, effective_outcome);
        let recommended_next = policy
            .recommended_next
            .unwrap_or_else(|| "open the result and choose a disposition".to_string());
        let rows = self.phase_result_detail_rows(
            completed,
            effective_outcome,
            &typed_receipt,
            live,
            &recommended_next,
        );
        let detail_lines = rows.iter().map(|row| row.text.clone()).collect();
        let semantic_keys = rows
            .iter()
            .flat_map(PhaseResultDetailRow::accounted_keys)
            .cloned()
            .collect();
        PhaseResultPresentation {
            attempt_id: completed.attempt_id.clone(),
            emphasis,
            compact_summary,
            detail_lines,
            detail_rows: rows,
            semantic_keys,
            outcome,
            actions,
            recommended_next,
        }
    }

    /// The compact summary, with the ledger consulted for the one count the
    /// receipt could not measure itself.
    ///
    /// Recorded Scan changes and distinct findings remain separate. Other phases
    /// keep their typed deltas. Without a typed delta,
    /// `changed_findings` is what the attempt's runs reported emitting — a
    /// total, not a delta — which is the number the banner used to print as
    /// `findings +27` over a panel that said 25. The ledger measures the same
    /// runs under the same attribution rule the Scan page uses, so when it
    /// backs a claim both surfaces name the same findings. The runs' own
    /// reported total is deliberately not carried here; see
    /// `attributed_findings_label`.
    fn phase_result_compact_summary(
        &self,
        completed: &PhaseAttemptCompleted,
        outcome: PhaseAttemptOutcome,
    ) -> PhaseResultCompactSummary {
        let mut summary = phase_result_compact_summary(completed, outcome);
        if summary.finding_delta_observed.is_none() || completed.phase == WorkflowPhase::Scan {
            summary.attributed_findings = self
                .phase_result_finding_runs(completed)
                .and_then(|runs| self.attributed_findings(&runs))
                .map(|ledger| ledger.distinct);
        }
        summary
    }

    fn phase_result_finding_runs(&self, completed: &PhaseAttemptCompleted) -> Option<Vec<String>> {
        if completed.phase != WorkflowPhase::Scan {
            return Some(completed.run_refs.clone());
        }
        let target = self.target()?;
        let mut runs = completed.run_refs.clone();
        for parent in &completed.run_refs {
            match self
                .workbench_cache()
                .borrow()
                .cached_scan_stage_receipt(target, parent)
            {
                crate::ViewDataState::Ready(crate::ScanStageReceiptState::Ready(receipt)) => {
                    runs.extend(receipt.run_refs)
                }
                crate::ViewDataState::Ready(crate::ScanStageReceiptState::Missing) => {}
                _ => return None,
            }
        }
        Some(runs)
    }

    fn phase_result_detail_rows(
        &self,
        completed: &PhaseAttemptCompleted,
        effective_outcome: PhaseAttemptOutcome,
        typed_receipt: &TypedReceiptResolution,
        live: Option<&RunFocusReceipt>,
        recommended_next: &str,
    ) -> Vec<PhaseResultDetailRow> {
        let mut details = phase_result_details(
            completed,
            effective_outcome,
            typed_receipt,
            live,
            recommended_next,
        );
        if let Some(row) = self.resume_checkpoint_row(completed, effective_outcome) {
            details.rows.push(row);
        }
        details.rows
    }

    /// Disclose a matching staged checkpoint on failed/canceled results.
    fn resume_checkpoint_row(
        &self,
        completed: &PhaseAttemptCompleted,
        outcome: PhaseAttemptOutcome,
    ) -> Option<PhaseResultDetailRow> {
        if !matches!(
            outcome,
            PhaseAttemptOutcome::Failed | PhaseAttemptOutcome::Canceled
        ) {
            return None;
        }
        self.stage_checkpoint_row(completed)
    }

    fn stage_checkpoint_row(
        &self,
        completed: &PhaseAttemptCompleted,
    ) -> Option<PhaseResultDetailRow> {
        let target = std::path::Path::new(&completed.target_snapshot.target);
        let coordinates = completed.run_refs.iter().rev().find_map(|run_id| {
            kuzushi_core::run_artifacts::matching_checkpoint_coordinates_for_run(target, run_id)
        })?;
        let resume = coordinates
            .resume_from
            .as_deref()
            .map(|stage| format!(" · resumes at {stage}"))
            .unwrap_or_default();
        Some(PhaseResultDetailRow::unkeyed(format!(
            "⟲ {} completed stage(s) checkpointed [{}]{resume} — c continue from the failure point",
            coordinates.completed_stages.len(),
            coordinates.completed_stages.join(", "),
        )))
    }

    pub(crate) fn projected_phase_result_policy(
        &self,
        phase: WorkflowPhase,
    ) -> Option<PhaseResultPolicy> {
        let record = self.engagement.unresolved_phase_attempt(phase)?;
        Some(self.phase_result_policy_for(&record.completed))
    }

    pub(crate) fn phase_result_control_state(
        &self,
        phase: WorkflowPhase,
    ) -> Option<(PhaseAttemptOutcome, PhaseResultPolicy)> {
        let completed = &self.engagement.unresolved_phase_attempt(phase)?.completed;
        let receipt = TypedReceiptResolution::resolve(completed);
        Some((
            receipt.outcome(),
            self.phase_result_policy_with_receipt(completed, &receipt),
        ))
    }

    fn phase_result_policy_for(&self, completed: &PhaseAttemptCompleted) -> PhaseResultPolicy {
        let receipt = TypedReceiptResolution::resolve(completed);
        self.phase_result_policy_with_receipt(completed, &receipt)
    }

    fn phase_result_policy_with_receipt(
        &self,
        completed: &PhaseAttemptCompleted,
        receipt: &TypedReceiptResolution,
    ) -> PhaseResultPolicy {
        let mut policy = if let Some(reason) = self.effective_phase_attempt_blocker(completed) {
            selection_blocked_result_policy(&reason)
        } else {
            receipt.authoritative_policy()
        };
        if let Some(reason) = self.phase_recovery_prerequisite_blocker(completed.phase) {
            return prerequisite_blocked_result_policy(&reason);
        }
        offer_threat_model_rerun_actions(completed, &mut policy);
        self.offer_continue_run(completed, &mut policy);
        self.refine_phase_result_continuation(completed.phase, &mut policy);
        policy
    }

    pub(crate) fn phase_recovery_prerequisite_blocker(
        &self,
        phase: WorkflowPhase,
    ) -> Option<String> {
        let snapshot = self.engagement.phase_target_snapshot()?;
        self.phase_recovery_prerequisite_blocker_for_snapshot(phase, snapshot)
    }

    pub(crate) fn phase_recovery_prerequisite_blocker_for_snapshot(
        &self,
        phase: WorkflowPhase,
        snapshot: &kuzushi_core::workflow_attempts::PhaseTargetSnapshot,
    ) -> Option<String> {
        let stale = WorkflowPhase::ORDER
            .iter()
            .copied()
            .take_while(|candidate| *candidate != phase)
            .find(|candidate| {
                self.engagement
                    .stale_selected_phase_attempt_for_snapshot(*candidate, snapshot)
                    .is_some()
            })?;
        Some(format!(
            "rerun {} because the accepted {} is stale, then retry {}",
            stale.title(),
            stale.title(),
            phase.title()
        ))
    }

    /// A failed/canceled attempt whose run left resumable checkpoint state
    /// gains the ContinueRun action: re-dispatching the identical recorded
    /// input resumes at the failure point instead of restarting. Never read
    /// from persisted receipts — checkpoint state changes after they are
    /// written, so it is derived live every time.
    fn offer_continue_run(
        &self,
        completed: &PhaseAttemptCompleted,
        policy: &mut PhaseResultPolicy,
    ) {
        if !matches!(
            completed.outcome,
            PhaseAttemptOutcome::Failed | PhaseAttemptOutcome::Canceled
        ) || policy.actions.contains(&PhaseResultAction::ContinueRun)
        {
            return;
        }
        if self.continuable_failed_run(completed).is_none() {
            return;
        }
        policy.actions.insert(0, PhaseResultAction::ContinueRun);
    }

    /// A checkpoint is eligible only when it names this failed run and its
    /// fingerprint matches that run's durable ToolCallRequested operation.
    pub(crate) fn continuable_failed_run(
        &self,
        completed: &PhaseAttemptCompleted,
    ) -> Option<String> {
        let target = std::path::Path::new(&completed.target_snapshot.target);
        completed
            .run_refs
            .iter()
            .rev()
            .find(|run_id| {
                kuzushi_core::run_artifacts::matching_checkpoint_coordinates_for_run(target, run_id)
                    .is_some()
            })
            .cloned()
    }

    pub(crate) fn effective_phase_attempt_outcome(
        &self,
        completed: &PhaseAttemptCompleted,
    ) -> PhaseAttemptOutcome {
        if self.effective_phase_attempt_blocker(completed).is_some() {
            return PhaseAttemptOutcome::Partial;
        }
        completed.outcome
    }

    pub(crate) fn cached_authoritative_phase_attempt_outcome(
        &self,
        completed: &PhaseAttemptCompleted,
    ) -> ViewDataState<PhaseAttemptOutcome> {
        let fallback = self.effective_phase_attempt_outcome(completed);
        let Some(target) = self.target() else {
            return ViewDataState::Ready(fallback);
        };
        if target != std::path::Path::new(&completed.target_snapshot.target) {
            return ViewDataState::Ready(fallback);
        }
        let state = self
            .workbench_cache()
            .borrow()
            .cached_phase_receipt_outcome(target, &completed.attempt_id);
        receipt_outcome_state(state, fallback)
    }

    pub(crate) fn effective_phase_attempt_blocker(
        &self,
        completed: &PhaseAttemptCompleted,
    ) -> Option<String> {
        // Blocked/failed/canceled attempts are already terminal and unselectable;
        // demoting them to "partial evidence" would misstate the outcome
        // exactly when the operator needs the honest one.
        if matches!(
            completed.outcome,
            PhaseAttemptOutcome::Blocked
                | PhaseAttemptOutcome::Failed
                | PhaseAttemptOutcome::Canceled
        ) {
            return None;
        }
        if self.engagement.phase_attempt_projection_is_degraded() {
            return Some(
                "phase result ledger is degraded; repair it before selecting this result"
                    .to_string(),
            );
        }
        completed
            .selection_blocked_reason
            .clone()
            .or_else(|| self.phase_attempt_identity_blocker(completed))
    }

    fn phase_attempt_identity_blocker(&self, completed: &PhaseAttemptCompleted) -> Option<String> {
        self.engagement.phase_attempt_content_is_blocked(&completed.attempt_id).then(|| {
            format!("Run {} again: its recorded source identity is unavailable or no longer current.", completed.phase.title())
        })
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

fn phase_result_details(
    completed: &PhaseAttemptCompleted,
    outcome: PhaseAttemptOutcome,
    typed_receipt: &TypedReceiptResolution,
    live: Option<&RunFocusReceipt>,
    recommended_next: &str,
) -> PhaseResultDetails {
    let outcome = format!("{outcome:?}").to_ascii_lowercase();
    let mut rows = typed_receipt
        .detail_lines()
        .unwrap_or_else(|| vec![legacy_result_receipt_line(completed, live, &outcome)])
        .into_iter()
        .map(PhaseResultDetailRow::unkeyed)
        .collect::<Vec<_>>();
    let mut terminal = terminal_result_details(completed, typed_receipt, live);
    rows.append(&mut terminal.rows);
    rows.push(PhaseResultDetailRow::unkeyed(target_lineage_line(
        &completed.target_snapshot,
    )));
    rows.push(PhaseResultDetailRow::unkeyed(format!(
        "next: {recommended_next}"
    )));
    PhaseResultDetails { rows }
}

fn phase_result_emphasis(
    phase: WorkflowPhase,
    outcome: PhaseAttemptOutcome,
    actions: &[PhaseResultAction],
) -> PhaseResultEmphasis {
    // Keep the pending Prove assessment prominent while its disposition is unresolved.
    if phase == WorkflowPhase::Prove {
        return PhaseResultEmphasis::DominantDecision;
    }
    let selectable = actions.iter().any(|action| {
        matches!(
            action,
            PhaseResultAction::Select
                | PhaseResultAction::SelectAndContinue
                | PhaseResultAction::SelectAndReport
        )
    });
    if outcome == PhaseAttemptOutcome::Completed && selectable {
        PhaseResultEmphasis::CompactDisposition
    } else {
        PhaseResultEmphasis::DominantDecision
    }
}

fn phase_result_compact_summary(
    completed: &PhaseAttemptCompleted,
    outcome: PhaseAttemptOutcome,
) -> PhaseResultCompactSummary {
    let receipt = completed.receipt.as_ref();
    PhaseResultCompactSummary {
        phase: completed.phase,
        outcome,
        run_count: receipt.map_or(completed.run_refs.len(), |receipt| receipt.run_count),
        artifact_count: receipt.map_or(0, |receipt| receipt.changed_artifacts.len()),
        changed_findings: receipt.map_or(0, |receipt| receipt.changed_findings),
        finding_delta_observed: receipt.and_then(|receipt| receipt.finding_delta_observed),
        attributed_findings: None,
        cost: receipt.map(|receipt| receipt.cost.clone()),
        revision_recorded: completed.target_snapshot.revision.is_some(),
        receipt_recorded: receipt.is_some(),
    }
}

/// Lineage row: the target identity this attempt was recorded against. The
/// degraded form is explicit ("rev unrecorded"), never omitted.
fn target_lineage_line(snapshot: &kuzushi_core::workflow_attempts::PhaseTargetSnapshot) -> String {
    match snapshot.revision.as_deref() {
        Some(sha) => format!(
            "lineage: target rev:{}{}",
            sha.chars().take(7).collect::<String>(),
            if snapshot.dirty { "*" } else { "" }
        ),
        None => "target revision was not recorded for this attempt".to_string(),
    }
}

fn legacy_result_receipt_line(
    completed: &PhaseAttemptCompleted,
    live: Option<&RunFocusReceipt>,
    outcome: &str,
) -> String {
    if let Some(receipt) = live {
        // The card is the cost surface here (unlike Run Focus, whose header
        // owns cost) — summary() dropped it, so append it explicitly.
        return format!(
            "{} · {} · {} finding delta · {} artifact delta · {} interaction(s)",
            receipt.summary(),
            receipt.cost,
            receipt.changed_findings,
            receipt.changed_artifacts.len(),
            receipt.interaction_count
        );
    }
    let Some(receipt) = completed.receipt.as_ref() else {
        return format!(
            "{} canonical run reference(s) · legacy receipt metadata unavailable",
            completed.run_refs.len()
        );
    };
    let cost = durable_receipt_cost_label(&receipt.cost);
    format!(
        "{outcome} · {} run{} · {}s · {cost} · {} · {} artifact delta · {} interaction(s)",
        receipt.run_count,
        if receipt.run_count == 1 { "" } else { "s" },
        receipt.elapsed_secs,
        finding_delta_label(
            &format!("+{}", receipt.changed_findings),
            receipt.changed_findings,
            receipt.finding_delta_observed,
        ),
        receipt.changed_artifacts.len(),
        receipt.interaction_count
    )
}

fn durable_receipt_cost_label(cost: &str) -> String {
    // Old persisted receipts carry "unavailable"/"invalid"; new ones carry
    // "not recorded"/"accounting error". Both generations get the prefix.
    let qualified = [
        "incomplete",
        "unavailable",
        "invalid",
        "not recorded",
        "accounting",
    ]
    .iter()
    .any(|marker| cost.contains(marker));
    if qualified {
        return format!("Cost: {cost}");
    }
    cost.to_string()
}

fn terminal_result_details(
    completed: &PhaseAttemptCompleted,
    _typed_receipt: &TypedReceiptResolution,
    live: Option<&RunFocusReceipt>,
) -> PhaseResultDetails {
    let _ = live;
    if let Some(typed) = typed_durable_result_details(completed) {
        return typed;
    }
    legacy_phase_result_details(vec![
        "run details unavailable — open the failed run for details".to_string(),
    ])
}

fn legacy_phase_result_details(lines: Vec<String>) -> PhaseResultDetails {
    PhaseResultDetails {
        rows: lines
            .into_iter()
            .map(PhaseResultDetailRow::unkeyed)
            .collect(),
    }
}

fn typed_durable_result_details(completed: &PhaseAttemptCompleted) -> Option<PhaseResultDetails> {
    let target = std::path::Path::new(&completed.target_snapshot.target);
    let runs = completed
        .run_refs
        .iter()
        .filter_map(|run_id| typed_run_result_details(target, run_id))
        .collect::<Vec<_>>();
    select_typed_run_result(runs)
}

fn select_typed_run_result(runs: Vec<TypedRunResultDetails>) -> Option<PhaseResultDetails> {
    let selected = runs
        .iter()
        .find(|run| run.is_problem)
        .or_else(|| runs.last())?;
    Some(PhaseResultDetails {
        rows: selected.rows.clone(),
    })
}

fn typed_run_result_details(
    target: &std::path::Path,
    run_id: &str,
) -> Option<TypedRunResultDetails> {
    use kuzushi_core::run_lifecycle::{ProjectionHealth, RunItemStatus, RunProjectionSource};
    let read = kuzushi_core::run_lifecycle::load_run_projection(target, run_id).ok()?;
    if read.source != RunProjectionSource::TypedV1 {
        return None;
    }
    let presentation = kuzushi_core::run_lifecycle::present_run(&read);
    if read.projection.health != ProjectionHealth::Healthy {
        let detail =
            format!("run {run_id} · semantic replay degraded — inspect the valid item prefix");
        let mut rows = vec![PhaseResultDetailRow::unkeyed(detail)];
        rows.extend(phase_card_run_rows(&presentation, true));
        return Some(TypedRunResultDetails {
            is_problem: true,
            rows,
        });
    }
    let terminal = read.projection.terminal.as_ref()?;
    let rows = phase_card_run_rows(&presentation, false);
    let is_problem = matches!(
        terminal.status,
        RunItemStatus::Blocked
            | RunItemStatus::Failed
            | RunItemStatus::Partial
            | RunItemStatus::Canceled
            | RunItemStatus::Interrupted
    );
    Some(TypedRunResultDetails { is_problem, rows })
}

/// The result card is an operator decision surface, not a run debugger:
/// keep the terminal outcome, hydrated result summaries (error + artifacts
/// by label), finding deltas, and operator questions/decisions. The work
/// ledger (plan/task/call rows), artifact digests, duplicate receipt rows,
/// and nominal stream-health lines stay behind one Replay disclosure.
/// replay/trace own that depth. `include_overview` re-admits the run-id and
/// stream-health lines when the projection itself is degraded.
fn phase_card_run_rows(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    include_overview: bool,
) -> Vec<PhaseResultDetailRow> {
    let mut rows = Vec::new();
    if include_overview {
        rows.extend(
            presentation
                .overview_lines()
                .into_iter()
                .map(PhaseResultDetailRow::unkeyed),
        );
    }
    let mut folded_keys = std::collections::BTreeSet::new();
    let has_result_row = phase_card_has_result_row(presentation);
    for section in &presentation.summary {
        for cell in &section.cells {
            let lines = phase_card_cell_lines(&section.kind, cell, has_result_row);
            if lines.is_empty() {
                folded_keys.insert(cell.key.clone());
                continue;
            }
            rows.extend(lines.into_iter().map(|text| PhaseResultDetailRow {
                key: Some(cell.key.clone()),
                disclosed_keys: std::collections::BTreeSet::new(),
                text,
            }));
        }
    }
    append_replay_disclosure(&mut rows, folded_keys, &presentation.timeline);
    rows
}

fn append_replay_disclosure(
    rows: &mut Vec<PhaseResultDetailRow>,
    mut folded_keys: std::collections::BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
    timeline: &[kuzushi_core::run_lifecycle::RunPresentationCellV1],
) {
    let records = folded_keys.len();
    folded_keys.extend(timeline.iter().map(|cell| cell.key.clone()));
    if folded_keys.is_empty() {
        return;
    }
    rows.push(PhaseResultDetailRow::disclosure(
        format!(
            "More in Replay · {records} run records · {} timeline entries",
            timeline.len()
        ),
        folded_keys,
    ));
}

/// The Terminal cell restates what the card already shows elsewhere: its
/// Cost line repeats the receipt header row and its run-level NEXT competes
/// with the card's phase-level `next:` footer, so only the leading Outcome
/// line survives — and even that folds away when a shown `Result ·` row
/// already carries the same tool summary.
fn phase_card_cell_lines(
    kind: &kuzushi_core::run_lifecycle::RunPresentationSectionKindV1,
    cell: &kuzushi_core::run_lifecycle::RunPresentationCellV1,
    has_result_row: bool,
) -> Vec<String> {
    use kuzushi_core::run_lifecycle::RunPresentationPayloadV1 as Payload;
    if !phase_card_shows_cell(kind, cell) {
        return Vec::new();
    }
    match &cell.payload {
        Payload::Terminal(_) if has_result_row => Vec::new(),
        Payload::Terminal(_) => cell.display_lines().into_iter().take(1).collect(),
        _ => cell.display_lines(),
    }
}

fn phase_card_has_result_row(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) -> bool {
    use kuzushi_core::run_lifecycle::RunPresentationPayloadV1 as Payload;
    presentation.summary.iter().any(|section| {
        section.cells.iter().any(|cell| {
            matches!(cell.payload, Payload::ResultSummary(_))
                && phase_card_shows_cell(&section.kind, cell)
        })
    })
}

fn phase_card_shows_cell(
    kind: &kuzushi_core::run_lifecycle::RunPresentationSectionKindV1,
    cell: &kuzushi_core::run_lifecycle::RunPresentationCellV1,
) -> bool {
    use kuzushi_core::run_lifecycle::RunPresentationPayloadV1 as Payload;
    use kuzushi_core::run_lifecycle::RunPresentationSectionKindV1 as Kind;
    match kind {
        Kind::Attention => true,
        Kind::Outcome => !matches!(cell.payload, Payload::PhaseReceipt(_)),
        Kind::Evidence => !matches!(cell.payload, Payload::Artifact(_)),
        Kind::Work => failed_model_call_cell(cell),
    }
}

fn failed_model_call_cell(cell: &kuzushi_core::run_lifecycle::RunPresentationCellV1) -> bool {
    use kuzushi_core::run_lifecycle::{RunItemStatus, RunPresentationPayloadV1 as Payload};
    let Payload::ModelCall(call) = &cell.payload else {
        return false;
    };
    matches!(
        call.status,
        RunItemStatus::Failed | RunItemStatus::Interrupted | RunItemStatus::Canceled
    )
}

fn selection_blocked_result_policy(reason: &str) -> PhaseResultPolicy {
    use PhaseResultAction::{Discard, Open, RunAgain};
    PhaseResultPolicy {
        actions: vec![Open, RunAgain, Discard],
        recommended_next: Some(reason.to_string()),
    }
}

fn prerequisite_blocked_result_policy(reason: &str) -> PhaseResultPolicy {
    use PhaseResultAction::{Discard, Open};
    PhaseResultPolicy {
        actions: vec![Open, Discard],
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
    use PhaseAttemptOutcome::{Blocked, Canceled, Failed, Partial};
    use PhaseResultAction::{Open, Select, SelectAndContinue, SelectAndReport};

    if matches!(outcome, Blocked | Failed | Canceled) {
        return [PhaseResultAction::ContinueRun, Open]
            .into_iter()
            .find(|action| actions.contains(action));
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

fn offer_threat_model_rerun_actions(
    completed: &PhaseAttemptCompleted,
    policy: &mut PhaseResultPolicy,
) {
    use PhaseResultAction::{Refine, Regenerate};
    if completed.phase != WorkflowPhase::Map
        || completed.outcome != PhaseAttemptOutcome::Completed
        || !phase_attempt_used_tool(completed, "threat-model:build")
    {
        return;
    }
    for action in [Refine, Regenerate] {
        if !policy.actions.contains(&action) {
            policy.actions.push(action);
        }
    }
}

fn phase_attempt_used_tool(completed: &PhaseAttemptCompleted, expected: &str) -> bool {
    let target = std::path::Path::new(&completed.target_snapshot.target);
    completed.run_refs.iter().rev().any(|run_id| {
        kuzushi_core::load_run_summary(target, run_id)
            .ok()
            .and_then(|summary| summary.tool)
            .is_some_and(|tool| tool == expected)
    })
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
        PhaseAttemptOutcome::Blocked => {
            "open the blocked run, address the stated requirement, then run it again"
        }
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

    /// Loaded ledger rows cannot supply discovery membership without the
    /// authenticated Scan stage receipt. Keep the reported count separate.
    #[test]
    fn the_banner_cannot_attribute_scan_findings_without_stage_evidence() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
        app.set_findings(ledger_observed_by("scan-run", 3));

        let completed = attempt_with_outcome(target.path(), PhaseAttemptOutcome::Completed)
            .with_receipt(run_reported_receipt(5));

        let summary = app
            .phase_result_presentation_for(&completed)
            .compact_summary;

        assert_eq!(summary.attributed_findings, None);
        assert_eq!(summary.findings_label(), "findings +5");
        assert!(!summary.findings_label().contains("observation"));
    }

    /// A typed finding delta is the durable measurement; the ledger must not
    /// be allowed to restate it, least of all as a non-delta count.
    #[test]
    fn a_typed_finding_delta_is_never_restated_from_the_ledger() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
        app.set_findings(ledger_observed_by("scan-run", 3));

        let mut receipt = run_reported_receipt(5);
        receipt.finding_delta_observed = Some(true);
        let completed = attempt_with_outcome(target.path(), PhaseAttemptOutcome::Completed)
            .with_receipt(receipt);

        let summary = app
            .phase_result_presentation_for(&completed)
            .compact_summary;

        assert_eq!(summary.attributed_findings, None);
        assert_eq!(summary.findings_label(), "finding changes 5");
    }

    /// A filtered projection holds only the rows the operator asked to see, so
    /// its count is a floor. The recorded count has to stand as it did before.
    #[test]
    fn a_filtered_ledger_never_moves_what_an_attempt_found() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
        app.set_findings(ledger_observed_by("scan-run", 3));
        app.set_active_findings_filter(Some("severity:high".to_string()));

        let completed = attempt_with_outcome(target.path(), PhaseAttemptOutcome::Completed)
            .with_receipt(run_reported_receipt(5));

        let summary = app
            .phase_result_presentation_for(&completed)
            .compact_summary;

        assert_eq!(summary.attributed_findings, None);
        assert_eq!(summary.findings_label(), "findings +5");
    }

    /// `changed_findings` without a typed delta is what the runs reported
    /// emitting, which `receipt_run_changes` reads off each run summary.
    fn run_reported_receipt(reported: u64) -> kuzushi_core::workflow_attempts::PhaseAttemptReceipt {
        kuzushi_core::workflow_attempts::PhaseAttemptReceipt {
            run_count: 1,
            elapsed_secs: 2,
            cost: "$0.0000".to_string(),
            changed_findings: reported,
            finding_delta_observed: None,
            changed_artifacts: Vec::new(),
            interaction_count: 0,
            rerun_specification: None,
            actions: vec![PhaseResultAction::Select],
            recommended_next: None,
        }
    }

    fn ledger_observed_by(run_id: &str, count: usize) -> Vec<kuzushi_core::Finding> {
        (0..count)
            .map(|index| {
                let mut finding = kuzushi_core::Finding::new_semgrep(
                    &format!("demo.rule.{index}"),
                    "src/app.rs",
                    index as u32 + 1,
                    None,
                    kuzushi_core::Severity::High,
                    "ledger finding",
                );
                finding.scan_id = Some(run_id.to_string());
                finding
            })
            .collect()
    }

    fn durable_partial_attempt(target: &std::path::Path) -> PhaseAttemptCompleted {
        PhaseAttemptCompleted::new(
            WorkflowPhase::Scan,
            vec!["scan-partial".to_string()],
            kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target),
            PhaseAttemptOutcome::Partial,
        )
        .with_receipt(durable_partial_receipt())
    }

    fn durable_partial_receipt() -> kuzushi_core::workflow_attempts::PhaseAttemptReceipt {
        use kuzushi_core::workflow_attempts::PhaseAttemptReceipt;
        PhaseAttemptReceipt {
            run_count: 1,
            elapsed_secs: 2,
            cost: ">=$0.0000 (incomplete)".to_string(),
            changed_findings: 0,
            finding_delta_observed: None,
            changed_artifacts: vec!["result.json".to_string()],
            interaction_count: 0,
            rerun_specification: None,
            actions: vec![PhaseResultAction::Open, PhaseResultAction::RunAgain],
            recommended_next: Some("choose a target with analyzable evidence".to_string()),
        }
    }

    fn record_partial_threat_model_result(target: &std::path::Path) {
        let record = kuzushi_core::run_artifacts::ToolRunRecord::new(
            target,
            "scan-partial",
            "tool",
            "threat-model:build",
        );
        kuzushi_core::run_artifacts::record_tool_run_started(record, &serde_json::json!({}));
        kuzushi_core::run_artifacts::record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "partial",
                "summary": "previous model preserved",
                "output": "Threats: 0\nSaved: previous model preserved",
                "warnings": [],
                "errors": [],
                "artifacts": [{
                    "label": "normalized-threat-model.json",
                    "path": "normalized-threat-model.json",
                    "kind": "json"
                }]
            }),
        );
    }

    fn write_pending_loop_checkpoint(target: &std::path::Path) {
        let dir = target.join(".kuzushi").join("v3").join("checkpoints");
        std::fs::create_dir_all(&dir).unwrap();
        let entry = kuzushi_core::runtime::LoopHistoryEntry::AssistantToolCall(
            kuzushi_core::runtime::ToolCall {
                name: "read_source".to_string(),
                input: serde_json::json!({}),
                call_id: "call-1".to_string(),
            },
        );
        let file = serde_json::json!({
            "version": 1,
            "fingerprint": "abcd",
            "transcript": [entry],
        });
        std::fs::write(dir.join("agent-loop-abcd.json"), file.to_string()).unwrap();
    }

    fn attempt_with_outcome(
        target: &std::path::Path,
        outcome: PhaseAttemptOutcome,
    ) -> PhaseAttemptCompleted {
        PhaseAttemptCompleted::new(
            WorkflowPhase::Scan,
            vec!["scan-run".to_string()],
            kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target),
            outcome,
        )
    }

    fn write_stage_checkpoint(target: &std::path::Path, run_id: &str) {
        std::fs::create_dir_all(target.join(".kuzushi")).unwrap();
        write_requested_operation(target, run_id, [5u8; 32]);
        std::fs::write(target.join("research.json"), "{}").unwrap();
        let store = kuzushi_core::run_artifacts::StageCheckpointStore::discover(target, &[5u8; 32])
            .unwrap();
        let handle = kuzushi_core::run_artifacts::StageCheckpointHandle::open(
            store,
            target,
            run_id,
            "threat-model:build",
        );
        handle
            .stage("research")
            .complete(vec!["research.json".to_string()]);
        handle.mark_current("gapfill");
    }

    fn write_requested_operation(target: &std::path::Path, run_id: &str, digest: [u8; 32]) {
        use kuzushi_core::run_lifecycle::*;
        let writer = RunItemWriter::open(target, run_id, None).unwrap();
        let item = RunItemV1::ToolCallRequested {
            tool_name: SafeText::operator_visible("threat-model:build"),
            operation_fingerprint: OperationFingerprint::from_digest(digest),
            safe_option_names: Vec::new(),
        };
        writer
            .emit_and_flush(
                RunItemRecord::new(RunItemId::new(), RunItemSource::Dispatch, item)
                    .with_call(RunCallId::new()),
            )
            .unwrap();
    }

    #[test]
    fn partial_prove_never_offers_selection_or_continuation() {
        let policy = phase_result_policy(
            Some(WorkflowPhase::Prove),
            PhaseAttemptOutcome::Partial,
            false,
        );
        assert_eq!(
            policy.actions,
            vec![
                PhaseResultAction::Open,
                PhaseResultAction::RunAgain,
                PhaseResultAction::Discard
            ]
        );
    }

    #[test]
    fn failed_attempt_with_stage_checkpoint_offers_continue_first() {
        let temp = tempfile::tempdir().unwrap();
        write_stage_checkpoint(temp.path(), "scan-run");
        let mut app = super::super::ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));

        let failed = app.phase_result_presentation_for(&attempt_with_outcome(
            temp.path(),
            PhaseAttemptOutcome::Failed,
        ));

        assert_eq!(
            failed.actions.first(),
            Some(&PhaseResultAction::ContinueRun),
            "{:?}",
            failed.actions
        );
        assert!(
            failed.detail_lines.iter().any(|line| {
                line.contains("1 completed stage(s) checkpointed [research]")
                    && line.contains("resumes at gapfill")
                    && line.contains("c continue")
            }),
            "{:?}",
            failed.detail_lines
        );
    }

    #[test]
    fn completed_attempt_never_offers_continue_run() {
        let temp = tempfile::tempdir().unwrap();
        write_stage_checkpoint(temp.path(), "scan-run");
        let mut app = super::super::ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));

        let completed = app.phase_result_presentation_for(&attempt_with_outcome(
            temp.path(),
            PhaseAttemptOutcome::Completed,
        ));

        assert!(!completed.actions.contains(&PhaseResultAction::ContinueRun));
    }

    #[test]
    fn only_selectable_completed_results_use_compact_disposition() {
        let target = tempfile::tempdir().unwrap();
        assert_eq!(
            phase_result_emphasis(
                WorkflowPhase::Scan,
                PhaseAttemptOutcome::Completed,
                &[PhaseResultAction::Select]
            ),
            PhaseResultEmphasis::CompactDisposition
        );
        let summary = phase_result_compact_summary(
            &attempt_with_outcome(target.path(), PhaseAttemptOutcome::Completed),
            PhaseAttemptOutcome::Completed,
        );
        assert_eq!(summary.phase, WorkflowPhase::Scan);
        assert_eq!(summary.run_count, 1);

        for outcome in [
            PhaseAttemptOutcome::Partial,
            PhaseAttemptOutcome::Blocked,
            PhaseAttemptOutcome::Failed,
            PhaseAttemptOutcome::Canceled,
        ] {
            assert_eq!(
                phase_result_emphasis(WorkflowPhase::Scan, outcome, &[PhaseResultAction::Select]),
                PhaseResultEmphasis::DominantDecision,
                "outcome={outcome:?}"
            );
        }
    }

    #[test]
    fn selectable_prove_result_keeps_the_new_assessment_expanded() {
        assert_eq!(
            phase_result_emphasis(
                WorkflowPhase::Prove,
                PhaseAttemptOutcome::Completed,
                &[
                    PhaseResultAction::Select,
                    PhaseResultAction::SelectAndContinue
                ],
            ),
            PhaseResultEmphasis::DominantDecision,
        );
    }

    #[test]
    fn selection_blocked_completion_remains_a_dominant_decision() {
        let target = tempfile::tempdir().unwrap();
        let mut app = super::super::ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(target.path().to_path_buf()));
        let completed = attempt_with_outcome(target.path(), PhaseAttemptOutcome::Completed)
            .with_selection_blocked("map evidence is stale".to_string());

        let result = app.phase_result_presentation_for(&completed);

        assert_eq!(result.emphasis, PhaseResultEmphasis::DominantDecision);
        assert!(!result.actions.iter().any(|action| matches!(
            action,
            PhaseResultAction::Select
                | PhaseResultAction::SelectAndContinue
                | PhaseResultAction::SelectAndReport
        )));
    }

    #[test]
    fn unrelated_loop_checkpoint_does_not_make_a_failed_result_continuable() {
        let temp = tempfile::tempdir().unwrap();
        write_pending_loop_checkpoint(temp.path());
        let mut app = super::super::ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));

        let failed = app.phase_result_presentation_for(&attempt_with_outcome(
            temp.path(),
            PhaseAttemptOutcome::Failed,
        ));
        assert!(!failed.actions.contains(&PhaseResultAction::ContinueRun));
        assert!(!failed
            .detail_lines
            .iter()
            .any(|line| line.contains("resume checkpoint")));

        // A successful result never advertises resume.
        let completed = app.phase_result_presentation_for(&attempt_with_outcome(
            temp.path(),
            PhaseAttemptOutcome::Completed,
        ));
        assert!(!completed
            .detail_lines
            .iter()
            .any(|line| line.contains("resume checkpoint")));
    }

    fn assert_contains_detail(presentation: &PhaseResultPresentation, expected: &str) {
        assert!(
            presentation
                .detail_lines
                .iter()
                .any(|line| line.contains(expected)),
            "missing phase-result detail: {expected}; lines={:?}",
            presentation.detail_lines
        );
    }

    #[test]
    fn typed_phase_result_accounts_only_for_the_selected_run() {
        use kuzushi_core::run_lifecycle::{RunCellKey, RunCellRoleV1, RunCellSourceV1, RunItemId};
        let completed_key = RunCellKey {
            source: RunCellSourceV1::Item(RunItemId::new()),
            role: RunCellRoleV1::TerminalOutcome,
            ordinal: 0,
        };
        let failed_key = RunCellKey {
            source: RunCellSourceV1::Item(RunItemId::new()),
            role: RunCellRoleV1::TerminalOutcome,
            ordinal: 0,
        };
        let runs = vec![
            typed_result_fixture(false, "completed run", completed_key.clone()),
            typed_result_fixture(true, "failed run", failed_key.clone()),
        ];

        let selected = select_typed_run_result(runs).expect("selected typed result");
        let accounted = selected
            .rows
            .iter()
            .flat_map(PhaseResultDetailRow::accounted_keys)
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(accounted, std::collections::BTreeSet::from([failed_key]));
        assert!(!accounted.contains(&completed_key));
        assert_eq!(selected.rows[0].text, "failed run");
    }

    #[test]
    fn typed_phase_result_prioritizes_blocked_over_later_completed_run() {
        let target = tempfile::tempdir().unwrap();
        let blocked_run = "typed-phase-blocked";
        let completed_run = "typed-phase-completed";
        write_typed_terminal_run_with_status(
            target.path(),
            blocked_run,
            kuzushi_core::run_lifecycle::RunItemStatus::Blocked,
        );
        write_typed_terminal_run_with_status(
            target.path(),
            completed_run,
            kuzushi_core::run_lifecycle::RunItemStatus::Completed,
        );
        let runs = vec![
            typed_run_result_details(target.path(), blocked_run).unwrap(),
            typed_run_result_details(target.path(), completed_run).unwrap(),
        ];

        let selected = select_typed_run_result(runs).expect("selected typed result");
        let detail = selected
            .rows
            .iter()
            .map(|row| row.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(detail.contains("blocked"), "{detail}");
        assert!(!detail.contains("scan completed"), "{detail}");
    }

    #[test]
    fn failed_result_card_names_the_exact_model_call_and_failure_metadata() {
        use kuzushi_core::run_lifecycle::*;
        let target = tempfile::tempdir().unwrap();
        let run_id = "typed-model-failure";
        let observation = terminal_run_observation(target.path(), run_id);
        let task = observation.task_handle().unwrap();
        task.update_and_flush(RunItemStatus::Running, None).unwrap();
        emit_failed_model_call(&observation);
        task.update_and_flush(RunItemStatus::Failed, None).unwrap();
        emit_phase_fixture_terminal(&observation, RunItemStatus::Failed);

        let result = typed_run_result_details(target.path(), run_id).unwrap();
        let detail = result
            .rows
            .iter()
            .map(|row| row.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            detail.contains("anthropic/anthropic:claude-test"),
            "{detail}"
        );
        assert!(detail.contains("error=sdk_client_validation"), "{detail}");
        assert!(detail.contains("stage=agentic-sast:review"), "{detail}");
        assert!(detail.contains("http=400"), "{detail}");
        assert!(
            detail.contains("detail: temperature is incompatible with adaptive thinking"),
            "{detail}"
        );
    }

    fn emit_failed_model_call(observation: &kuzushi_core::run_lifecycle::RunObservationHandle) {
        use kuzushi_core::run_lifecycle::*;
        use kuzushi_core::runtime::{RuntimeFailureClass, RuntimeFailureMetadata};
        let call_id = RunCallId::new();
        let item_id = RunItemId::new();
        let metadata = RuntimeFailureMetadata::new(
            RuntimeFailureClass::SdkClientValidation,
            Some(400),
            Some("temperature incompatible with adaptive thinking"),
        )
        .with_model_call(call_id, Some("agentic-sast:review"));
        observation
            .emit_and_flush(
                RunItemRecord::new(
                    item_id,
                    RunItemSource::Runtime,
                    RunItemV1::ModelCallStarted {
                        provider: SafeText::operator_visible("anthropic"),
                        model: SafeText::operator_visible("anthropic:claude-test"),
                        operation_fingerprint: OperationFingerprint::from_bytes(b"model request"),
                    },
                )
                .with_call(call_id),
            )
            .unwrap();
        observation
            .emit_and_flush(
                RunItemRecord::new(
                    item_id,
                    RunItemSource::Runtime,
                    failed_model_finish(metadata),
                )
                .with_call(call_id),
            )
            .unwrap();
    }

    fn failed_model_finish(
        metadata: kuzushi_core::runtime::RuntimeFailureMetadata,
    ) -> kuzushi_core::run_lifecycle::RunItemV1 {
        use kuzushi_core::run_lifecycle::*;
        RunItemV1::ModelCallFinished {
            provider: SafeText::operator_visible("anthropic"),
            model: SafeText::operator_visible("anthropic:claude-test"),
            status: RunItemStatus::Failed,
            latency_ms: 25,
            usage: ModelUsage {
                input_tokens: None,
                output_tokens: None,
            },
            cost: kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
            error_class: Some(SafeText::operator_visible(metadata.error_class.to_string())),
            failure: Some(metadata),
        }
    }

    fn typed_result_fixture(
        is_problem: bool,
        text: &str,
        key: kuzushi_core::run_lifecycle::RunCellKey,
    ) -> TypedRunResultDetails {
        TypedRunResultDetails {
            is_problem,
            rows: vec![PhaseResultDetailRow {
                key: Some(key),
                disclosed_keys: std::collections::BTreeSet::new(),
                text: text.to_string(),
            }],
        }
    }

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
            reverify_evidence: Some(crate::test_support::test_reverify_evidence_ref()),
            detail: Some("re-verification passed".to_string()),
            actor: "operator".to_string(),
            application_started_at: "1".to_string(),
            applied_at: Some("2".to_string()),
            updated_at: "3".to_string(),
        }
    }

    struct TypedPhaseFixture {
        completed: PhaseAttemptCompleted,
        receipt: kuzushi_core::run_lifecycle::PhaseReceiptProjection,
        app: ShellApp,
    }

    fn typed_phase_fixture(
        target: &std::path::Path,
        run_id: &str,
        phase: WorkflowPhase,
    ) -> TypedPhaseFixture {
        crate::test_support::record_indexed_run(
            target,
            run_id,
            "fixture:run",
            serde_json::json!({"ok": true, "status": "completed", "data": {}}),
        );
        let completed = typed_attempt_for_phase(target, run_id, phase);
        kuzushi_core::workflow_attempts::append_phase_attempt_completed_with_v2(
            target,
            completed.clone(),
        )
        .unwrap();
        let receipt = kuzushi_core::workflow_attempts::load_phase_receipt_projection_v2(
            target,
            &completed.attempt_id,
        )
        .unwrap()
        .expect("hash-linked typed receipt");
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(target.to_path_buf()));
        TypedPhaseFixture {
            completed,
            receipt,
            app,
        }
    }

    fn assert_phase_card_matches(
        app: &ShellApp,
        phase: WorkflowPhase,
        presentation: &PhaseResultPresentation,
    ) {
        let card = crate::ui_view_models::phase_cockpit_model_for_phase(app, phase)
            .header
            .result_card
            .unwrap_or_else(|| panic!("typed {} result card", phase.label()));
        assert_eq!(card.actions, presentation.actions);
        assert_eq!(card.recommended, presentation.recommended_next);
        assert_eq!(card.semantic_keys, presentation.semantic_keys);
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
    fn blocked_failed_and_canceled_attempts_offer_only_recovery_actions() {
        for outcome in [
            PhaseAttemptOutcome::Blocked,
            PhaseAttemptOutcome::Failed,
            PhaseAttemptOutcome::Canceled,
        ] {
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
    fn blocked_and_refused_labels_preserve_the_policy_outcome() {
        for label in ["blocked", "refused"] {
            assert_eq!(
                phase_attempt_outcome_from_label(label),
                PhaseAttemptOutcome::Blocked
            );
        }
    }

    #[test]
    fn untyped_map_record_does_not_invent_an_evidence_blocker() {
        let target = tempfile::tempdir().unwrap();
        let completed = PhaseAttemptCompleted::new(
            WorkflowPhase::Map,
            vec!["untyped-map-run".to_string()],
            kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target.path()),
            PhaseAttemptOutcome::Completed,
        );
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);

        assert_eq!(
            app.effective_phase_attempt_outcome(&completed),
            PhaseAttemptOutcome::Completed
        );
        assert_eq!(app.effective_phase_attempt_blocker(&completed), None);
    }

    #[test]
    fn workflow_v1_result_is_explicitly_degraded_after_the_typed_cutover() {
        let target = tempfile::tempdir().unwrap();
        record_partial_threat_model_result(target.path());
        let completed = durable_partial_attempt(target.path());
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);

        let presentation = app.phase_result_presentation_for(&completed);

        assert_eq!(presentation.outcome, "partial");
        assert_contains_detail(&presentation, "run receipt unavailable");
        assert_contains_detail(&presentation, "open the failed run");
        assert!(!presentation
            .detail_lines
            .iter()
            .any(|line| line.contains("Cost: >=$0.0000")));
    }

    #[test]
    fn typed_phase_result_uses_hash_linked_receipt_after_restart() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "typed-phase-result";
        write_typed_terminal_run(target.path(), run_id);
        let completed = contradictory_typed_attempt(target.path(), run_id);
        kuzushi_core::workflow_attempts::append_phase_attempt_completed_with_v2(
            target.path(),
            completed.clone(),
        )
        .unwrap();
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);

        let presentation = app.phase_result_presentation_for(&completed);

        assert_eq!(presentation.recommended_next, "open REVIEW");
        assert!(presentation
            .actions
            .contains(&PhaseResultAction::SelectAndContinue));
        assert!(!presentation.recommended_next.contains("wrong transient"));
        assert!(
            !presentation
                .detail_lines
                .iter()
                .any(|line| line.contains("receipt NEXT")),
            "continuation renders once via the card's next: row, not in details: {:?}",
            presentation.detail_lines
        );
    }

    #[test]
    fn typed_fix_receipt_policy_ignores_mutable_verified_remediation_cache() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "typed-fix-receipt-authority";
        let mut fixture = typed_phase_fixture(target.path(), run_id, WorkflowPhase::Fix);
        assert!(matches!(
            fixture.receipt.offered_actions.as_slice(),
            [
                kuzushi_core::run_lifecycle::WorkflowContinuation::NoFurtherAction { .. },
                kuzushi_core::run_lifecycle::WorkflowContinuation::InspectRun { .. },
                kuzushi_core::run_lifecycle::WorkflowContinuation::Retry { .. },
            ]
        ));
        let expected_next = fixture.receipt.continuation.operator_label();
        let expected_keys = typed_run_semantic_keys(target.path(), run_id);
        fixture
            .app
            .domain_mut()
            .set_patch_lifecycle_records(&[verified_lifecycle(run_id)]);
        fixture.app.refresh_phase_attempt_projection();

        let presentation = fixture
            .app
            .phase_result_presentation_for(&fixture.completed);

        assert_eq!(
            presentation.actions,
            vec![
                PhaseResultAction::Select,
                PhaseResultAction::Open,
                PhaseResultAction::RunAgain,
            ]
        );
        assert_eq!(presentation.recommended_next, expected_next);
        assert!(!presentation
            .recommended_next
            .contains("re-verification passed"));
        assert_eq!(presentation.semantic_keys, expected_keys);
        assert_phase_card_matches(&fixture.app, WorkflowPhase::Fix, &presentation);
    }

    #[test]
    fn typed_map_receipt_policy_does_not_reconstruct_legacy_evidence_guards() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "typed-map-receipt-authority";
        let mut fixture = typed_phase_fixture(target.path(), run_id, WorkflowPhase::Map);
        assert!(matches!(
            fixture.receipt.offered_actions.as_slice(),
            [
                kuzushi_core::run_lifecycle::WorkflowContinuation::OpenPhase {
                    phase: WorkflowPhase::Scan,
                },
                kuzushi_core::run_lifecycle::WorkflowContinuation::NoFurtherAction { .. },
                kuzushi_core::run_lifecycle::WorkflowContinuation::InspectRun { .. },
                kuzushi_core::run_lifecycle::WorkflowContinuation::Retry { .. },
            ]
        ));
        let expected_next = fixture.receipt.continuation.operator_label();
        let expected_keys = typed_run_semantic_keys(target.path(), run_id);
        fixture.app.refresh_phase_attempt_projection();

        let presentation = fixture
            .app
            .phase_result_presentation_for(&fixture.completed);

        assert_eq!(presentation.outcome, "completed");
        assert_eq!(
            presentation.actions,
            vec![
                PhaseResultAction::SelectAndContinue,
                PhaseResultAction::Select,
                PhaseResultAction::Open,
                PhaseResultAction::RunAgain,
            ]
        );
        assert_eq!(presentation.recommended_next, expected_next);
        assert!(!presentation.recommended_next.contains("no map evidence"));
        assert_eq!(presentation.semantic_keys, expected_keys);
        assert_phase_card_matches(&fixture.app, WorkflowPhase::Map, &presentation);
    }

    #[test]
    fn typed_phase_result_retains_all_canonical_run_cell_keys() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "typed-phase-result-keys";
        write_typed_terminal_run(target.path(), run_id);
        let completed = contradictory_typed_attempt(target.path(), run_id);
        kuzushi_core::workflow_attempts::append_phase_attempt_completed_with_v2(
            target.path(),
            completed.clone(),
        )
        .unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(target.path().to_path_buf()));
        app.refresh_phase_attempt_projection();
        let read = kuzushi_core::run_lifecycle::load_run_projection(target.path(), run_id).unwrap();
        let canonical_keys = kuzushi_core::run_lifecycle::present_run(&read).semantic_keys();

        let presentation = app.phase_result_presentation_for(&completed);

        assert_eq!(presentation.semantic_keys, canonical_keys);
        let card = crate::ui_view_models::phase_cockpit_model_for_phase(&app, WorkflowPhase::Scan)
            .header
            .result_card
            .expect("typed phase-result card");
        assert_eq!(card.semantic_keys, presentation.semantic_keys);
        assert!(
            card.detail.contains("timeline entries"),
            "phase card must explicitly disclose its bounded timeline"
        );
    }

    /// The result card is a decision surface: stream-health diagnostics and
    /// the plan/task/call work ledger stay behind the disclosure row, while
    /// the terminal outcome stays visible.
    #[test]
    fn typed_phase_result_card_folds_the_work_ledger_behind_a_disclosure() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "typed-phase-result-folded";
        let mut fixture = typed_phase_fixture(target.path(), run_id, WorkflowPhase::Map);
        fixture.app.refresh_phase_attempt_projection();

        let presentation = fixture
            .app
            .phase_result_presentation_for(&fixture.completed);

        let detail = presentation.detail_lines.join("\n");
        assert!(
            !detail.contains("Stream:") && !detail.contains("Durability:"),
            "stream-health diagnostics leaked into the card: {detail}"
        );
        assert!(
            !detail.contains("Task "),
            "work-ledger rows leaked into the card: {detail}"
        );
        assert!(
            detail.contains("Result · Fixture run (fixture:run) · completed · tool completed"),
            "terminal outcome missing from the card: {detail}"
        );
        assert!(
            !detail.contains("Cost · ") && !detail.contains("NEXT · "),
            "terminal cost/continuation rows duplicate the receipt header and \
             the card's next: footer: {detail}"
        );
        assert!(
            detail.contains("More in Replay") && detail.contains("run records"),
            "missing work-ledger disclosure: {detail}"
        );
    }

    /// The run's Terminal cell restates the receipt header (cost) and
    /// competes with the card's phase-level `next:` footer (run-level
    /// continuation); the card keeps only the Outcome line — and folds even
    /// that behind the disclosure when a shown `Result ·` row already
    /// carries the same tool summary.
    #[test]
    fn phase_card_compacts_the_terminal_cell() {
        use kuzushi_core::run_lifecycle::*;
        let cell = RunPresentationCellV1 {
            key: RunCellKey {
                source: RunCellSourceV1::Item(RunItemId::new()),
                role: RunCellRoleV1::TerminalOutcome,
                ordinal: 0,
            },
            importance: RunCellImportanceV1::Essential,
            payload: RunPresentationPayloadV1::Terminal(TerminalPresentationV1 {
                status: RunItemStatus::Completed,
                summary: SafeText::operator_visible("hunt completed 7 chunks"),
                cost: kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
                continuation: WorkflowContinuation::NoFurtherAction {
                    reason: SafeText::operator_visible("run terminal"),
                },
            }),
            disclosure: None,
        };
        let kind = RunPresentationSectionKindV1::Outcome;

        assert!(
            phase_card_cell_lines(&kind, &cell, true).is_empty(),
            "with a Result row shown the whole cell folds behind the disclosure"
        );

        let standalone = phase_card_cell_lines(&kind, &cell, false);
        assert_eq!(standalone.len(), 1, "outcome only: {standalone:?}");
        assert!(standalone[0].starts_with("Outcome · completed"));
    }

    #[test]
    fn empty_run_details_do_not_offer_an_empty_replay_disclosure() {
        let mut rows = Vec::new();
        append_replay_disclosure(&mut rows, Default::default(), &[]);
        assert!(rows.is_empty());
    }

    #[test]
    fn typed_phase_result_card_covers_every_terminal_status_without_losing_keys() {
        for status in terminal_statuses() {
            assert_terminal_status_card(status);
        }
    }

    fn assert_terminal_status_card(status: kuzushi_core::run_lifecycle::RunItemStatus) {
        let (canonical, card) = terminal_status_card_fixture(status);
        assert_eq!(
            card.semantic_keys,
            canonical.semantic_keys(),
            "{} card keys",
            status.label()
        );
        assert!(
            card.detail.contains(status.label()),
            "{} terminal truth missing from card: {}",
            status.label(),
            card.detail
        );
        let disclosure = format!("{} timeline entries", canonical.timeline.len());
        assert_eq!(card.detail.matches("More in Replay").count(), 1);
        assert!(
            card.detail.contains(&disclosure),
            "{} card did not disclose bounded timeline",
            status.label()
        );
        if status == kuzushi_core::run_lifecycle::RunItemStatus::Blocked {
            assert_eq!(card.outcome, "blocked");
            assert!(!card.actions.contains(&PhaseResultAction::Select));
            assert!(!card.actions.contains(&PhaseResultAction::SelectAndContinue));
            assert!(card.recommended.contains("address the stated requirement"));
        }
    }

    fn terminal_status_card_fixture(
        status: kuzushi_core::run_lifecycle::RunItemStatus,
    ) -> (
        kuzushi_core::run_lifecycle::RunPresentationV1,
        crate::ui_view_models::PhaseResultCardModel,
    ) {
        let target = tempfile::tempdir().unwrap();
        let run_id = format!("typed-phase-result-{}", status.label());
        write_typed_terminal_run_with_status(target.path(), &run_id, status);
        let completed = typed_attempt_for_status(target.path(), &run_id, status);
        kuzushi_core::workflow_attempts::append_phase_attempt_completed_with_v2(
            target.path(),
            completed,
        )
        .unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(target.path().to_path_buf()));
        app.refresh_phase_attempt_projection();
        let read =
            kuzushi_core::run_lifecycle::load_run_projection(target.path(), &run_id).unwrap();
        let canonical = kuzushi_core::run_lifecycle::present_run(&read);
        let card = crate::ui_view_models::phase_cockpit_model_for_phase(&app, WorkflowPhase::Scan)
            .header
            .result_card
            .unwrap_or_else(|| panic!("{} phase-result card", status.label()));
        (canonical, card)
    }

    fn write_typed_terminal_run(target: &std::path::Path, run_id: &str) {
        write_typed_terminal_run_with_status(
            target,
            run_id,
            kuzushi_core::run_lifecycle::RunItemStatus::Completed,
        );
    }

    fn write_typed_terminal_run_with_status(
        target: &std::path::Path,
        run_id: &str,
        status: kuzushi_core::run_lifecycle::RunItemStatus,
    ) {
        use kuzushi_core::run_lifecycle::*;
        let observation = terminal_run_observation(target, run_id);
        let task = observation.task_handle().unwrap();
        task.update_and_flush(RunItemStatus::Running, None).unwrap();
        emit_phase_fixture_notice(&observation);
        task.update_and_flush(status, None).unwrap();
        emit_phase_fixture_terminal(&observation, status);
    }

    fn terminal_run_observation(
        target: &std::path::Path,
        run_id: &str,
    ) -> kuzushi_core::run_lifecycle::RunObservationHandle {
        let summary = kuzushi_core::RunSummary::running(
            run_id,
            "tool",
            Some("fixture:run".to_string()),
            target.to_string_lossy(),
        );
        kuzushi_core::write_run_summary(target, &summary).unwrap();
        kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target.to_path_buf(), run_id)
            .unwrap()
            .start_root_task("Scan target")
            .unwrap()
    }

    fn emit_phase_fixture_notice(observation: &kuzushi_core::run_lifecycle::RunObservationHandle) {
        use kuzushi_core::run_lifecycle::*;
        observation
            .emit_and_flush(RunItemRecord::new(
                RunItemId::new(),
                RunItemSource::Workflow,
                RunItemV1::DiagnosticNotice {
                    level: DiagnosticLevel::Info,
                    message: SafeText::operator_visible("typed phase-result fixture"),
                },
            ))
            .unwrap();
    }

    fn emit_phase_fixture_terminal(
        observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
        status: kuzushi_core::run_lifecycle::RunItemStatus,
    ) {
        use kuzushi_core::run_lifecycle::*;
        observation
            .emit_and_flush(RunItemRecord::new(
                RunItemId::new(),
                RunItemSource::Workflow,
                RunItemV1::TerminalOutcome {
                    status,
                    summary: SafeText::operator_visible(format!("scan {}", status.label())),
                    cost: kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
                    continuation: WorkflowContinuation::NoFurtherAction {
                        reason: SafeText::operator_visible("run terminal"),
                    },
                },
            ))
            .unwrap();
    }

    fn typed_attempt_for_status(
        target: &std::path::Path,
        run_id: &str,
        status: kuzushi_core::run_lifecycle::RunItemStatus,
    ) -> PhaseAttemptCompleted {
        PhaseAttemptCompleted::new(
            WorkflowPhase::Scan,
            vec![run_id.to_string()],
            kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target),
            phase_outcome_for_terminal(status),
        )
        .with_attempt_id(kuzushi_core::run_lifecycle::RunAttemptId::new().to_string())
        .with_receipt(kuzushi_core::workflow_attempts::PhaseAttemptReceipt {
            run_count: 1,
            elapsed_secs: 0,
            cost: "typed receipt pending".to_string(),
            changed_findings: 0,
            finding_delta_observed: None,
            changed_artifacts: Vec::new(),
            interaction_count: 0,
            rerun_specification: None,
            actions: Vec::new(),
            recommended_next: None,
        })
    }

    fn phase_outcome_for_terminal(
        status: kuzushi_core::run_lifecycle::RunItemStatus,
    ) -> PhaseAttemptOutcome {
        use kuzushi_core::run_lifecycle::RunItemStatus;
        match status {
            RunItemStatus::Completed | RunItemStatus::Skipped => PhaseAttemptOutcome::Completed,
            RunItemStatus::Partial => PhaseAttemptOutcome::Partial,
            RunItemStatus::Blocked => PhaseAttemptOutcome::Blocked,
            RunItemStatus::Canceled => PhaseAttemptOutcome::Canceled,
            RunItemStatus::Failed | RunItemStatus::Interrupted => PhaseAttemptOutcome::Failed,
            RunItemStatus::Pending | RunItemStatus::Running => {
                unreachable!("terminal-status fixture received a nonterminal status")
            }
        }
    }

    fn terminal_statuses() -> [kuzushi_core::run_lifecycle::RunItemStatus; 7] {
        use kuzushi_core::run_lifecycle::RunItemStatus;
        [
            RunItemStatus::Completed,
            RunItemStatus::Partial,
            RunItemStatus::Blocked,
            RunItemStatus::Failed,
            RunItemStatus::Canceled,
            RunItemStatus::Interrupted,
            RunItemStatus::Skipped,
        ]
    }

    fn contradictory_typed_attempt(
        target: &std::path::Path,
        run_id: &str,
    ) -> PhaseAttemptCompleted {
        typed_attempt_for_phase(target, run_id, WorkflowPhase::Scan)
    }

    fn typed_attempt_for_phase(
        target: &std::path::Path,
        run_id: &str,
        phase: WorkflowPhase,
    ) -> PhaseAttemptCompleted {
        PhaseAttemptCompleted::new(
            phase,
            vec![run_id.to_string()],
            kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target),
            PhaseAttemptOutcome::Completed,
        )
        .with_attempt_id(kuzushi_core::run_lifecycle::RunAttemptId::new().to_string())
        .with_receipt(kuzushi_core::workflow_attempts::PhaseAttemptReceipt {
            run_count: 99,
            elapsed_secs: 99,
            cost: "wrong transient cost".to_string(),
            changed_findings: 99,
            finding_delta_observed: None,
            changed_artifacts: Vec::new(),
            interaction_count: 99,
            rerun_specification: None,
            actions: vec![PhaseResultAction::Open],
            recommended_next: Some("wrong transient NEXT".to_string()),
        })
    }

    fn typed_run_semantic_keys(
        target: &std::path::Path,
        run_id: &str,
    ) -> std::collections::BTreeSet<kuzushi_core::run_lifecycle::RunCellKey> {
        let read = kuzushi_core::run_lifecycle::load_run_projection(target, run_id).unwrap();
        kuzushi_core::run_lifecycle::present_run(&read).semantic_keys()
    }

    #[test]
    fn degraded_ledger_projection_blocks_result_selection() {
        let target = tempfile::tempdir().unwrap();
        let snapshot = kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target.path());
        let completed = PhaseAttemptCompleted::new(
            WorkflowPhase::Scan,
            vec!["scan-run".to_string()],
            snapshot.clone(),
            PhaseAttemptOutcome::Completed,
        );
        let ledger = kuzushi_core::workflow_attempts::PhaseAttemptLedger::from_events([
            kuzushi_core::workflow_attempts::PhaseAttemptEvent::PhaseAttemptCompleted(completed),
        ])
        .unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.engagement
            .set_phase_attempt_projection_health(Some(snapshot), ledger, true);

        let policy = app
            .projected_phase_result_policy(WorkflowPhase::Scan)
            .unwrap();
        assert!(!policy.actions.contains(&PhaseResultAction::Select));
        assert!(policy.recommended_next.unwrap().contains("degraded"));
    }

    #[test]
    fn blocked_failed_and_canceled_attempts_are_never_demoted_by_evidence_blockers() {
        // An empty target trips the legacy map-evidence blocker; the
        // blocker must not rewrite a terminal Blocked/Failed/Canceled outcome into
        // "partial evidence", which would misstate what happened.
        let target = tempfile::tempdir().unwrap();
        let snapshot = kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target.path());
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        for outcome in [
            PhaseAttemptOutcome::Blocked,
            PhaseAttemptOutcome::Failed,
            PhaseAttemptOutcome::Canceled,
        ] {
            let completed = PhaseAttemptCompleted::new(
                WorkflowPhase::Map,
                vec!["map-run".to_string()],
                snapshot.clone(),
                outcome,
            );
            assert_eq!(app.effective_phase_attempt_outcome(&completed), outcome);
            assert_eq!(app.effective_phase_attempt_blocker(&completed), None);
            let presentation = app.phase_result_presentation_for(&completed);
            assert!(
                !presentation
                    .detail_lines
                    .iter()
                    .any(|line| line.contains("partial")),
                "{outcome:?} attempt presented as partial: {:?}",
                presentation.detail_lines
            );
        }
    }

    #[test]
    fn stale_map_blocks_scan_recovery_until_a_fresh_map_is_selected() {
        use kuzushi_core::workflow_attempts::{
            PhaseAttemptDisposition, PhaseAttemptDispositionRecorded, PhaseAttemptEvent,
            PhaseAttemptLedger, PhaseTargetSnapshot,
        };
        let target = tempfile::tempdir().unwrap();
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
        let selected = |attempt_id: String| {
            PhaseAttemptEvent::PhaseAttemptDispositionRecorded(
                PhaseAttemptDispositionRecorded::new(
                    attempt_id,
                    PhaseAttemptDisposition::Selected {
                        acknowledged_partial: false,
                    },
                ),
            )
        };
        let events = vec![
            PhaseAttemptEvent::PhaseAttemptCompleted(map.clone()),
            selected(map.attempt_id.clone()),
            PhaseAttemptEvent::PhaseAttemptCompleted(scan.clone()),
        ];
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.engagement.set_phase_attempt_projection(
            Some(current.clone()),
            PhaseAttemptLedger::from_events(events.clone()).unwrap(),
        );

        let blocked = app.phase_result_presentation(WorkflowPhase::Scan).unwrap();
        assert_eq!(blocked.compact_summary.outcome, PhaseAttemptOutcome::Failed);
        assert_eq!(
            blocked.actions,
            vec![PhaseResultAction::Open, PhaseResultAction::Discard]
        );
        assert_eq!(
            blocked.recommended_next,
            "rerun Map because the accepted Map is stale, then retry Scan"
        );

        let fresh_map = PhaseAttemptCompleted::new(
            WorkflowPhase::Map,
            vec!["map-current".to_string()],
            current.clone(),
            PhaseAttemptOutcome::Completed,
        );
        let mut refreshed_events = events;
        refreshed_events.push(PhaseAttemptEvent::PhaseAttemptCompleted(fresh_map.clone()));
        refreshed_events.push(selected(fresh_map.attempt_id));
        app.engagement.set_phase_attempt_projection(
            Some(current),
            PhaseAttemptLedger::from_events(refreshed_events).unwrap(),
        );

        let restored = app.phase_result_presentation(WorkflowPhase::Scan).unwrap();
        assert!(restored.actions.contains(&PhaseResultAction::RunAgain));
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
    fn completed_map_keeps_the_generic_action_set_narrow() {
        let actions = successful_result_actions(WorkflowPhase::Map, false);

        assert!(actions.contains(&PhaseResultAction::RunAgain));
        assert!(!actions.contains(&PhaseResultAction::Regenerate));
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
