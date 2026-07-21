use crossterm::event::KeyCode;
use kuzushi_core::workflow_attempts::{
    assess_map_evidence, collect_map_evidence, insufficient_map_evidence_message,
    MapEvidenceAdequacy, PhaseAttemptCompleted, PhaseAttemptOutcome, PhaseResultAction,
};
use kuzushi_core::WorkflowPhase;

use super::{RunFocusReceipt, RunSummaryEntriesState, ShellApp, ViewDataState};

#[path = "phase_results/typed_receipt.rs"]
mod typed_receipt;
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
    pub(crate) detail_lines: Vec<String>,
    pub(crate) detail_rows: Vec<PhaseResultDetailRow>,
    pub(crate) semantic_keys: std::collections::BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
    pub(crate) actions: Vec<PhaseResultAction>,
    pub(crate) recommended_next: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhaseResultDetailRow {
    pub(crate) key: Option<kuzushi_core::run_lifecycle::RunCellKey>,
    pub(crate) disclosed_keys: std::collections::BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
    pub(crate) text: String,
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
        let typed_receipt = TypedReceiptResolution::resolve(completed);
        let policy = self.phase_result_policy_with_receipt(completed, &typed_receipt);
        let live = self.matching_live_result_receipt(&completed.attempt_id);
        let fallback_outcome = self.effective_phase_attempt_outcome(completed);
        let effective_outcome = typed_receipt.outcome_or(fallback_outcome);
        let outcome = format!("{effective_outcome:?}").to_ascii_lowercase();
        let actions =
            ordered_phase_result_actions(completed.phase, effective_outcome, &policy.actions);
        let recommended_next = policy
            .recommended_next
            .unwrap_or_else(|| "open the result and choose a disposition".to_string());
        let details = phase_result_details(
            completed,
            effective_outcome,
            &typed_receipt,
            live,
            &recommended_next,
        );
        let detail_lines = details.rows.iter().map(|row| row.text.clone()).collect();
        let semantic_keys = details
            .rows
            .iter()
            .flat_map(PhaseResultDetailRow::accounted_keys)
            .cloned()
            .collect();
        PhaseResultPresentation {
            attempt_id: completed.attempt_id.clone(),
            detail_lines,
            detail_rows: details.rows,
            semantic_keys,
            outcome,
            actions,
            recommended_next,
        }
    }

    pub(crate) fn projected_phase_result_policy(
        &self,
        phase: WorkflowPhase,
    ) -> Option<PhaseResultPolicy> {
        let record = self.engagement.unresolved_phase_attempt(phase)?;
        Some(self.phase_result_policy_for(&record.completed))
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
        if let Some(policy) = receipt.authoritative_policy() {
            return policy;
        }
        if let Some(policy) = self.guarded_legacy_phase_result_policy(completed) {
            return policy;
        }
        let live = self.matching_live_result_receipt(&completed.attempt_id);
        legacy_receipt_result_policy(
            completed,
            self.effective_phase_attempt_outcome(completed),
            live,
        )
    }

    fn guarded_legacy_phase_result_policy(
        &self,
        completed: &PhaseAttemptCompleted,
    ) -> Option<PhaseResultPolicy> {
        if self.engagement.phase_attempt_projection_is_degraded() {
            return Some(selection_blocked_result_policy(
                "workflow attempt ledger is degraded; repair it before selecting results",
            ));
        }
        if let Some(reason) = self.effective_phase_attempt_blocker(completed) {
            return Some(selection_blocked_result_policy(&reason));
        }
        if self.verified_remediation_run_refs(
            completed.phase,
            completed.outcome,
            &completed.run_refs,
        ) {
            return Some(verified_remediation_result_policy());
        }
        None
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

    pub(crate) fn effective_phase_attempt_blocker(
        &self,
        completed: &PhaseAttemptCompleted,
    ) -> Option<String> {
        // Failed/canceled attempts are already terminal and unselectable;
        // demoting them to "partial evidence" would misstate the outcome
        // exactly when the operator needs the honest one.
        if matches!(
            completed.outcome,
            PhaseAttemptOutcome::Failed | PhaseAttemptOutcome::Canceled
        ) {
            return None;
        }
        if let Some(reason) = completed.selection_blocked_reason.as_ref() {
            return Some(reason.clone());
        }
        legacy_map_evidence_blocker(completed)
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
    rows.push(PhaseResultDetailRow::unkeyed(format!(
        "next: {recommended_next}"
    )));
    PhaseResultDetails { rows }
}

fn legacy_result_receipt_line(
    completed: &PhaseAttemptCompleted,
    live: Option<&RunFocusReceipt>,
    outcome: &str,
) -> String {
    if let Some(receipt) = live {
        return format!(
            "{} · {} finding delta · {} artifact delta · {} interaction(s)",
            receipt.summary(),
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
        "{outcome} · {} run{} · {}s · {cost} · {} finding delta · {} artifact delta · {} interaction(s)",
        receipt.run_count,
        if receipt.run_count == 1 { "" } else { "s" },
        receipt.elapsed_secs,
        receipt.changed_findings,
        receipt.changed_artifacts.len(),
        receipt.interaction_count
    )
}

fn durable_receipt_cost_label(cost: &str) -> String {
    // Old persisted receipts carry "unavailable"/"invalid"; new ones carry
    // "not recorded"/"accounting error". Both generations get the prefix.
    let qualified = ["incomplete", "unavailable", "invalid", "not recorded", "accounting"]
        .iter()
        .any(|marker| cost.contains(marker));
    if qualified {
        return format!("Cost: {cost}");
    }
    cost.to_string()
}

fn terminal_result_details(
    completed: &PhaseAttemptCompleted,
    typed_receipt: &TypedReceiptResolution,
    live: Option<&RunFocusReceipt>,
) -> PhaseResultDetails {
    if typed_receipt.is_legacy_lossy() {
        return legacy_terminal_result_details(completed, live);
    }
    if let Some(typed) = typed_durable_result_details(completed) {
        return typed;
    }
    legacy_phase_result_details(vec![
        "typed run result unavailable — inspect the referenced run".to_string(),
    ])
}

fn legacy_terminal_result_details(
    completed: &PhaseAttemptCompleted,
    live: Option<&RunFocusReceipt>,
) -> PhaseResultDetails {
    if let Some(result) = live.and_then(focused_live_result) {
        return legacy_phase_result_details(result_summary_lines(result));
    }
    let lines = legacy_durable_result_summary(completed)
        .as_ref()
        .map(result_summary_lines)
        .unwrap_or_default();
    if lines.is_empty() {
        return typed_durable_result_details(completed).unwrap_or_default();
    }
    legacy_phase_result_details(lines)
}

fn legacy_phase_result_details(lines: Vec<String>) -> PhaseResultDetails {
    PhaseResultDetails {
        rows: lines
            .into_iter()
            .map(PhaseResultDetailRow::unkeyed)
            .collect(),
    }
}

fn focused_live_result(
    receipt: &RunFocusReceipt,
) -> Option<&kuzushi_core::run_artifacts::RunResultSummary> {
    receipt
        .result_summaries
        .iter()
        .find(|result| matches!(result.status.as_str(), "failed" | "partial"))
        .or_else(|| receipt.result_summaries.last())
}

fn legacy_durable_result_summary(
    completed: &PhaseAttemptCompleted,
) -> Option<kuzushi_core::run_artifacts::RunResultSummary> {
    let target = std::path::Path::new(&completed.target_snapshot.target);
    let mut fallback = None;
    for run_id in &completed.run_refs {
        let Ok(Some(result)) = kuzushi_core::run_artifacts::load_run_result_summary(target, run_id)
        else {
            continue;
        };
        if matches!(result.status.as_str(), "failed" | "partial") {
            return Some(result);
        }
        fallback = Some(result);
    }
    fallback
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
        RunItemStatus::Failed
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
/// and nominal stream-health lines stay behind the disclosure rows —
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
    if !folded_keys.is_empty() {
        rows.push(PhaseResultDetailRow::disclosure(
            format!(
                "{} run ledger cell(s) omitted from the result card · inspect replay",
                folded_keys.len()
            ),
            folded_keys,
        ));
    }
    if !presentation.timeline.is_empty() {
        let disclosed_keys = presentation
            .timeline
            .iter()
            .map(|cell| cell.key.clone())
            .collect();
        rows.push(PhaseResultDetailRow::disclosure(
            format!(
                "{} timeline cell(s) omitted from the result card · inspect replay",
                presentation.timeline.len()
            ),
            disclosed_keys,
        ));
    }
    rows
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
        Kind::Work => false,
    }
}

fn result_summary_lines(result: &kuzushi_core::run_artifacts::RunResultSummary) -> Vec<String> {
    semantic_result_lines(
        &result.tool,
        &result.status,
        &result.summary,
        result.operator_output_preview(5).into_iter(),
        result
            .errors
            .first()
            .or_else(|| result.warnings.first())
            .map(String::as_str),
        result
            .artifacts
            .iter()
            .map(|artifact| artifact.label.as_str()),
    )
}

fn semantic_result_lines<'a>(
    tool: &str,
    status: &str,
    summary: &str,
    output_lines: impl Iterator<Item = &'a str>,
    operator_message: Option<&str>,
    artifact_labels: impl Iterator<Item = &'a str>,
) -> Vec<String> {
    let mut lines = vec![format!("{tool} · {status} — {summary}")];
    lines.extend(output_lines.take(5).map(|line| format!("│ {line}")));
    if let Some(message) = operator_message.filter(|message| *message != summary) {
        lines.push(format!("⚠ {message}"));
    }
    let labels = artifact_labels.take(3).collect::<Vec<_>>();
    if !labels.is_empty() {
        lines.push(format!("artifacts: {}", labels.join(" · ")));
    }
    lines
}

fn legacy_receipt_result_policy(
    completed: &PhaseAttemptCompleted,
    outcome: PhaseAttemptOutcome,
    live: Option<&RunFocusReceipt>,
) -> PhaseResultPolicy {
    let fallback = phase_result_policy(Some(completed.phase), outcome, false);
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

fn legacy_map_evidence_blocker(completed: &PhaseAttemptCompleted) -> Option<String> {
    if completed.phase != WorkflowPhase::Map {
        return None;
    }
    let target = std::path::Path::new(&completed.target_snapshot.target);
    let facts = collect_map_evidence(target, &completed.run_refs);
    (assess_map_evidence(&facts) == MapEvidenceAdequacy::Inadequate)
        .then(|| insufficient_map_evidence_message(target))
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
        write_typed_terminal_run(target, run_id);
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
    fn evidence_empty_legacy_map_projects_as_blocked_partial() {
        let target = tempfile::tempdir().unwrap();
        let completed = PhaseAttemptCompleted::new(
            WorkflowPhase::Map,
            vec!["legacy-map-run".to_string()],
            kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target.path()),
            PhaseAttemptOutcome::Completed,
        );
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);

        assert_eq!(
            app.effective_phase_attempt_outcome(&completed),
            PhaseAttemptOutcome::Partial
        );
        assert!(app
            .effective_phase_attempt_blocker(&completed)
            .unwrap()
            .contains("no map evidence"));
    }

    #[test]
    fn workflow_v1_result_presentation_uses_receipt_metadata_without_copying_results() {
        let target = tempfile::tempdir().unwrap();
        record_partial_threat_model_result(target.path());
        let completed = durable_partial_attempt(target.path());
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);

        let presentation = app.phase_result_presentation_for(&completed);

        assert_eq!(presentation.outcome, "partial");
        assert_contains_detail(&presentation, "Cost: >=$0.0000 (incomplete)");
        assert_contains_detail(&presentation, "choose a target with analyzable evidence");
        for expected in [
            "threat-model:build · partial",
            "Threats: 0",
            "previous model preserved",
            "normalized-threat-model.json",
        ] {
            assert_contains_detail(&presentation, expected);
        }
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
        assert!(!presentation
            .recommended_next
            .contains("no map evidence"));
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
            card.detail
                .contains("timeline cell(s) omitted from the result card · inspect replay"),
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
            detail.contains("Outcome · "),
            "terminal outcome missing from the card: {detail}"
        );
        assert!(
            !detail.contains("Cost · ") && !detail.contains("NEXT · "),
            "terminal cost/continuation rows duplicate the receipt header and \
             the card's next: footer: {detail}"
        );
        assert!(
            detail.contains("run ledger cell(s) omitted from the result card"),
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
        let disclosure = format!(
            "{} timeline cell(s) omitted from the result card · inspect replay",
            canonical.timeline.len()
        );
        assert!(
            card.detail.contains(&disclosure),
            "{} card did not disclose bounded timeline",
            status.label()
        );
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
            RunItemStatus::Canceled => PhaseAttemptOutcome::Canceled,
            RunItemStatus::Failed | RunItemStatus::Interrupted => PhaseAttemptOutcome::Failed,
            RunItemStatus::Pending | RunItemStatus::Running => {
                unreachable!("terminal-status fixture received a nonterminal status")
            }
        }
    }

    fn terminal_statuses() -> [kuzushi_core::run_lifecycle::RunItemStatus; 6] {
        use kuzushi_core::run_lifecycle::RunItemStatus;
        [
            RunItemStatus::Completed,
            RunItemStatus::Partial,
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
    fn failed_and_canceled_attempts_are_never_demoted_to_partial_by_evidence_blockers() {
        // An empty target trips the legacy map-evidence blocker; the
        // blocker must not rewrite a terminal Failed/Canceled outcome into
        // "partial evidence", which would misstate what happened.
        let target = tempfile::tempdir().unwrap();
        let snapshot = kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target.path());
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        for outcome in [PhaseAttemptOutcome::Failed, PhaseAttemptOutcome::Canceled] {
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
