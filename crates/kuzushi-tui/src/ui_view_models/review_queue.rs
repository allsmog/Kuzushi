use super::findings::{
    finding_identity_label, finding_proof_meter, finding_unique_source_count,
    projected_visible_findings, relativize_location, target_base, visible_findings_cache_key,
};
use super::review_conflicts::effective_review_decision_conflict_label;
use super::review_state::{
    effective_review_author_label, effective_review_confidence_label,
    effective_review_decision_complete, effective_review_decision_label, evidence_state_label,
    lifecycle_status_label, EffectiveReviewDecision, EffectiveReviewStateIndex,
};
use super::SeverityTone;
use crate::{ReviewQueueCacheKey, ShellApp};
use kuzushi_core::{
    finding_next_action, project_finding, Finding, FindingNextAction, ProofConfidence,
};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReviewQueueMode {
    Open,
    Complete,
    All,
}

/// Operator-workflow metadata carried by each review row. It describes the
/// review state without changing the canonical confidence-first order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReviewWorkflowGroup {
    NeedsReview,
    Confirmed,
    Deferred,
    Closed,
}

impl ReviewQueueMode {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Complete => "complete",
            Self::All => "all",
        }
    }

    fn cache_key(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Complete => 1,
            Self::All => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReviewQueueModel {
    pub(crate) navigation_active: bool,
    pub(crate) total_count: usize,
    pub(crate) visible_count: usize,
    pub(crate) open_count: usize,
    pub(crate) complete_count: usize,
    pub(crate) filter_label: String,
    pub(crate) completeness_mode: &'static str,
    pub(crate) header: String,
    pub(crate) empty_reason: Option<String>,
    pub(crate) rows: Arc<[ReviewQueueRow]>,
    pub(crate) selected_row: Option<usize>,
}

impl ReviewQueueModel {
    #[cfg(test)]
    pub(crate) fn row_is_selected(&self, index: usize) -> bool {
        self.selected_row == Some(index)
    }

    #[cfg(test)]
    pub(crate) fn selected(&self) -> Option<&ReviewQueueRow> {
        self.selected_row.and_then(|index| self.rows.get(index))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReviewQueueRow {
    pub(crate) alias: String,
    pub(crate) identity_label: String,
    pub(crate) severity_tone: SeverityTone,
    pub(crate) severity_label: String,
    pub(crate) proof_confidence: ProofConfidence,
    pub(crate) proof_confidence_label: String,
    pub(crate) confidence_label: String,
    pub(crate) priority_label: String,
    pub(crate) lifecycle_status: String,
    pub(crate) decision: String,
    pub(crate) decision_conflict: Option<String>,
    pub(crate) decision_complete: bool,
    pub(crate) decision_author: String,
    pub(crate) title: String,
    pub(crate) location: String,
    pub(crate) rule: String,
    pub(crate) tool: String,
    pub(crate) proof_label: String,
    pub(crate) proof_meter: String,
    pub(crate) source_count: usize,
    pub(crate) evidence_state: String,
    pub(crate) next_action: String,
    pub(crate) projection_index: usize,
    /// Renderer fixtures may set this directly. Production selection lives on
    /// `ReviewQueueModel::selected_row` so cached rows survive cursor moves.
    pub(crate) selected: bool,
    pub(crate) workflow_group: ReviewWorkflowGroup,
}

pub(crate) fn review_queue_model(app: &ShellApp, mode: ReviewQueueMode) -> ReviewQueueModel {
    let (rows, open_count, complete_count) = cached_review_queue_rows(app, mode);
    let total_count = open_count + complete_count;
    let visible_count = rows.len();
    let cursor = app.router.findings().cursor();
    let selected_row = rows.iter().position(|row| row.projection_index == cursor);
    ReviewQueueModel {
        navigation_active: app.input_mode() == crate::InputMode::Navigate,
        total_count,
        visible_count,
        open_count,
        complete_count,
        filter_label: review_queue_filter_label(app, mode),
        completeness_mode: mode.label(),
        header: review_queue_header(visible_count, total_count, open_count, complete_count),
        empty_reason: review_queue_empty_reason(total_count, visible_count, mode),
        rows,
        selected_row,
    }
}

fn cached_review_queue_rows(
    app: &ShellApp,
    mode: ReviewQueueMode,
) -> (Arc<[ReviewQueueRow]>, usize, usize) {
    let key = ReviewQueueCacheKey::new(visible_findings_cache_key(app), mode.cache_key());
    if let Some(cached) = app.workbench_cache().borrow().review_queue(&key) {
        return cached;
    }
    let base = target_base(app);
    let review_index = EffectiveReviewStateIndex::from_findings_and_decisions(
        app.findings(),
        app.review_decisions(),
    );
    let all_rows = projected_review_queue_rows(app, &review_index, base.as_deref());
    let open_count = all_rows.iter().filter(|row| !row.review_complete()).count();
    let complete_count = all_rows.len().saturating_sub(open_count);
    let rows = Arc::from(filter_review_rows(all_rows, mode));
    app.workbench_cache().borrow_mut().cache_review_queue(
        key,
        Arc::clone(&rows),
        open_count,
        complete_count,
    );
    (rows, open_count, complete_count)
}

fn review_queue_filter_label(app: &ShellApp, mode: ReviewQueueMode) -> String {
    app.active_findings_filter()
        .as_deref()
        .map(str::trim)
        .filter(|filter| !filter.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("completeness:{}", mode.label()))
}

fn projected_review_queue_rows(
    app: &ShellApp,
    review_index: &EffectiveReviewStateIndex,
    base: Option<&str>,
) -> Vec<ReviewQueueRow> {
    projected_visible_findings(app)
        .iter()
        .enumerate()
        .map(|(index, projected)| {
            let decision = review_index.effective_decision_for(&projected.finding);
            ReviewQueueRow::from_finding(
                index,
                projected.alias.clone(),
                &projected.finding,
                decision.as_ref(),
                base,
            )
        })
        .collect()
}

fn filter_review_rows(rows: Vec<ReviewQueueRow>, mode: ReviewQueueMode) -> Vec<ReviewQueueRow> {
    rows.into_iter()
        .filter(|row| match mode {
            ReviewQueueMode::Open => !row.review_complete(),
            ReviewQueueMode::Complete => row.review_complete(),
            ReviewQueueMode::All => true,
        })
        .collect()
}

fn review_queue_header(
    visible_count: usize,
    total_count: usize,
    open_count: usize,
    complete_count: usize,
) -> String {
    format!(
        "REVIEW QUEUE - showing {visible_count} of {total_count} - {open_count} open - {complete_count} complete"
    )
}

fn review_queue_empty_reason(
    total_count: usize,
    visible_count: usize,
    mode: ReviewQueueMode,
) -> Option<String> {
    if visible_count > 0 {
        return None;
    }
    if total_count == 0 {
        return Some("no findings loaded for review".to_string());
    }
    match mode {
        ReviewQueueMode::Open => Some("all visible findings have terminal decisions".to_string()),
        ReviewQueueMode::Complete => {
            Some("no visible findings have terminal decisions".to_string())
        }
        ReviewQueueMode::All => None,
    }
}

impl ReviewQueueRow {
    fn from_finding(
        index: usize,
        alias: String,
        finding: &Finding,
        decision: Option<&EffectiveReviewDecision>,
        base: Option<&str>,
    ) -> Self {
        let projection = project_finding(finding, Some(alias.clone()));
        let decision_label = effective_review_decision_label(finding, decision);
        let decision_conflict = effective_review_decision_conflict_label(finding, decision);
        let workflow_group = workflow_group(&decision_label, decision_conflict.as_deref());
        Self {
            alias,
            identity_label: finding_identity_label(finding),
            severity_tone: SeverityTone::from_severity(projection.severity),
            severity_label: projection.severity_label,
            proof_confidence: ProofConfidence::classify(finding),
            proof_confidence_label: ProofConfidence::classify(finding).label().to_string(),
            confidence_label: effective_review_confidence_label(finding, decision),
            priority_label: format!("review-order:{}", index + 1),
            lifecycle_status: lifecycle_status_label(finding),
            decision: decision_label,
            decision_conflict,
            decision_complete: effective_review_decision_complete(finding, decision),
            decision_author: effective_review_author_label(finding, decision),
            title: projection.title,
            location: relativize_location(projection.location, base),
            rule: projection.rule,
            tool: projection.tool,
            proof_label: projection.proof_state,
            proof_meter: finding_proof_meter(finding),
            source_count: finding_unique_source_count(finding),
            evidence_state: evidence_state_label(finding),
            next_action: review_next_action_label(finding, decision),
            projection_index: index,
            selected: false,
            workflow_group,
        }
    }

    fn review_complete(&self) -> bool {
        self.decision_complete && self.decision_conflict.is_none()
    }
}

pub(crate) fn workflow_group(decision: &str, conflict: Option<&str>) -> ReviewWorkflowGroup {
    if conflict.is_some() {
        return ReviewWorkflowGroup::NeedsReview;
    }
    match decision {
        "confirmed" | "to_fix" => ReviewWorkflowGroup::Confirmed,
        "deferred" | "accepted_risk" => ReviewWorkflowGroup::Deferred,
        "rejected_false_positive" | "false_positive" | "suppressed" => ReviewWorkflowGroup::Closed,
        _ => ReviewWorkflowGroup::NeedsReview,
    }
}

fn review_next_action_label(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> String {
    match (
        review_verdict(finding, decision),
        finding_next_action(finding, None),
    ) {
        (decision, _) if decision.is_terminal() => "review complete".to_string(),
        (_, FindingNextAction::Validate) => "validate".to_string(),
        (_, FindingNextAction::Patch) => "patch".to_string(),
        (_, FindingNextAction::Suppress) => "review_rejection".to_string(),
        (_, FindingNextAction::Review) => "review".to_string(),
    }
}

fn review_verdict(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> kuzushi_core::findings::ReviewDecisionVerdict {
    decision
        .map(EffectiveReviewDecision::verdict)
        .unwrap_or_else(|| super::review_state::current_review_decision(finding))
}

#[cfg(test)]
#[path = "tests/review_queue.rs"]
mod tests;
