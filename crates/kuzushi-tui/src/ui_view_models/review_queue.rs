use super::findings::{
    finding_identity_label, projected_visible_finding_pairs, relativize_location, target_base,
};
use super::review_conflicts::effective_review_decision_conflict_label;
use super::review_state::{
    effective_review_author_label, effective_review_confidence_label,
    effective_review_decision_complete, effective_review_decision_label, evidence_state_label,
    lifecycle_status_label, EffectiveReviewDecision, EffectiveReviewStateIndex,
};
use super::SeverityTone;
use crate::ShellApp;
use kuzushi_core::{finding_next_action, project_finding, Finding, FindingNextAction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReviewQueueMode {
    Open,
    Complete,
    All,
}

impl ReviewQueueMode {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Complete => "complete",
            Self::All => "all",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReviewQueueModel {
    pub(crate) total_count: usize,
    pub(crate) visible_count: usize,
    pub(crate) open_count: usize,
    pub(crate) complete_count: usize,
    pub(crate) filter_label: String,
    pub(crate) completeness_mode: &'static str,
    pub(crate) header: String,
    pub(crate) empty_reason: Option<String>,
    pub(crate) rows: Vec<ReviewQueueRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReviewQueueRow {
    pub(crate) alias: String,
    pub(crate) identity_label: String,
    pub(crate) severity_tone: SeverityTone,
    pub(crate) severity_label: String,
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
    pub(crate) evidence_state: String,
    pub(crate) next_action: String,
    pub(crate) selected: bool,
}

pub(crate) fn review_queue_model(app: &ShellApp, mode: ReviewQueueMode) -> ReviewQueueModel {
    let base = target_base(app);
    let selected_key = app.selected_finding.as_ref().map(review_queue_key);
    let review_index = EffectiveReviewStateIndex::from_findings_and_decisions(
        &app.findings,
        &app.review_decisions,
    );
    let all_rows = projected_visible_finding_pairs(app)
        .into_iter()
        .enumerate()
        .map(|(index, (alias, finding))| {
            let decision = review_index.effective_decision_for(&finding);
            ReviewQueueRow::from_finding(
                index,
                app.findings_route.cursor(),
                alias,
                &finding,
                decision.as_ref(),
                base.as_deref(),
                selected_key.as_deref(),
            )
        })
        .collect::<Vec<_>>();
    let open_count = all_rows.iter().filter(|row| !row.review_complete()).count();
    let complete_count = all_rows.len().saturating_sub(open_count);
    let rows = filter_review_rows(all_rows, mode);
    let total_count = open_count + complete_count;
    let visible_count = rows.len();
    ReviewQueueModel {
        total_count,
        visible_count,
        open_count,
        complete_count,
        filter_label: format!("decision:{}", mode.label()),
        completeness_mode: mode.label(),
        header: review_queue_header(visible_count, total_count, open_count, complete_count),
        empty_reason: review_queue_empty_reason(total_count, visible_count, mode),
        rows,
    }
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
        cursor: usize,
        alias: String,
        finding: &Finding,
        decision: Option<&EffectiveReviewDecision>,
        base: Option<&str>,
        selected_key: Option<&str>,
    ) -> Self {
        let projection = project_finding(finding, Some(alias.clone()));
        Self {
            alias,
            identity_label: finding_identity_label(finding),
            severity_tone: SeverityTone::from_severity(projection.severity),
            severity_label: projection.severity_label,
            confidence_label: effective_review_confidence_label(finding, decision),
            priority_label: format!("review-order:{}", index + 1),
            lifecycle_status: lifecycle_status_label(finding),
            decision: effective_review_decision_label(finding, decision),
            decision_conflict: effective_review_decision_conflict_label(finding, decision),
            decision_complete: effective_review_decision_complete(finding, decision),
            decision_author: effective_review_author_label(finding, decision),
            title: projection.title,
            location: relativize_location(projection.location, base),
            rule: projection.rule,
            tool: projection.tool,
            proof_label: projection.proof_state,
            evidence_state: evidence_state_label(finding),
            next_action: review_next_action_label(finding, decision),
            selected: review_row_selected(index, cursor, finding, selected_key),
        }
    }

    fn review_complete(&self) -> bool {
        self.decision_complete && self.decision_conflict.is_none()
    }
}

fn review_row_selected(
    index: usize,
    cursor: usize,
    finding: &Finding,
    selected_key: Option<&str>,
) -> bool {
    selected_key
        .map(|key| key == review_queue_key(finding))
        .unwrap_or(index == cursor)
}

fn review_next_action_label(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> String {
    match (
        review_verdict(finding, decision),
        finding_next_action(finding, None),
    ) {
        (decision, _) if decision.is_terminal() => "decision_complete".to_string(),
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

fn review_queue_key(finding: &Finding) -> String {
    finding
        .dedup_key
        .clone()
        .unwrap_or_else(|| finding.fingerprint.clone())
}

#[cfg(test)]
#[path = "tests/review_queue.rs"]
mod tests;
