use super::findings::{
    displayed_location, finding_confidence_label, finding_identity_label, finding_proof_meter,
    finding_unique_source_count, projected_findings_before_search, projected_visible_findings,
    target_base, visible_findings_cache_key,
};
use super::review_conflicts::effective_review_decision_conflict_label;
use super::review_state::{
    effective_review_author_label, effective_review_confidence_label,
    effective_review_decision_complete, effective_review_decision_label, evidence_state_label,
    lifecycle_status_label, EffectiveReviewDecision, EffectiveReviewStateIndex,
};
use super::{finding_facet_values, FindingSearch, SeverityTone};
use crate::{ReviewQueueCacheKey, ShellApp};
use kuzushi_core::findings::{ReviewDecisionConflict, ReviewDecisionVerdict};
use kuzushi_core::{project_finding, Finding, PersistedVerification, ProofConfidence};
use std::sync::Arc;
mod read_feedback;
pub(crate) use read_feedback::ReviewReadFeedback;

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
    pub(crate) path_history: bool,
    pub(crate) refresh_status: Option<ReviewReadFeedback>,
    pub(crate) decision_save_label: Option<String>,
    pub(crate) page: Option<ReviewQueuePage>,
    pub(crate) partial_load: Option<ReviewQueuePartialLoad>,
    pub(crate) total_count: usize,
    pub(crate) visible_count: usize,
    pub(crate) open_count: usize,
    pub(crate) complete_count: usize,
    pub(crate) search_active: bool,
    pub(crate) search_capture: bool,
    pub(crate) active_filter_chips: Vec<String>,
    pub(crate) facet_groups: Arc<[ReviewFacetGroup]>,
    pub(crate) filter_label: String,
    pub(crate) completeness_mode: &'static str,
    /// Names the active display order. The normal queue announces its
    /// proof-band/severity order; Learn replaces that label when it actually
    /// reorders a band. Backlog names severity-first in its header instead.
    pub(crate) ordering_indicator: Option<&'static str>,
    pub(crate) operator_calibration: OperatorCalibrationModel,
    pub(crate) header: String,
    pub(crate) empty_reason: Option<String>,
    pub(crate) rows: Arc<[ReviewQueueRow]>,
    pub(crate) selected_row: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReviewQueuePartialLoad {
    pub(crate) loaded: usize,
    pub(crate) matching: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReviewQueuePage {
    pub(crate) offset: usize,
    pub(crate) loaded: usize,
    pub(crate) total: usize,
    pub(crate) has_next: bool,
    pub(crate) has_previous: bool,
}

impl ReviewQueuePage {
    pub(crate) fn label(self) -> String {
        format!(
            "rows {}-{} of {}",
            self.offset + usize::from(self.loaded > 0),
            self.offset + self.loaded,
            self.total
        )
    }
}

impl ReviewQueuePartialLoad {
    pub(crate) fn label(self) -> String {
        format!(
            "{} of {} matching findings loaded",
            self.loaded, self.matching
        )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct OperatorCalibrationModel {
    pub(crate) identified: usize,
    pub(crate) runtime_supported: usize,
    pub(crate) contradicted: usize,
    pub(crate) needs_follow_up: usize,
    pub(crate) unattributed_human_history: bool,
}

impl OperatorCalibrationModel {
    pub(crate) fn is_available(self) -> bool {
        self.identified > 0 || self.unattributed_human_history
    }

    pub(crate) fn label(self, compact: bool) -> String {
        if self.identified == 0 && self.unattributed_human_history {
            return if compact {
                "my decisions · identity unavailable".to_string()
            } else {
                "your evidence follow-up is unavailable · older human decisions have no stable operator identity"
                    .to_string()
            };
        }
        if compact {
            return format!(
                "my decisions · ok {} · conflict {} · check {}",
                self.runtime_supported, self.contradicted, self.needs_follow_up
            );
        }
        format!(
            "your evidence follow-up · {} runtime-supported · {} contradicted · {} need follow-up",
            self.runtime_supported, self.contradicted, self.needs_follow_up
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReviewFacetGroup {
    pub(crate) label: &'static str,
    pub(crate) values: Vec<ReviewFacetCount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReviewFacetCount {
    pub(crate) value: String,
    pub(crate) count: usize,
}

impl ReviewQueueModel {
    pub(crate) fn population_title(&self) -> String {
        self.decision_save_label
            .as_ref()
            .map(|label| format!("FINDINGS · saving {label}"))
            .unwrap_or_else(|| self.population_title_without_save())
    }

    fn population_title_without_save(&self) -> String {
        if self.completeness_mode == "backlog" {
            return format!("REVIEW BACKLOG · {}", self.visible_count);
        }
        self.findings_population_title()
    }

    fn findings_population_title(&self) -> String {
        if let Some(feedback) = &self.refresh_status {
            return feedback.population_title().into();
        }
        if let Some(page) = self.page.filter(|page| page.offset > 0) {
            return format!(
                "FINDINGS · {}-{}/{}",
                page.offset + 1,
                page.offset + page.loaded,
                page.total
            );
        }
        match self.partial_load {
            Some(partial) => format!("FINDINGS · {}/{} loaded", partial.loaded, partial.matching),
            None => format!("FINDINGS · {}", self.visible_count),
        }
    }
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
    pub(crate) occurrence: Option<ReviewOccurrence>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReviewOccurrence {
    pub(crate) seen: usize,
    pub(crate) completed: usize,
    pub(crate) planned: usize,
    pub(crate) failed: usize,
}

pub(crate) fn review_queue_model(app: &ShellApp, mode: ReviewQueueMode) -> ReviewQueueModel {
    let (rows, open_count, complete_count, facet_groups) = cached_review_queue_rows(app, mode);
    let total_count = open_count + complete_count;
    let visible_count = rows.len();
    let cursor = app.router.findings().cursor();
    let selected_row = rows.iter().position(|row| row.projection_index == cursor);
    let review = app.router.workbench().review();
    let search_active = review_search_active(review);
    let backlog = super::review_backlog_active(app);
    let partial_load = app
        .domain()
        .findings_are_partial()
        .then(|| ReviewQueuePartialLoad {
            loaded: app.findings().len(),
            matching: app.findings_total_count(),
        });
    let header = if backlog {
        backlog_header(visible_count, review)
    } else {
        review_queue_header(visible_count, total_count, open_count, complete_count)
    };
    ReviewQueueModel {
        path_history: app.dfd_path_query_is_active(),
        navigation_active: app.input_mode() == crate::InputMode::Navigate,
        refresh_status: app.findings_read_feedback(),
        decision_save_label: app.review_decision_save_label(),
        page: app
            .domain()
            .findings_page()
            .filter(|page| page.total > page.loaded)
            .map(|page| ReviewQueuePage {
                offset: page.offset,
                loaded: page.loaded,
                total: page.total,
                has_next: page.next_cursor.is_some(),
                has_previous: page.previous_cursor.is_some(),
            }),
        partial_load,
        total_count,
        visible_count,
        open_count,
        complete_count,
        search_active,
        search_capture: review.search_capture,
        active_filter_chips: review_filter_chips(app, mode),
        facet_groups,
        filter_label: review_queue_filter_label(app, mode),
        completeness_mode: if backlog { "backlog" } else { mode.label() },
        ordering_indicator: review_ordering_indicator(app, backlog),
        operator_calibration: operator_calibration_model(app.findings(), app.review_decisions()),
        header: qualify_partial_review_header(header, partial_load),
        empty_reason: app
            .findings_refresh_status()
            .or_else(|| partial_review_empty_reason(partial_load, visible_count))
            .or_else(|| {
                review_queue_empty_reason(
                    total_count,
                    visible_count,
                    app.findings().len(),
                    search_active,
                    mode,
                )
            }),
        rows,
        selected_row,
    }
}

fn qualify_partial_review_header(
    header: String,
    partial: Option<ReviewQueuePartialLoad>,
) -> String {
    match partial {
        Some(partial) => format!("{header} · {}", partial.label()),
        None => header,
    }
}

fn partial_review_empty_reason(
    partial: Option<ReviewQueuePartialLoad>,
    visible: usize,
) -> Option<String> {
    (partial.is_some() && visible == 0).then(|| {
        "No matches in the loaded portion. Filter the ledger to inspect omitted findings.".into()
    })
}

fn operator_calibration_model(
    findings: &[Finding],
    decisions: &[kuzushi_core::findings::ReviewDecisionRecord],
) -> OperatorCalibrationModel {
    let index = EffectiveReviewStateIndex::from_findings_and_decisions(findings, decisions);
    let unattributed_human_history = decisions.iter().any(|record| {
        record.decision.author == kuzushi_core::findings::TriageAuthor::Human
            && record.decision.actor.as_deref().is_none_or(str::is_empty)
    });
    let mut model = OperatorCalibrationModel {
        unattributed_human_history,
        ..OperatorCalibrationModel::default()
    };
    for finding in findings {
        let Some(decision) = index.effective_decision_for(finding) else {
            continue;
        };
        if decision.review_decision().actor.as_deref() != Some("operator") {
            continue;
        }
        model.identified += 1;
        let conflict = ReviewDecisionConflict::classify(
            finding,
            decision.verdict(),
            decision.carried_from_durable_identity(),
        );
        match conflict {
            Some(
                ReviewDecisionConflict::RuntimeVerifiedAfterRejection
                | ReviewDecisionConflict::NotReproducedAfterConfirmation,
            ) => {
                model.contradicted += 1;
                continue;
            }
            Some(ReviewDecisionConflict::ReappearedAfterRejection) => {
                model.needs_follow_up += 1;
                continue;
            }
            None => {}
        }
        if matches!(
            decision.verdict(),
            ReviewDecisionVerdict::Confirmed | ReviewDecisionVerdict::ToFix
        ) && finding
            .verification
            .as_ref()
            .is_some_and(PersistedVerification::is_empirically_verified)
        {
            model.runtime_supported += 1;
            continue;
        }
        model.needs_follow_up += 1;
    }
    model
}

fn review_search_active(review: &crate::app::WorkbenchReviewState) -> bool {
    !review.search_query.trim().is_empty()
}

/// What the queue says about itself when Learn mode is moving rows.
///
/// The gap is the *model's*, never the finding's: a row near the top is one
/// the model has little evidence about, not one more likely to be a real
/// vulnerability. Absent whenever the objective ranks nothing — an armed mode
/// whose every band is frozen leaves the baseline order on screen, and a chip
/// claiming otherwise would name a state that does not exist.
pub(crate) const LEARN_ORDERING_INDICATOR: &str = "learn mode - model knowledge-gap review";
pub(crate) const BASELINE_ORDERING_INDICATOR: &str = "order: proof band, then severity";

fn learn_ordering_indicator(app: &ShellApp) -> Option<&'static str> {
    super::findings::learn_ordering_ranks_queue(app).then_some(LEARN_ORDERING_INDICATOR)
}

fn review_ordering_indicator(app: &ShellApp, backlog: bool) -> Option<&'static str> {
    if backlog {
        return None;
    }
    Some(learn_ordering_indicator(app).unwrap_or(BASELINE_ORDERING_INDICATOR))
}

/// The backlog projection already dropped decided findings, so the header
/// reports burn-down progress instead of open/complete split. Active
/// severity/tool filter chips render inline so the operator always sees
/// what the one-key and bulk actions will hit.
fn backlog_header(visible_count: usize, review: &crate::app::WorkbenchReviewState) -> String {
    let mut chips = String::new();
    if let Some(severity) = review.backlog_severity {
        chips.push_str(&format!(" - sev:{severity}"));
    }
    if let Some(tool) = review.backlog_tool.as_deref() {
        chips.push_str(&format!(" - tool:{tool}"));
    }
    if review.backlog_confirm_bulk {
        chips.push_str(&format!(
            " - CONFIRM defer-all {visible_count}? press X again"
        ));
    }
    format!(
        "REVIEW BACKLOG - {visible_count} untriaged, severity-first{chips} - {} decided this session - c confirm - f reject-FP - d defer - w needs-review - s/t filter - X defer-all - u undo",
        review.session_decided
    )
}

fn cached_review_queue_rows(
    app: &ShellApp,
    mode: ReviewQueueMode,
) -> (Arc<[ReviewQueueRow]>, usize, usize, Arc<[ReviewFacetGroup]>) {
    let key = ReviewQueueCacheKey::new(visible_findings_cache_key(app), mode.cache_key());
    if let Some(cached) = app.workbench_cache().borrow().review_queue(&key) {
        return cached;
    }
    let base = target_base(app);
    let review_index = EffectiveReviewStateIndex::from_findings_and_decisions(
        app.findings(),
        app.review_decisions(),
    );
    let candidates = projected_findings_before_search(app);
    let facet_groups = Arc::from(review_facet_groups(app, &candidates, &review_index));
    let (open_count, complete_count) = candidate_review_counts(app, &candidates, &review_index);
    let all_rows = projected_review_queue_rows(app, &review_index, base.as_deref());
    let rows = Arc::from(filter_review_rows(all_rows, mode));
    app.workbench_cache().borrow_mut().cache_review_queue(
        key,
        Arc::clone(&rows),
        open_count,
        complete_count,
        Arc::clone(&facet_groups),
    );
    (rows, open_count, complete_count, facet_groups)
}

fn candidate_review_counts(
    app: &ShellApp,
    candidates: &[crate::VisibleFindingProjection],
    review_index: &EffectiveReviewStateIndex,
) -> (usize, usize) {
    let complete = candidates
        .iter()
        .filter(|candidate| {
            let decision = review_index.effective_decision_for(&candidate.finding);
            super::review_state::source_qualified_review_complete(
                app,
                &candidate.finding,
                decision.as_ref(),
            )
        })
        .count();
    (candidates.len().saturating_sub(complete), complete)
}

fn review_queue_filter_label(app: &ShellApp, mode: ReviewQueueMode) -> String {
    review_filter_chips(app, mode).join(" ")
}

fn review_filter_chips(app: &ShellApp, mode: ReviewQueueMode) -> Vec<String> {
    let mut chips = super::findings::scope_filter::display(app)
        .as_deref()
        .map(str::trim)
        .filter(|filter| !filter.is_empty())
        .map(str::to_string)
        .into_iter()
        .collect::<Vec<_>>();
    let review = app.router.workbench().review();
    if let Some(severity) = review.backlog_severity {
        chips.push(format!("severity:{severity}"));
    }
    if let Some(tool) = review.backlog_tool.as_deref() {
        chips.push(format!("source:{tool}"));
    }
    if let Some(batch_id) = app.router.campaign().active_batch_id.as_deref() {
        chips.push(format!("batch:{batch_id}"));
    }
    chips.extend(FindingSearch::parse(&review.search_query).chips(review.search_capture));
    if chips.is_empty() {
        chips.push(format!("completeness:{}", mode.label()));
    }
    chips
}

fn review_facet_groups(
    app: &ShellApp,
    candidates: &[crate::VisibleFindingProjection],
    review_index: &EffectiveReviewStateIndex,
) -> Vec<ReviewFacetGroup> {
    let mut counts = std::collections::BTreeMap::<(&'static str, String), usize>::new();
    for candidate in candidates {
        for facet in finding_facet_values(&candidate.finding, review_index) {
            *counts.entry((facet.facet, facet.value)).or_default() += 1;
        }
    }
    append_batch_run_facets(app, candidates, &mut counts);
    review_facet_labels(app)
        .into_iter()
        .map(|label| facet_group(label, &counts))
        .collect()
}

fn review_facet_labels(app: &ShellApp) -> Vec<&'static str> {
    let mut labels = vec![
        "severity",
        "source",
        "file",
        "actor",
        "confidence",
        "status",
    ];
    if app.router.campaign().active_batch_report().is_some() {
        labels.push("runs");
    }
    labels
}

fn append_batch_run_facets(
    app: &ShellApp,
    candidates: &[crate::VisibleFindingProjection],
    counts: &mut std::collections::BTreeMap<(&'static str, String), usize>,
) {
    let Some(report) = app.router.campaign().active_batch_report() else {
        return;
    };
    let visible = candidates
        .iter()
        .map(|candidate| &candidate.finding.fingerprint)
        .collect::<std::collections::HashSet<_>>();
    for row in report
        .rows
        .iter()
        .filter(|row| row.fingerprints.iter().any(|value| visible.contains(value)))
    {
        for run_id in &row.run_ids {
            *counts.entry(("runs", run_id.clone())).or_default() += 1;
        }
    }
}

fn facet_group(
    label: &'static str,
    counts: &std::collections::BTreeMap<(&'static str, String), usize>,
) -> ReviewFacetGroup {
    let mut values = counts
        .iter()
        .filter(|((facet, _), _)| *facet == label)
        .map(|((_, value), count)| ReviewFacetCount {
            value: value.clone(),
            count: *count,
        })
        .collect::<Vec<_>>();
    values.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then(left.value.cmp(&right.value))
    });
    ReviewFacetGroup { label, values }
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
            let mut row = ReviewQueueRow::from_finding(
                index,
                projected.alias.clone(),
                &projected.finding,
                decision.as_ref(),
                base,
                batch_occurrence(app, &projected.finding.fingerprint),
            );
            if app
                .domain()
                .review_source_needs_reassessment(&projected.finding)
            {
                row.decision_complete = false;
                row.workflow_group = workflow_group("needs_review", None);
                row.decision.push_str(" · reassess");
                row.next_action = "reassess recorded source".into();
            }
            row
        })
        .collect()
}

fn batch_occurrence(app: &ShellApp, fingerprint: &str) -> Option<ReviewOccurrence> {
    let row = app
        .router
        .campaign()
        .active_batch_report()?
        .rows
        .iter()
        .find(|row| row.fingerprints.iter().any(|value| value == fingerprint))?;
    Some(ReviewOccurrence {
        seen: row.seen,
        completed: row.completed,
        planned: row.planned,
        failed: row.failed,
    })
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
    loaded_count: usize,
    search_active: bool,
    mode: ReviewQueueMode,
) -> Option<String> {
    if visible_count > 0 {
        return None;
    }
    if total_count == 0 {
        return Some(if loaded_count == 0 {
            "no findings loaded for review".to_string()
        } else {
            "no findings match the active loaded-list filters".to_string()
        });
    }
    if search_active {
        return Some("no findings match the active search and filters".to_string());
    }
    review_queue_mode_empty_reason(mode)
}

fn review_queue_mode_empty_reason(mode: ReviewQueueMode) -> Option<String> {
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
        occurrence: Option<ReviewOccurrence>,
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
            proof_confidence_label: finding_confidence_label(finding).to_string(),
            confidence_label: effective_review_confidence_label(finding, decision),
            occurrence,
            priority_label: format!("review-order:{}", index + 1),
            lifecycle_status: lifecycle_status_label(finding),
            decision: decision_label,
            decision_conflict,
            decision_complete: effective_review_decision_complete(finding, decision),
            decision_author: effective_review_author_label(finding, decision),
            title: projection.title,
            location: displayed_location(projection.location, base),
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
    if review_verdict(finding, decision).is_terminal() {
        return "review complete".to_string();
    }
    "review".to_string()
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
