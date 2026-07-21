use super::planning_overview::format_relative_age;
use super::review_conflicts::effective_review_decision_conflict_label;
use super::review_state::{
    effective_review_confidence_label, effective_review_decision_complete,
    effective_review_decision_label, evidence_state_label, lifecycle_status_label,
    EffectiveReviewDecision, EffectiveReviewStateIndex,
};
use super::workspace::findings_db_relative_path;
use super::{context_snapshot_state, SeverityCounts, SeverityTone};
use crate::{
    ScannedSnippetWindow, ShellApp, ViewDataState, VisibleFindingProjection,
    VisibleFindingsCacheKey,
};
use kuzushi_core::findings::{FindingSource, ReviewDecision, VulnSource};
use kuzushi_core::{
    compare_findings_by_confidence, finding_next_action, finding_remediation_hint,
    finding_source_label, project_finding, runtime_validation_summary, static_proof_summary,
    Finding, FindingListFilter, FindingNextAction, FindingProjection, PersistedProofVerdict,
    ProofConfidence, RunSummary, RunTargetGitMetadata, StaticProofState, TriageVerdict,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FINDINGS_PREVIEW_LIMIT: usize = 8;
const FINDING_DETAIL_SECTION_LIMIT: usize = 8;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FindingsModel {
    pub(crate) total: usize,
    pub(crate) triaged: usize,
    pub(crate) pending: usize,
    pub(crate) counts: SeverityCounts,
    pub(crate) header: String,
    pub(crate) reconciliation_header: String,
    pub(crate) cursor: usize,
    pub(crate) empty: FindingsEmptyState,
    pub(crate) selected_out_of_window: Option<String>,
    pub(crate) rows: Vec<FindingListRow>,
    pub(crate) preview: FindingsPreviewModel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingsEmptyState {
    pub(crate) hint: &'static str,
    pub(crate) ledger: String,
    pub(crate) context_cta: Option<(&'static str, &'static str)>,
    pub(crate) filtered_out: Option<FilteredFindingsEmptyState>,
    pub(crate) clean_scan: Option<CleanScanEmptyState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilteredFindingsEmptyState {
    pub(crate) expression: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CleanScanEmptyState {
    pub(crate) summary: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FindingsPreviewModel {
    pub(crate) header: String,
    pub(crate) rows: Vec<FindingListRow>,
    pub(crate) overflow: Option<FindingsPreviewOverflow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingsPreviewOverflow {
    pub(crate) label: String,
    pub(crate) command: &'static str,
    pub(crate) suffix: &'static str,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FindingListRow {
    pub(crate) alias: String,
    pub(crate) identity_label: String,
    pub(crate) severity_tone: SeverityTone,
    pub(crate) severity_label: String,
    pub(crate) title: String,
    pub(crate) location: String,
    pub(crate) run_label: String,
    pub(crate) revision_label: String,
    pub(crate) verdict: String,
    pub(crate) confidence: String,
    pub(crate) priority_label: String,
    pub(crate) lifecycle_status: String,
    pub(crate) decision: String,
    pub(crate) decision_conflict: Option<String>,
    pub(crate) proof_label: String,
    pub(crate) proof_meter: String,
    pub(crate) proof_marker: &'static str,
    pub(crate) proof_tier: ProofTier,
    pub(crate) proof_confidence: ProofConfidence,
    pub(crate) proof_confidence_label: String,
    pub(crate) cwe: String,
    pub(crate) source: String,
    pub(crate) evidence: String,
    pub(crate) selected: bool,
    pub(crate) cursor: bool,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct FindingDetailModel {
    pub(crate) alias: Option<String>,
    pub(crate) identity_label: String,
    pub(crate) severity_tone: SeverityTone,
    pub(crate) severity_label: String,
    pub(crate) title: String,
    pub(crate) location: String,
    pub(crate) rule: String,
    pub(crate) tool: String,
    pub(crate) source_signature: String,
    pub(crate) corroboration: String,
    pub(crate) source_count: usize,
    pub(crate) fingerprint: String,
    pub(crate) run_label: String,
    pub(crate) run_status: String,
    pub(crate) run_tool: String,
    pub(crate) run_model: String,
    pub(crate) run_runtime: String,
    pub(crate) run_kuzushi_version: String,
    pub(crate) revision_label: String,
    pub(crate) branch_label: String,
    pub(crate) vuln_source_label: String,
    pub(crate) proof_label: String,
    pub(crate) proof_meter: String,
    pub(crate) proof_marker: &'static str,
    pub(crate) proof_tier: ProofTier,
    pub(crate) proof_confidence: ProofConfidence,
    pub(crate) proof_confidence_label: String,
    pub(crate) confidence: String,
    pub(crate) lifecycle_status: String,
    pub(crate) decision: String,
    pub(crate) decision_source: String,
    pub(crate) decision_history: String,
    pub(crate) decision_conflict: Option<String>,
    pub(crate) evidence_state: String,
    pub(crate) proof_state: String,
    pub(crate) runtime_verification: String,
    pub(crate) static_proof_label: String,
    pub(crate) static_proof_explanation: String,
    pub(crate) runtime_label: String,
    pub(crate) runtime_explanation: String,
    pub(crate) next_action_label: String,
    pub(crate) next_command: Option<String>,
    pub(crate) next_detail: String,
    pub(crate) remediation_hint: Option<String>,
    pub(crate) evidence: Vec<FindingEvidenceRow>,
    pub(crate) message_lines: Vec<String>,
    pub(crate) message_overflow: usize,
    pub(crate) evidence_overflow: usize,
    pub(crate) triage: Option<TriageSummaryModel>,
    pub(crate) source_snippet: Option<SourceSnippetModel>,
}

/// On-disk source context around the finding's `file_path:start_line`,
/// read through the workbench cache so browsing findings never re-reads
/// the same file per frame. `lines` is empty when `note` explains why the
/// snippet is unavailable (unreadable file, line beyond EOF).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct SourceSnippetModel {
    pub(crate) start_line: usize,
    pub(crate) focus_line: usize,
    pub(crate) lines: Vec<String>,
    pub(crate) note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ProofTier {
    RuntimeVerified,
    StaticLinked,
    #[default]
    Suspected,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingEvidenceRow {
    pub(crate) origin: String,
    pub(crate) header: String,
    pub(crate) snippet: String,
    pub(crate) rationale: String,
    pub(crate) capture: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TriageSummaryModel {
    pub(crate) review_decision: String,
    pub(crate) verdict: String,
    pub(crate) confidence: String,
    pub(crate) author: String,
    pub(crate) source: String,
    pub(crate) rationale: String,
}

pub(crate) fn findings_model(app: &ShellApp) -> FindingsModel {
    let visible = projected_visible_findings(app);
    let review_index = EffectiveReviewStateIndex::from_findings_and_decisions(
        app.findings(),
        app.review_decisions(),
    );
    let rows = finding_rows(app, &visible, &review_index);
    let selected_out_of_window = selected_out_of_window_notice(app, &rows);
    let total = visible.len();
    let triaged = visible_triaged_count(&visible, &review_index);
    let pending = total.saturating_sub(triaged);
    let counts = visible_severity_counts(&visible);
    FindingsModel {
        total,
        triaged,
        pending,
        counts,
        header: findings_header_with_ledger(
            total,
            counts,
            active_component_rel_path(app).as_deref(),
            ledger_population(app),
        ),
        reconciliation_header: findings_reconciliation_header(
            total,
            app.findings().len(),
            active_findings_filter_label(app).as_str(),
            active_component_rel_path(app).as_deref(),
            backlog_reconciliation_state(app),
        ),
        cursor: app.router.findings().cursor().min(total.saturating_sub(1)),
        empty: empty_state(app),
        selected_out_of_window,
        preview: findings_preview(total, triaged, pending, &rows),
        rows,
    }
}

/// Backlog-preset facts the reconciliation header must reflect: the preset
/// hides review-complete rows, adds severity/tool chips, and switches the
/// sort to severity-major — the header claims must track all three.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct BacklogReconciliationState {
    active: bool,
    severity: Option<&'static str>,
    tool: Option<String>,
}

fn backlog_reconciliation_state(app: &ShellApp) -> BacklogReconciliationState {
    if !review_backlog_active(app) {
        return BacklogReconciliationState::default();
    }
    let review = app.router.workbench().review();
    BacklogReconciliationState {
        active: true,
        severity: review.backlog_severity,
        tool: review.backlog_tool.clone(),
    }
}

fn findings_reconciliation_header(
    total: usize,
    loaded: usize,
    active_filter: &str,
    component: Option<&str>,
    backlog: BacklogReconciliationState,
) -> String {
    let mut filters = combined_filter_label(active_filter, component);
    if backlog.active {
        if let Some(severity) = backlog.severity {
            filters = join_filter_label(filters, format!("sev:{severity}"));
        }
        if let Some(tool) = backlog.tool.as_deref() {
            filters = join_filter_label(filters, format!("tool:{tool}"));
        }
    }
    let review = if backlog.active { "open" } else { "all" };
    let sort = if backlog.active {
        "severity"
    } else {
        "priority"
    };
    format!("showing {total} of {loaded} · filters:{filters} · review:{review} · sorted by {sort}")
}

fn join_filter_label(current: String, chip: String) -> String {
    if current == "all" {
        chip
    } else {
        format!("{current} + {chip}")
    }
}

fn active_findings_filter_label(app: &ShellApp) -> String {
    app.active_findings_filter()
        .as_deref()
        .map(str::trim)
        .filter(|filter| !filter.is_empty())
        .unwrap_or("all")
        .to_string()
}

fn combined_filter_label(active_filter: &str, component: Option<&str>) -> String {
    let mut filters = Vec::new();
    if let Some(component) = component {
        filters.push(format!("component:{component}"));
    }
    if active_filter != "all" {
        filters.push(active_filter.to_string());
    }
    if filters.is_empty() {
        "all".to_string()
    } else {
        filters.join(" + ")
    }
}

/// The durable candidate ledger can hold far more rows than this session has
/// loaded (e.g. a long-running campaign written by other sessions). When the
/// populations differ, name the ledger one so the operator can reconcile this
/// pane's count with the ledger-based NEXT banner instead of concluding one
/// of them is wrong.
fn findings_header_with_ledger(
    total: usize,
    counts: SeverityCounts,
    component: Option<&str>,
    ledger_total: Option<usize>,
) -> String {
    let mut parts = vec![format!("FINDINGS · {total}")];
    if let Some(component) = component {
        parts.push(format!("component:{component}"));
    }
    for segment in severity_count_segments(counts) {
        parts.push(segment);
    }
    if let Some(ledger) = ledger_total {
        parts.push(format!("ledger:{ledger}"));
    }
    parts.join(" · ")
}

/// The ledger population, only when it holds MORE than this session loaded —
/// the "481 findings here, 4340 candidates there" confusion. A smaller or
/// matching ledger (fresh in-memory findings not yet persisted) would only
/// add noise.
fn ledger_population(app: &ShellApp) -> Option<usize> {
    let ledger = app.domain().finding_ledger_counts()?.total;
    (ledger > app.findings().len()).then_some(ledger)
}

fn severity_count_segments(counts: SeverityCounts) -> Vec<String> {
    [
        (counts.critical, "C"),
        (counts.high, "H"),
        (counts.medium, "M"),
        (counts.low, "L"),
        (counts.info, "I"),
    ]
    .into_iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, suffix)| format!("{count}{suffix}"))
    .collect()
}

pub(crate) fn selected_finding_detail_model(app: &ShellApp) -> Option<FindingDetailModel> {
    let (alias, finding) = current_finding_for_detail(app)?;
    Some(finding_detail_model_for_projection(app, alias, &finding))
}

pub(crate) fn finding_detail_model_for_projection(
    app: &ShellApp,
    alias: Option<String>,
    finding: &Finding,
) -> FindingDetailModel {
    let review_index = EffectiveReviewStateIndex::from_findings_and_decisions(
        app.findings(),
        app.review_decisions(),
    );
    let decision = review_index.effective_decision_for(finding);
    let runs = run_summary_index(app);
    let provenance = finding_run_provenance(finding, &runs);
    let mut detail = FindingDetailModel::from_finding(
        finding,
        alias,
        target_base(app).as_deref(),
        decision.as_ref(),
        provenance,
    );
    detail.source_snippet = source_snippet_model(app, finding);
    detail
}

pub(crate) const SNIPPET_CONTEXT_BEFORE: usize = 3;
pub(crate) const SNIPPET_CONTEXT_AFTER: usize = 4;

/// Read the finding's source context through the workbench cache. `None`
/// means the finding carries no usable location (no file, line 0, or no
/// way to resolve a relative path without a target); an unreadable file
/// still yields a model whose `note` says why, so the operator learns the
/// snippet is missing rather than wondering where it went. When the live
/// file is missing or has drifted at the cited line, the scanned-time copy
/// from the observation blob store renders instead, labeled as such.
fn source_snippet_model(app: &ShellApp, finding: &Finding) -> Option<SourceSnippetModel> {
    let focus_line = finding.start_line as usize;
    if focus_line == 0 {
        return None;
    }
    let path = finding_source_path(app, finding)?;
    let content = app.workbench_cache().borrow_mut().read_source_file(&path);
    let live = match content {
        Ok(content) => snippet_from_content(&content, focus_line),
        Err(error) => snippet_note(focus_line, format!("source unavailable · {error}")),
    };
    Some(resolve_snippet_with_scanned_copy(app, finding, live))
}

enum ScannedSnippetLookup {
    Window(ScannedSnippetWindow),
    Absent,
    Unknown,
}

fn resolve_snippet_with_scanned_copy(
    app: &ShellApp,
    finding: &Finding,
    live: SourceSnippetModel,
) -> SourceSnippetModel {
    let live_ok = live.note.is_none();
    match cached_scanned_window(app, finding) {
        ScannedSnippetLookup::Window(window) if !live_ok || snippet_is_stale(&live, &window) => {
            scanned_snippet_fallback_model(app, finding, window)
        }
        ScannedSnippetLookup::Absent if !live_ok => append_snippet_note(live, "no scanned copy recorded"),
        _ => live,
    }
}

fn cached_scanned_window(app: &ShellApp, finding: &Finding) -> ScannedSnippetLookup {
    let Some(target) = app.target() else {
        return ScannedSnippetLookup::Unknown;
    };
    let stable_fp = finding
        .identity_id
        .as_deref()
        .unwrap_or(finding.fingerprint.as_str());
    let state = app.workbench_cache().borrow().cached_scanned_snippet(
        target,
        stable_fp,
        finding.scan_id.as_deref(),
        finding.start_line,
    );
    match state {
        ViewDataState::Ready(crate::ScannedSnippetState::Ready(window)) => {
            ScannedSnippetLookup::Window(window)
        }
        ViewDataState::Ready(crate::ScannedSnippetState::Missing) => ScannedSnippetLookup::Absent,
        _ => ScannedSnippetLookup::Unknown,
    }
}

/// Stale when the on-disk focus line no longer matches the scanned copy's
/// focus line under whitespace normalization. An out-of-window comparison
/// (either side missing its focus line) is not judged stale.
fn snippet_is_stale(live: &SourceSnippetModel, scanned: &ScannedSnippetWindow) -> bool {
    let live_line = snippet_focus_text(&live.lines, live.start_line, live.focus_line);
    let scanned_line = snippet_focus_text(&scanned.lines, scanned.start_line, scanned.focus_line);
    match (live_line, scanned_line) {
        (Some(live_line), Some(scanned_line)) => {
            normalized_snippet_line(&live_line) != normalized_snippet_line(&scanned_line)
        }
        _ => false,
    }
}

fn snippet_focus_text(lines: &[String], start_line: usize, focus_line: usize) -> Option<String> {
    lines.get(focus_line.checked_sub(start_line)?).cloned()
}

fn normalized_snippet_line(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn scanned_snippet_fallback_model(
    app: &ShellApp,
    finding: &Finding,
    window: ScannedSnippetWindow,
) -> SourceSnippetModel {
    let sha = scanned_revision_sha(app, finding);
    SourceSnippetModel {
        start_line: window.start_line,
        focus_line: window.focus_line,
        lines: window
            .lines
            .iter()
            .map(|line| line.replace('\t', "  "))
            .collect(),
        note: Some(format!(
            "as scanned @ {sha} — live source missing or changed"
        )),
    }
}

fn scanned_revision_sha(app: &ShellApp, finding: &Finding) -> String {
    let runs = run_summary_index(app);
    finding
        .scan_id
        .as_deref()
        .and_then(|run_id| runs.get(run_id))
        .and_then(|summary| summary.target_git.as_ref())
        .map(|git| compact_git_sha(&git.sha))
        .unwrap_or_else(|| "unknown".to_string())
}

fn append_snippet_note(mut snippet: SourceSnippetModel, suffix: &str) -> SourceSnippetModel {
    snippet.note = Some(match snippet.note.take() {
        Some(note) => format!("{note} · {suffix}"),
        None => suffix.to_string(),
    });
    snippet
}

fn finding_source_path(app: &ShellApp, finding: &Finding) -> Option<std::path::PathBuf> {
    let raw = finding.file_path.trim();
    if raw.is_empty() {
        return None;
    }
    let path = std::path::Path::new(raw);
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    Some(app.target()?.join(path))
}

fn snippet_from_content(content: &str, focus_line: usize) -> SourceSnippetModel {
    let all: Vec<&str> = content.lines().collect();
    if focus_line > all.len() {
        let total = all.len();
        let plural = if total == 1 { "" } else { "s" };
        return snippet_note(
            focus_line,
            format!(
                "line {focus_line} is beyond the on-disk file ({total} line{plural}) · source has changed since the scan"
            ),
        );
    }
    let start_line = focus_line.saturating_sub(SNIPPET_CONTEXT_BEFORE).max(1);
    let end_line = focus_line
        .saturating_add(SNIPPET_CONTEXT_AFTER)
        .min(all.len());
    SourceSnippetModel {
        start_line,
        focus_line,
        lines: all[start_line - 1..end_line]
            .iter()
            .map(|line| line.replace('\t', "  "))
            .collect(),
        note: None,
    }
}

fn snippet_note(focus_line: usize, note: String) -> SourceSnippetModel {
    SourceSnippetModel {
        start_line: focus_line,
        focus_line,
        lines: Vec::new(),
        note: Some(note),
    }
}

pub(crate) fn current_finding_for_detail(app: &ShellApp) -> Option<(Option<String>, Finding)> {
    let visible = projected_visible_findings(app);
    if let Some(finding) = selected_outside_loaded_findings(app, &visible) {
        let alias = cached_alias_for_fingerprint(app, &finding.fingerprint);
        return Some((alias, finding));
    }
    if let Some(projected) = visible.get(app.router.findings().cursor()) {
        return Some((Some(projected.alias.clone()), projected.finding.clone()));
    }
    let finding = app.selected_finding().clone()?;
    let alias = cached_alias_for_fingerprint(app, &finding.fingerprint);
    Some((alias, finding))
}

pub(crate) fn visible_finding_at_cursor(app: &ShellApp) -> Option<(String, Finding)> {
    visible_finding_at_index(app, app.router.findings().cursor())
}

pub(crate) fn visible_finding_at_index(app: &ShellApp, index: usize) -> Option<(String, Finding)> {
    projected_visible_findings(app)
        .get(index)
        .map(|projected| (projected.alias.clone(), projected.finding.clone()))
}

pub(crate) fn finding_identity_label(finding: &Finding) -> String {
    finding
        .identity_id
        .as_deref()
        .filter(|identity| !identity.trim().is_empty())
        .map(compact_identity_id)
        .unwrap_or_else(|| "unassigned".to_string())
}

pub(crate) fn visible_finding_position_for(app: &ShellApp, selected: &Finding) -> Option<usize> {
    let selected_key = engagement_projection_key(selected);
    projected_visible_findings(app)
        .iter()
        .position(|projected| engagement_projection_key(&projected.finding) == selected_key)
}

fn selected_outside_loaded_findings(
    app: &ShellApp,
    visible: &[ProjectedFinding],
) -> Option<Finding> {
    if active_component_rel_path(app).is_some() {
        return None;
    }
    let selected = app.selected_finding().as_ref()?;
    let selected_key = engagement_projection_key(selected);
    let selected_is_loaded = visible
        .iter()
        .any(|projected| engagement_projection_key(&projected.finding) == selected_key);
    (!selected_is_loaded).then_some(selected.clone())
}

fn selected_out_of_window_notice(app: &ShellApp, rows: &[FindingListRow]) -> Option<String> {
    let selected = app.selected_finding().as_ref()?;
    if rows.iter().any(|row| row.selected) {
        return None;
    }
    Some(format!(
        "opened finding is outside the loaded list · {}",
        selected.fingerprint
    ))
}

fn finding_rows(
    app: &ShellApp,
    visible: &[ProjectedFinding],
    review_index: &EffectiveReviewStateIndex,
) -> Vec<FindingListRow> {
    let selected_key = app
        .selected_finding()
        .as_ref()
        .map(engagement_projection_key);
    let base = target_base(app);
    let runs = run_summary_index(app);
    visible
        .iter()
        .enumerate()
        .map(|(row_index, projected)| {
            let provenance = finding_run_provenance(&projected.finding, &runs);
            let decision = review_index.effective_decision_for(&projected.finding);
            FindingListRow::from_finding(
                row_index,
                app.router.findings().cursor(),
                selected_key.as_deref(),
                projected.alias.clone(),
                &projected.finding,
                base.as_deref(),
                provenance,
                decision.as_ref(),
            )
        })
        .collect()
}

pub(crate) fn cached_sorted_finding_alias_indices(app: &ShellApp) -> Vec<(String, usize)> {
    app.workbench_cache()
        .borrow_mut()
        .sorted_finding_alias_indices(app.findings(), app.findings_revision())
}

pub(crate) fn visible_sorted_finding_alias_indices(app: &ShellApp) -> Vec<(String, usize)> {
    let sorted = cached_sorted_finding_alias_indices(app);
    // The backlog preset keeps the severity-major base order (skipping the
    // confidence-first display reorder) so an operator can burn down the
    // untriaged queue worst-severity-first. Explicit toggle only.
    let display_ordered = if review_backlog_active(app) {
        sorted
    } else {
        confidence_first_display_order(app, sorted)
    };
    let component_filtered = component_filtered_finding_alias_indices(app, display_ordered);
    let filtered = active_filter_finding_alias_indices(app, component_filtered);
    backlog_open_only_finding_alias_indices(app, filtered)
}

pub(crate) fn review_backlog_active(app: &ShellApp) -> bool {
    app.router.workbench().review().backlog
}

/// Backlog preset visibility: drop findings whose review is already complete
/// (same completeness rule as the review queue's `open` mode).
fn backlog_open_only_finding_alias_indices(
    app: &ShellApp,
    visible: Vec<(String, usize)>,
) -> Vec<(String, usize)> {
    if !review_backlog_active(app) {
        return visible;
    }
    let review = app.router.workbench().review();
    let severity_filter = review.backlog_severity;
    let tool_filter = review.backlog_tool.clone();
    let review_index = EffectiveReviewStateIndex::from_findings_and_decisions(
        app.findings(),
        app.review_decisions(),
    );
    visible
        .into_iter()
        .filter(|(_, index)| {
            app.findings().get(*index).is_some_and(|finding| {
                let decision = review_index.effective_decision_for(finding);
                !super::review_state::effective_review_decision_complete(finding, decision.as_ref())
                    && backlog_filters_match(finding, severity_filter, tool_filter.as_deref())
            })
        })
        .collect()
}

/// Backlog v2 filters: severity chip (`s`) and tool chip (`t`) narrow the
/// untriaged queue; `None` means the axis is unfiltered.
fn backlog_filters_match(
    finding: &Finding,
    severity: Option<&'static str>,
    tool: Option<&str>,
) -> bool {
    severity.is_none_or(|wanted| finding.severity.as_str() == wanted)
        && tool.is_none_or(|wanted| finding.tool == wanted)
}

/// Re-order the severity-major aliased pairs into confidence-first *display*
/// order (`Confirmed` before `Unverified`, severity as the tie-break). The
/// engagement projection preserves that order after duplicate folding;
/// workflow groups remain row metadata only.
/// Alias strings stay attached to their findings, so `F-0001` identity — and
/// every export/CLI ordering keyed off `sorted_finding_alias_indices` — is
/// unchanged; only the Workbench row/cursor order moves.
fn confidence_first_display_order(
    app: &ShellApp,
    mut sorted: Vec<(String, usize)>,
) -> Vec<(String, usize)> {
    let findings = app.findings();
    sorted.sort_by(|a, b| match (findings.get(a.1), findings.get(b.1)) {
        (Some(left), Some(right)) => compare_findings_by_confidence(left, right),
        _ => std::cmp::Ordering::Equal,
    });
    sorted
}

fn component_filtered_finding_alias_indices(
    app: &ShellApp,
    sorted: Vec<(String, usize)>,
) -> Vec<(String, usize)> {
    let Some(prefix) = active_component_rel_path(app) else {
        return sorted;
    };
    let base = target_base(app);
    sorted
        .into_iter()
        .filter(|(_, index)| {
            app.findings()
                .get(*index)
                .is_some_and(|finding| finding_in_component(finding, &prefix, base.as_deref()))
        })
        .collect()
}

fn active_filter_finding_alias_indices(
    app: &ShellApp,
    visible: Vec<(String, usize)>,
) -> Vec<(String, usize)> {
    let Some(filter) = parsed_active_findings_filter(app) else {
        return visible;
    };
    let review_index = EffectiveReviewStateIndex::from_findings_and_decisions(
        app.findings(),
        app.review_decisions(),
    );
    let runs = run_summary_index(app);
    visible
        .into_iter()
        .filter(|(_, index)| {
            app.findings().get(*index).is_some_and(|finding| {
                finding_matches_active_filter(finding, &filter, &review_index, &runs)
            })
        })
        .collect()
}

fn parsed_active_findings_filter(app: &ShellApp) -> Option<FindingListFilter> {
    let expression = app.active_findings_filter().as_deref()?.trim();
    if expression.is_empty() {
        return None;
    }
    FindingListFilter::from_filter_expression(expression).ok()
}

fn finding_matches_active_filter(
    finding: &Finding,
    filter: &FindingListFilter,
    review_index: &EffectiveReviewStateIndex,
    runs: &BTreeMap<String, RunSummary>,
) -> bool {
    let decision = review_index.effective_decision_for(finding);
    filter.matches_with_review_decision(
        finding,
        decision
            .as_ref()
            .map(EffectiveReviewDecision::review_decision),
    ) && filter.matches_run_provenance(finding, runs)
}

pub(crate) fn visible_findings_len(app: &ShellApp) -> usize {
    projected_visible_findings(app).len()
}

fn cached_alias_for_fingerprint(app: &ShellApp, fingerprint: &str) -> Option<String> {
    cached_sorted_finding_alias_indices(app)
        .into_iter()
        .find_map(|(alias, index)| {
            app.findings()
                .get(index)
                .is_some_and(|finding| finding.fingerprint == fingerprint)
                .then_some(alias)
        })
}

/// The canonical absolute target path, used to relativize finding locations so
/// the list shows `crates/foo.rs:12` instead of a full `/Users/...` path. Shared
/// with the Map and Review projections so every surface relativizes identically.
pub(crate) fn target_base(app: &ShellApp) -> Option<String> {
    match app
        .workbench_cache()
        .borrow()
        .cached_target_base(app.target())
    {
        crate::app::ViewDataState::Ready(base) => Some(base),
        crate::app::ViewDataState::NotRequested | crate::app::ViewDataState::Loading => None,
    }
}

/// Strip the target prefix from a `path:line` location when present, leaving a
/// repo-relative path; otherwise return it unchanged.
pub(crate) fn relativize_location(location: String, base: Option<&str>) -> String {
    let Some(base) = base else {
        return location;
    };
    match location.strip_prefix(base) {
        Some(rest) => rest.trim_start_matches('/').to_string(),
        None => location,
    }
}

type ProjectedFinding = VisibleFindingProjection;

pub(crate) fn projected_visible_findings(app: &ShellApp) -> Arc<[ProjectedFinding]> {
    let key = visible_findings_cache_key(app);
    if let Some(cached) = app.workbench_cache().borrow().visible_findings(&key) {
        return cached;
    }
    let projected: Arc<[ProjectedFinding]> =
        engagement_projected_findings(app, visible_sorted_finding_alias_indices(app)).into();
    app.workbench_cache()
        .borrow_mut()
        .cache_visible_findings(key, Arc::clone(&projected));
    projected
}

pub(crate) fn visible_findings_cache_key(app: &ShellApp) -> VisibleFindingsCacheKey {
    VisibleFindingsCacheKey::from_app_parts(
        app.findings_revision(),
        app.review_decisions_revision(),
        target_base(app),
        active_component_rel_path(app),
        active_findings_filter_cache_value(app),
    )
}

fn active_findings_filter_cache_value(app: &ShellApp) -> Option<String> {
    let filter = app
        .active_findings_filter()
        .as_deref()
        .map(str::trim)
        .filter(|filter| !filter.is_empty())
        .map(ToString::to_string);
    // The backlog preset changes visibility and ordering, so it must key the
    // projection cache alongside the filter expression.
    if review_backlog_active(app) {
        // Severity/tool filters change visibility, so they must key the
        // cache too — a chip toggle with unchanged revisions must not
        // serve stale rows.
        let review = app.router.workbench().review();
        return Some(format!(
            "[backlog sev:{} tool:{}]{}",
            review.backlog_severity.unwrap_or("*"),
            review.backlog_tool.as_deref().unwrap_or("*"),
            filter.unwrap_or_default()
        ));
    }
    filter
}

#[cfg(test)]
pub(crate) fn projected_visible_finding_pairs(app: &ShellApp) -> Vec<(String, Finding)> {
    projected_visible_findings(app)
        .iter()
        .map(|projected| (projected.alias.clone(), projected.finding.clone()))
        .collect()
}

fn engagement_projected_findings(
    app: &ShellApp,
    visible: Vec<(String, usize)>,
) -> Vec<ProjectedFinding> {
    let mut groups = Vec::<ProjectedFinding>::new();
    let mut group_index = BTreeMap::<String, usize>::new();
    for (alias, index) in visible {
        let Some(finding) = app.findings().get(index).cloned() else {
            continue;
        };
        let key = engagement_projection_key(&finding);
        if let Some(position) = group_index.get(&key).copied() {
            merge_projected_finding(&mut groups[position], alias, finding);
        } else {
            let position = groups.len();
            group_index.insert(key, position);
            groups.push(VisibleFindingProjection { alias, finding });
        }
    }
    groups
}

fn engagement_projection_key(finding: &Finding) -> String {
    finding
        .dedup_key
        .clone()
        .unwrap_or_else(|| finding.fingerprint.clone())
}

fn merge_projected_finding(projected: &mut ProjectedFinding, alias: String, finding: Finding) {
    let previous = projected.finding.clone();
    let next_sources = finding.sources.clone();
    let next_count = finding.corroboration_count;
    let mut representative = if finding_rank(&finding) > finding_rank(&previous) {
        projected.alias = alias;
        finding
    } else {
        previous.clone()
    };
    representative.sources = merged_sources(&previous.sources, &next_sources);
    representative.corroboration_count = merged_corroboration_count(
        previous.corroboration_count,
        next_count,
        representative.sources.len(),
    );
    projected.finding = representative;
}

fn finding_rank(finding: &Finding) -> (u8, u8) {
    (severity_rank(finding), proof_rank(finding))
}

fn severity_rank(finding: &Finding) -> u8 {
    match finding.severity {
        kuzushi_core::Severity::Critical => 5,
        kuzushi_core::Severity::High => 4,
        kuzushi_core::Severity::Medium => 3,
        kuzushi_core::Severity::Low => 2,
        kuzushi_core::Severity::Info => 1,
        kuzushi_core::Severity::Unknown => 0,
    }
}

fn proof_rank(finding: &Finding) -> u8 {
    // Higher rank = stronger proof, used only to pick the representative among
    // duplicates. Delegates to the canonical confidence classifier so the dedup
    // representative and the confidence chip agree. `rank()` is 0=Confirmed..
    // 3=Dismissed, so invert to keep "higher = stronger" here.
    3u8.saturating_sub(ProofConfidence::classify(finding).rank())
}

fn merged_sources(left: &[FindingSource], right: &[FindingSource]) -> Vec<FindingSource> {
    let mut by_key = BTreeMap::<String, FindingSource>::new();
    for source in left.iter().chain(right.iter()) {
        by_key.insert(
            format!(
                "{}\0{}\0{}",
                source.tool, source.source_signature, source.last_scan_id
            ),
            source.clone(),
        );
    }
    by_key.into_values().collect()
}

fn merged_corroboration_count(left: u32, right: u32, merged_source_count: usize) -> u32 {
    if merged_source_count > 0 {
        return merged_source_count as u32;
    }
    left.max(1).saturating_add(right.max(1))
}

fn visible_triaged_count(
    visible: &[ProjectedFinding],
    review_index: &EffectiveReviewStateIndex,
) -> usize {
    visible
        .iter()
        .map(|projected| &projected.finding)
        .filter(|finding| {
            let decision = review_index.effective_decision_for(finding);
            effective_review_decision_complete(finding, decision.as_ref())
        })
        .count()
}

fn visible_severity_counts(visible: &[ProjectedFinding]) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for projected in visible {
        counts.add(projected.finding.severity);
    }
    counts
}

fn active_component_rel_path(app: &ShellApp) -> Option<String> {
    let active = app.active_scope()?;
    if active.rel_path == "." || active.rel_path.trim().is_empty() {
        return None;
    }
    let target = app.target()?;
    let state = app
        .workbench_cache()
        .borrow()
        .cached_project_scope_tree(Some(target));
    let ViewDataState::Ready(state) = state else {
        return None;
    };
    let tree = match &state {
        crate::app::ProjectScopeTreeState::Persisted(tree) => tree,
        crate::app::ProjectScopeTreeState::RootOnly
        | crate::app::ProjectScopeTreeState::Unreadable(_) => return None,
    };
    let in_active_component = tree.non_root_scopes().any(|scope| {
        scope.id == active.id
            && scope.rel_path == active.rel_path
            && matches!(
                scope.kind,
                kuzushi_core::NestedProjectKind::Submodule
                    | kuzushi_core::NestedProjectKind::PackageRoot
                    | kuzushi_core::NestedProjectKind::EntrypointCluster
            )
    });
    in_active_component.then(|| active.rel_path.trim_matches('/').to_string())
}

fn finding_in_component(finding: &Finding, prefix: &str, base: Option<&str>) -> bool {
    let path = normalize_repo_path(&relativize_location(finding.file_path.clone(), base));
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn normalize_repo_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("./")
        .trim_matches('/')
        .to_string()
}

fn empty_state(app: &ShellApp) -> FindingsEmptyState {
    let mut state = context_empty_state(context_snapshot_state(app));
    state.filtered_out = filtered_empty_state(app);
    state.clean_scan = clean_scan_empty_state(&run_summary_index(app), SystemTime::now());
    state
}

fn filtered_empty_state(app: &ShellApp) -> Option<FilteredFindingsEmptyState> {
    app.active_findings_filter()
        .as_deref()
        .map(str::trim)
        .filter(|filter| !filter.is_empty())
        .map(|filter| FilteredFindingsEmptyState {
            expression: filter.to_string(),
        })
}

fn context_empty_state(context_state: &'static str) -> FindingsEmptyState {
    let (hint, context_cta) = match context_state {
        "present" => (
            "opens the guided Scan workflow for the active target.",
            None,
        ),
        "malformed" => (
            "context snapshot is malformed; rebuild it before scanning.",
            Some(("context build", "rewrite the malformed snapshot first")),
        ),
        _ => (
            "opens the guided workflow for the target.",
            Some((
                "context build",
                "optional: index the repo first for richer analysis.",
            )),
        ),
    };
    FindingsEmptyState {
        hint,
        ledger: format!("ledger: {}", findings_db_relative_path()),
        context_cta,
        filtered_out: None,
        clean_scan: None,
    }
}

fn clean_scan_empty_state(
    runs: &BTreeMap<String, RunSummary>,
    now: SystemTime,
) -> Option<CleanScanEmptyState> {
    let summary = latest_scan_summary(runs)?;
    if summary.status != "completed" || summary.findings != Some(0) {
        return None;
    }
    Some(CleanScanEmptyState {
        summary: format!(
            "scanned {} · 0 findings · run:{}",
            completed_age(summary, now),
            compact_run_id(&summary.run_id)
        ),
    })
}

fn latest_scan_summary(runs: &BTreeMap<String, RunSummary>) -> Option<&RunSummary> {
    runs.values()
        .filter(|summary| summary.kind == "scan")
        .max_by_key(|summary| summary.completed_at_unix.unwrap_or(summary.started_at_unix))
}

fn completed_age(summary: &RunSummary, now: SystemTime) -> String {
    summary
        .completed_at_unix
        .and_then(system_time_from_unix)
        .and_then(|completed| format_relative_age(now, completed))
        .unwrap_or_else(|| "recently".to_string())
}

fn system_time_from_unix(unix: u64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_secs(unix))
}

fn findings_preview(
    total: usize,
    triaged: usize,
    pending: usize,
    rows: &[FindingListRow],
) -> FindingsPreviewModel {
    FindingsPreviewModel {
        header: format!("FINDINGS · {triaged} triaged · {pending} pending"),
        rows: rows.iter().take(FINDINGS_PREVIEW_LIMIT).cloned().collect(),
        overflow: findings_preview_overflow(total),
    }
}

fn findings_preview_overflow(total: usize) -> Option<FindingsPreviewOverflow> {
    (total > FINDINGS_PREVIEW_LIMIT).then(|| FindingsPreviewOverflow {
        label: format!("… {} more · ", total - FINDINGS_PREVIEW_LIMIT),
        command: "/findings",
        suffix: " to drill in",
    })
}

impl FindingListRow {
    fn from_finding(
        index: usize,
        cursor: usize,
        selected_key: Option<&str>,
        alias: String,
        finding: &Finding,
        base: Option<&str>,
        provenance: FindingRunProvenance,
        decision: Option<&EffectiveReviewDecision>,
    ) -> Self {
        let projection = project_finding(finding, Some(alias.clone()));
        let proof = finding_proof_badge(finding);
        Self {
            alias,
            identity_label: finding_identity_label(finding),
            severity_tone: SeverityTone::from_severity(projection.severity),
            severity_label: projection.severity_label,
            title: projection.title,
            location: relativize_location(projection.location, base),
            run_label: provenance.run_label,
            revision_label: provenance.revision_label,
            verdict: projection.verdict_label,
            confidence: effective_review_confidence_label(finding, decision),
            priority_label: format!("p:{}", index + 1),
            lifecycle_status: lifecycle_status_label(finding),
            decision: effective_review_decision_label(finding, decision),
            decision_conflict: effective_review_decision_conflict_label(finding, decision),
            proof_label: proof.label,
            proof_meter: finding_proof_meter(finding),
            proof_marker: proof.marker,
            proof_tier: proof.tier,
            proof_confidence: ProofConfidence::classify(finding),
            proof_confidence_label: ProofConfidence::classify(finding).label().to_string(),
            cwe: projection.cwe_label,
            source: finding_source_summary_label(finding),
            evidence: projection.evidence_preview,
            selected: selected_key.is_some_and(|key| key == engagement_projection_key(finding)),
            cursor: cursor == index,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProofBadge {
    label: String,
    marker: &'static str,
    tier: ProofTier,
}

#[cfg(test)]
fn finding_proof_label(finding: &Finding) -> String {
    finding_proof_badge(finding).label
}

fn finding_proof_badge(finding: &Finding) -> ProofBadge {
    runtime_proof_label(finding)
        .or_else(|| static_proof_label(finding))
        .unwrap_or_else(|| proof_badge("unverified", ProofTier::Suspected))
}

pub(crate) fn finding_proof_meter(finding: &Finding) -> String {
    match finding_proof_badge(finding).tier {
        ProofTier::RuntimeVerified => "[●●●]".to_string(),
        ProofTier::StaticLinked => "[●●○]".to_string(),
        ProofTier::Suspected => "[●○○]".to_string(),
        ProofTier::Rejected => "[×××]".to_string(),
    }
}

pub(crate) fn finding_unique_source_count(finding: &Finding) -> usize {
    let unique = finding
        .sources
        .iter()
        .map(|source| (&source.tool, &source.source_signature))
        .collect::<BTreeSet<_>>()
        .len();
    unique.max(finding.corroboration_count as usize)
}

fn runtime_proof_label(finding: &Finding) -> Option<ProofBadge> {
    let verification = finding.verification.as_ref()?;
    Some(match verification.proof_verdict {
        PersistedProofVerdict::Exploited => proof_badge(
            format!("verified L{}", verification.proof_level),
            ProofTier::RuntimeVerified,
        ),
        PersistedProofVerdict::NotReproduced => proof_badge("not-repro", ProofTier::Rejected),
        PersistedProofVerdict::HarnessFailedToBuild => {
            proof_badge("verify-build", ProofTier::Rejected)
        }
        PersistedProofVerdict::InfrastructureError => {
            proof_badge("verify-infra", ProofTier::Rejected)
        }
        PersistedProofVerdict::LanguageUnsupportedYet => {
            proof_badge("unsupported", ProofTier::Suspected)
        }
        PersistedProofVerdict::InsufficientFindingDetail => {
            proof_badge("needs-detail", ProofTier::Suspected)
        }
    })
}

fn static_proof_label(finding: &Finding) -> Option<ProofBadge> {
    match finding.static_proof_state? {
        StaticProofState::StaticallyConfirmed => {
            Some(proof_badge("static-supported", ProofTier::StaticLinked))
        }
        StaticProofState::StaticallyRejected => Some(proof_badge("static-no", ProofTier::Rejected)),
        StaticProofState::SourceSinkLinked | StaticProofState::SanitizerChecked => {
            Some(proof_badge("path-linked", ProofTier::StaticLinked))
        }
        StaticProofState::CodeCited => Some(proof_badge("code-cited", ProofTier::StaticLinked)),
        StaticProofState::NeedsRuntimeEvidence => {
            Some(proof_badge("needs-runtime", ProofTier::Suspected))
        }
        StaticProofState::SignalOnly => Some(proof_badge("signal-only", ProofTier::Suspected)),
    }
}

fn proof_badge(label: impl Into<String>, tier: ProofTier) -> ProofBadge {
    ProofBadge {
        label: label.into(),
        marker: proof_tier_marker(tier),
        tier,
    }
}

fn proof_tier_marker(tier: ProofTier) -> &'static str {
    match tier {
        ProofTier::RuntimeVerified => "✓",
        ProofTier::StaticLinked => "◇",
        ProofTier::Suspected => "?",
        ProofTier::Rejected => "!",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FindingRunProvenance {
    run_label: String,
    revision_label: String,
    branch_label: String,
    status_label: String,
    tool_label: String,
    model_label: String,
    runtime_label: String,
    kuzushi_version_label: String,
}

fn run_summary_index(app: &ShellApp) -> BTreeMap<String, RunSummary> {
    match app
        .workbench_cache()
        .borrow()
        .cached_run_summary_index(app.target())
    {
        ViewDataState::Ready(index) => index,
        ViewDataState::NotRequested | ViewDataState::Loading => BTreeMap::new(),
    }
}

fn finding_run_provenance(
    finding: &Finding,
    runs: &BTreeMap<String, RunSummary>,
) -> FindingRunProvenance {
    let Some(run_id) = finding
        .scan_id
        .as_deref()
        .filter(|run_id| !run_id.is_empty())
    else {
        return missing_run_provenance();
    };
    let summary = runs.get(run_id);
    FindingRunProvenance {
        run_label: format!("run:{}", compact_run_id(run_id)),
        revision_label: summary
            .and_then(run_revision_label)
            .unwrap_or_else(|| "rev:unknown".to_string()),
        branch_label: run_branch_label(summary),
        status_label: run_status_label(summary),
        tool_label: run_tool_label(summary),
        model_label: run_model_label(summary),
        runtime_label: run_runtime_label(summary),
        kuzushi_version_label: run_kuzushi_version_label(summary),
    }
}

fn missing_run_provenance() -> FindingRunProvenance {
    FindingRunProvenance {
        run_label: "run:unknown".to_string(),
        revision_label: "rev:unknown".to_string(),
        branch_label: "branch:unknown".to_string(),
        status_label: "-".to_string(),
        tool_label: "-".to_string(),
        model_label: "-".to_string(),
        runtime_label: "-".to_string(),
        kuzushi_version_label: "-".to_string(),
    }
}

fn run_revision_label(summary: &RunSummary) -> Option<String> {
    summary.target_git.as_ref().map(target_git_revision_label)
}

/// Branch of the *target* repository at scan time. `RunSummary.git_branch`
/// is the Kuzushi build's own branch, so only `target_git` may supply this.
fn run_branch_label(summary: Option<&RunSummary>) -> String {
    summary
        .and_then(|summary| summary.target_git.as_ref())
        .and_then(|git| git.branch.as_deref())
        .filter(|branch| !branch.is_empty())
        .map(|branch| format!("branch:{branch}"))
        .unwrap_or_else(|| "branch:unknown".to_string())
}

fn run_status_label(summary: Option<&RunSummary>) -> String {
    prefixed_run_label("status", summary.map(|summary| summary.status.as_str()))
}

fn run_tool_label(summary: Option<&RunSummary>) -> String {
    prefixed_run_label("tool", summary.and_then(|summary| summary.tool.as_deref()))
}

fn run_model_label(summary: Option<&RunSummary>) -> String {
    prefixed_run_label(
        "model",
        summary.and_then(|summary| summary.model.as_deref()),
    )
}

fn run_runtime_label(summary: Option<&RunSummary>) -> String {
    prefixed_run_label(
        "runtime",
        summary.and_then(|summary| summary.platform.as_deref()),
    )
}

fn run_kuzushi_version_label(summary: Option<&RunSummary>) -> String {
    prefixed_run_label(
        "kuzushi",
        summary.and_then(|summary| summary.kuzushi_version.as_deref()),
    )
}

fn prefixed_run_label(prefix: &str, value: Option<&str>) -> String {
    value
        .map(|value| format!("{prefix}:{value}"))
        .unwrap_or_else(|| "-".to_string())
}

fn target_git_revision_label(git: &RunTargetGitMetadata) -> String {
    format!(
        "rev:{}{}",
        compact_git_sha(&git.sha),
        if git.dirty { "*" } else { "" }
    )
}

fn compact_run_id(run_id: &str) -> String {
    compact_middle(run_id, 6, 4, 14)
}

fn compact_git_sha(sha: &str) -> String {
    sha.chars().take(7).collect()
}

fn compact_middle(value: &str, head: usize, tail: usize, max_len: usize) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() <= max_len {
        return value.to_string();
    }
    let prefix = chars.iter().take(head).collect::<String>();
    let suffix = chars
        .iter()
        .skip(chars.len().saturating_sub(tail))
        .collect::<String>();
    format!("{prefix}..{suffix}")
}

impl FindingDetailModel {
    fn from_finding(
        finding: &Finding,
        alias: Option<String>,
        base: Option<&str>,
        decision: Option<&EffectiveReviewDecision>,
        provenance: FindingRunProvenance,
    ) -> Self {
        let projection = project_finding(finding, alias);
        let proof = finding_proof_badge(finding);
        let status = detail_status_fields(finding, projection.alias.as_deref(), decision);
        let body = detail_body_fields(finding, decision);
        Self::from_parts(finding, projection, proof, status, body, base, provenance)
    }

    fn from_parts(
        finding: &Finding,
        projection: FindingProjection,
        proof: ProofBadge,
        status: DetailStatusFields,
        body: DetailBodyFields,
        base: Option<&str>,
        provenance: FindingRunProvenance,
    ) -> Self {
        let mut detail = Self::from_projection(finding, projection, base);
        detail.apply_proof_fields(finding, proof);
        detail.apply_provenance_fields(provenance);
        detail.apply_status_fields(status);
        detail.apply_body_fields(body);
        detail
    }

    fn from_projection(
        finding: &Finding,
        projection: FindingProjection,
        base: Option<&str>,
    ) -> Self {
        let confidence = ProofConfidence::classify(finding);
        Self {
            alias: projection.alias,
            identity_label: finding_identity_label(finding),
            severity_tone: SeverityTone::from_severity(projection.severity),
            severity_label: finding.severity.as_str().to_string(),
            title: projection.title,
            location: relativize_location(projection.location, base),
            rule: projection.rule,
            tool: projection.tool,
            vuln_source_label: vuln_source_label(finding),
            source_signature: source_signature_label(finding),
            corroboration: corroboration_label(finding),
            source_count: finding_unique_source_count(finding),
            fingerprint: projection.fingerprint,
            proof_confidence: confidence,
            proof_confidence_label: confidence.label().to_string(),
            proof_state: projection.proof_state,
            runtime_verification: projection.runtime_validation,
            ..Self::default()
        }
    }

    fn apply_provenance_fields(&mut self, provenance: FindingRunProvenance) {
        self.run_label = provenance.run_label;
        self.run_status = provenance.status_label;
        self.run_tool = provenance.tool_label;
        self.run_model = provenance.model_label;
        self.run_runtime = provenance.runtime_label;
        self.run_kuzushi_version = provenance.kuzushi_version_label;
        self.revision_label = provenance.revision_label;
        self.branch_label = provenance.branch_label;
    }

    fn apply_proof_fields(&mut self, finding: &Finding, proof: ProofBadge) {
        self.proof_label = proof.label;
        self.proof_meter = finding_proof_meter(finding);
        self.proof_marker = proof.marker;
        self.proof_tier = proof.tier;
    }

    fn apply_status_fields(&mut self, status: DetailStatusFields) {
        self.confidence = status.confidence;
        self.lifecycle_status = status.lifecycle_status;
        self.decision = status.decision;
        self.decision_source = status.decision_source;
        self.decision_history = status.decision_history;
        self.decision_conflict = status.decision_conflict;
        self.evidence_state = status.evidence_state;
        self.static_proof_label = status.static_proof_label;
        self.static_proof_explanation = status.static_proof_explanation;
        self.runtime_label = status.runtime_label;
        self.runtime_explanation = status.runtime_explanation;
        self.next_action_label = status.next_action_label;
        self.next_command = status.next_command;
        self.next_detail = status.next_detail;
        self.remediation_hint = status.remediation_hint;
    }

    fn apply_body_fields(&mut self, body: DetailBodyFields) {
        self.evidence = body.evidence;
        self.message_lines = body.message_lines;
        self.message_overflow = body.message_overflow;
        self.evidence_overflow = body.evidence_overflow;
        self.triage = body.triage;
    }
}

fn compact_identity_id(identity_id: &str) -> String {
    let trimmed = identity_id.trim();
    if let Some(suffix) = trimmed.strip_prefix("fi_") {
        let compact = suffix.chars().take(8).collect::<String>();
        return format!("FI-{}", compact.to_ascii_uppercase());
    }
    if trimmed.chars().count() <= 12 {
        return trimmed.to_string();
    }
    // Never clip mid-word without saying so — a bare cut reads as the
    // actual identity ("phase-findin").
    let prefix: String = trimmed.chars().take(11).collect();
    format!("{prefix}…")
}

struct DetailStatusFields {
    static_proof_label: String,
    static_proof_explanation: String,
    runtime_label: String,
    runtime_explanation: String,
    next_action_label: String,
    next_command: Option<String>,
    next_detail: String,
    remediation_hint: Option<String>,
    confidence: String,
    lifecycle_status: String,
    decision: String,
    decision_source: String,
    decision_history: String,
    decision_conflict: Option<String>,
    evidence_state: String,
}

fn detail_status_fields(
    finding: &Finding,
    alias: Option<&str>,
    decision: Option<&EffectiveReviewDecision>,
) -> DetailStatusFields {
    let static_proof = static_proof_summary(finding.static_proof_state);
    let runtime = runtime_validation_summary(finding.verification.as_ref());
    let next = next_action_display(finding_next_action(finding, None), alias);
    DetailStatusFields {
        static_proof_label: static_proof.label.to_string(),
        static_proof_explanation: static_proof.explanation.to_string(),
        runtime_label: runtime.label,
        runtime_explanation: runtime.explanation.to_string(),
        next_action_label: next.label.to_string(),
        next_command: next.command,
        next_detail: next.detail.to_string(),
        remediation_hint: finding_remediation_hint(finding),
        confidence: effective_review_confidence_label(finding, decision),
        lifecycle_status: lifecycle_status_label(finding),
        decision: effective_review_decision_label(finding, decision),
        decision_source: effective_review_source_label(finding, decision),
        decision_history: decision_history_summary(finding, decision),
        decision_conflict: effective_review_decision_conflict_label(finding, decision),
        evidence_state: evidence_state_label(finding),
    }
}

fn effective_review_source_label(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> String {
    decision
        .map(|decision| decision.source_label().to_string())
        .unwrap_or_else(|| {
            finding
                .triage
                .as_ref()
                .map(|_| "selected finding".to_string())
                .unwrap_or_else(|| "none".to_string())
        })
}

fn decision_history_summary(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> String {
    if let Some(decision) = decision {
        return format!("latest loaded decision from {}", decision.source_label());
    }
    if finding.triage.is_some() {
        return "latest loaded decision from selected finding".to_string();
    }
    "no decision history loaded".to_string()
}

struct DetailBodyFields {
    evidence: Vec<FindingEvidenceRow>,
    message_lines: Vec<String>,
    message_overflow: usize,
    evidence_overflow: usize,
    triage: Option<TriageSummaryModel>,
}

fn detail_body_fields(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> DetailBodyFields {
    let message_lines = finding
        .message
        .lines()
        .take(FINDING_DETAIL_SECTION_LIMIT)
        .map(str::to_string)
        .collect::<Vec<_>>();
    DetailBodyFields {
        evidence: evidence_rows(finding),
        message_overflow: finding
            .message
            .lines()
            .count()
            .saturating_sub(message_lines.len()),
        evidence_overflow: finding
            .evidence
            .len()
            .saturating_sub(FINDING_DETAIL_SECTION_LIMIT),
        message_lines,
        triage: finding_triage_summary(finding, decision),
    }
}

struct NextActionDisplay {
    label: &'static str,
    command: Option<String>,
    detail: &'static str,
}

fn next_action_display(action: FindingNextAction, alias: Option<&str>) -> NextActionDisplay {
    let alias = alias.unwrap_or("selected");
    match action {
        FindingNextAction::Validate => NextActionDisplay {
            label: action.as_str(),
            command: Some(format!("verify {alias}")),
            detail: "collect runtime proof or stronger source evidence before patching",
        },
        FindingNextAction::Patch => NextActionDisplay {
            label: action.as_str(),
            command: Some(format!("patch {alias}")),
            detail: "runtime proof is recorded; generate remediation",
        },
        FindingNextAction::Suppress => NextActionDisplay {
            label: action.as_str(),
            command: None,
            detail: "review the rejection evidence before suppressing",
        },
        FindingNextAction::Review => NextActionDisplay {
            label: action.as_str(),
            command: None,
            detail: "review the finding and keep evidence attached",
        },
    }
}

impl FindingEvidenceRow {
    fn from_evidence(evidence: &kuzushi_core::FindingEvidence) -> Self {
        Self {
            origin: evidence_origin_label(evidence).to_string(),
            header: format!(
                "{} · conf {} · {}:{}",
                evidence.kind, evidence.confidence, evidence.file_path, evidence.line
            ),
            snippet: evidence.snippet.clone(),
            rationale: evidence.rationale.clone(),
            capture: evidence_capture_summary(evidence),
        }
    }
}

fn evidence_origin_label(evidence: &kuzushi_core::FindingEvidence) -> &'static str {
    if evidence.kind.trim().eq_ignore_ascii_case("reasoning") {
        return "model-generated reasoning";
    }
    if evidence.request_blob.is_some() || evidence.response_blob.is_some() {
        return "observed capture evidence";
    }
    if !evidence.file_path.trim().is_empty() || !evidence.snippet.trim().is_empty() {
        return "observed code evidence";
    }
    "observed evidence"
}

fn evidence_capture_summary(evidence: &kuzushi_core::FindingEvidence) -> Option<String> {
    let mut artifacts = Vec::new();
    if evidence.request_blob.is_some() {
        artifacts.push("request body recorded");
    }
    if evidence.response_blob.is_some() {
        artifacts.push("response body recorded");
    }
    (!artifacts.is_empty()).then(|| format!("http capture: {}", artifacts.join(", ")))
}

fn finding_triage_summary(
    finding: &Finding,
    decision: Option<&EffectiveReviewDecision>,
) -> Option<TriageSummaryModel> {
    if let Some(decision) = decision {
        return Some(effective_triage_summary(decision));
    }
    raw_finding_triage_summary(finding)
}

fn effective_triage_summary(decision: &EffectiveReviewDecision) -> TriageSummaryModel {
    TriageSummaryModel {
        review_decision: decision.decision_label(),
        verdict: decision
            .triage_verdict_label()
            .unwrap_or("not_applicable")
            .to_string(),
        confidence: decision.confidence_label(),
        author: decision.author_label(),
        source: decision.source_label().to_string(),
        rationale: decision.rationale().to_string(),
    }
}

fn raw_finding_triage_summary(finding: &Finding) -> Option<TriageSummaryModel> {
    let triage = finding.triage.as_ref()?;
    let decision = ReviewDecision::from_triage(triage, finding.triaged_by);
    Some(TriageSummaryModel {
        review_decision: decision.verdict.as_str().to_string(),
        verdict: triage.verdict.as_str().to_string(),
        confidence: format!("{:.2}", triage.confidence),
        author: finding
            .triaged_by
            .map(|author| author.as_str().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        source: "selected finding".to_string(),
        rationale: triage.rationale.clone(),
    })
}

fn finding_source_summary_label(finding: &Finding) -> String {
    let source = finding_source_label(finding);
    match finding.corroboration_count {
        count if count > 1 => format!("{source} · corroboration {count}"),
        _ => source,
    }
}

fn source_signature_label(finding: &Finding) -> String {
    finding
        .source_signature
        .clone()
        .unwrap_or_else(|| "-".to_string())
}

fn vuln_source_label(finding: &Finding) -> String {
    finding
        .vuln_source
        .map(VulnSource::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| "-".to_string())
}

fn corroboration_label(finding: &Finding) -> String {
    if finding.sources.is_empty() {
        return finding.corroboration_count.to_string();
    }
    let tools = finding
        .sources
        .iter()
        .map(|source| source.tool.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    format!("{} ({tools})", finding.sources.len())
}

fn evidence_rows(finding: &Finding) -> Vec<FindingEvidenceRow> {
    finding
        .evidence
        .iter()
        .take(FINDING_DETAIL_SECTION_LIMIT)
        .map(FindingEvidenceRow::from_evidence)
        .collect()
}

#[cfg(test)]
mod tests;
