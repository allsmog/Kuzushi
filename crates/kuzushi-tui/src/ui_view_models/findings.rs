use super::planning_overview::format_relative_age;
use super::workspace::findings_db_relative_path;
use super::{context_snapshot_state, SeverityCounts, SeverityTone};
use crate::ShellApp;
use kuzushi_core::{
    finding_next_action, finding_remediation_hint, finding_source_label, project_finding,
    runtime_validation_summary, static_proof_summary, Finding, FindingNextAction,
    FindingProjection, PersistedProofVerdict, RunSummary, RunTargetGitMetadata, StaticProofState,
    TriageVerdict,
};
use std::collections::BTreeMap;
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
    pub(crate) clean_scan: Option<CleanScanEmptyState>,
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
    pub(crate) severity_tone: SeverityTone,
    pub(crate) severity_label: String,
    pub(crate) title: String,
    pub(crate) location: String,
    pub(crate) run_label: String,
    pub(crate) revision_label: String,
    pub(crate) verdict: String,
    pub(crate) confidence: String,
    pub(crate) proof_label: String,
    pub(crate) proof_marker: &'static str,
    pub(crate) proof_tier: ProofTier,
    pub(crate) cwe: String,
    pub(crate) source: String,
    pub(crate) evidence: String,
    pub(crate) selected: bool,
    pub(crate) cursor: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FindingDetailModel {
    pub(crate) alias: Option<String>,
    pub(crate) severity_tone: SeverityTone,
    pub(crate) severity_label: String,
    pub(crate) title: String,
    pub(crate) location: String,
    pub(crate) rule: String,
    pub(crate) tool: String,
    pub(crate) fingerprint: String,
    pub(crate) proof_label: String,
    pub(crate) proof_marker: &'static str,
    pub(crate) proof_tier: ProofTier,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProofTier {
    RuntimeVerified,
    Confirmed,
    StaticLinked,
    Suspected,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingEvidenceRow {
    pub(crate) header: String,
    pub(crate) snippet: String,
    pub(crate) rationale: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TriageSummaryModel {
    pub(crate) verdict: String,
    pub(crate) confidence: String,
    pub(crate) rationale: String,
}

pub(crate) fn findings_model(app: &ShellApp) -> FindingsModel {
    let visible = visible_sorted_finding_alias_indices(app);
    let rows = finding_rows(app, &visible);
    let selected_out_of_window = selected_out_of_window_notice(app, &rows);
    let total = visible.len();
    let triaged = visible_triaged_count(app, &visible);
    let pending = total.saturating_sub(triaged);
    let counts = visible_severity_counts(app, &visible);
    FindingsModel {
        total,
        triaged,
        pending,
        counts,
        header: findings_header(total, counts, active_component_rel_path(app).as_deref()),
        cursor: app.findings_cursor.min(total.saturating_sub(1)),
        empty: empty_state(app),
        selected_out_of_window,
        preview: findings_preview(total, triaged, pending, &rows),
        rows,
    }
}

fn findings_header(total: usize, counts: SeverityCounts, component: Option<&str>) -> String {
    let mut parts = vec![format!("FINDINGS · {total}")];
    if let Some(component) = component {
        parts.push(format!("component:{component}"));
    }
    for segment in severity_count_segments(counts) {
        parts.push(segment);
    }
    parts.join(" · ")
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
    Some(FindingDetailModel::from_finding(
        &finding,
        alias,
        target_base(app).as_deref(),
    ))
}

pub(crate) fn current_finding_for_detail(app: &ShellApp) -> Option<(Option<String>, Finding)> {
    let sorted = visible_sorted_finding_alias_indices(app);
    if let Some(finding) = selected_outside_loaded_findings(app, &sorted) {
        let alias = cached_alias_for_fingerprint(app, &finding.fingerprint);
        return Some((alias, finding));
    }
    if let Some((alias, index)) = sorted.get(app.findings_cursor) {
        return app
            .findings
            .get(*index)
            .cloned()
            .map(|finding| (Some(alias.clone()), finding));
    }
    let finding = app.selected_finding.clone()?;
    let alias = cached_alias_for_fingerprint(app, &finding.fingerprint);
    Some((alias, finding))
}

fn selected_outside_loaded_findings(app: &ShellApp, sorted: &[(String, usize)]) -> Option<Finding> {
    if active_component_rel_path(app).is_some() {
        return None;
    }
    let selected = app.selected_finding.as_ref()?;
    let selected_is_loaded = sorted.iter().any(|(_, index)| {
        app.findings
            .get(*index)
            .is_some_and(|finding| finding.fingerprint == selected.fingerprint)
    });
    (!selected_is_loaded).then_some(selected.clone())
}

fn selected_out_of_window_notice(app: &ShellApp, rows: &[FindingListRow]) -> Option<String> {
    let selected = app.selected_finding.as_ref()?;
    if rows.iter().any(|row| row.selected) {
        return None;
    }
    Some(format!(
        "opened finding is outside the loaded list · {}",
        selected.fingerprint
    ))
}

fn finding_rows(app: &ShellApp, visible: &[(String, usize)]) -> Vec<FindingListRow> {
    let selected = app
        .selected_finding
        .as_ref()
        .map(|finding| finding.fingerprint.as_str());
    let base = target_base(app);
    let runs = run_summary_index(app);
    visible
        .iter()
        .enumerate()
        .filter_map(|(row_index, (alias, finding_index))| {
            let finding = app.findings.get(*finding_index)?;
            let provenance = finding_run_provenance(&finding, &runs);
            Some(FindingListRow::from_finding(
                row_index,
                app.findings_cursor,
                selected,
                alias.clone(),
                finding,
                base.as_deref(),
                provenance,
            ))
        })
        .collect()
}

pub(crate) fn cached_sorted_finding_alias_indices(app: &ShellApp) -> Vec<(String, usize)> {
    app.workbench_cache
        .borrow_mut()
        .sorted_finding_alias_indices(&app.findings)
}

pub(crate) fn visible_sorted_finding_alias_indices(app: &ShellApp) -> Vec<(String, usize)> {
    let sorted = cached_sorted_finding_alias_indices(app);
    let Some(prefix) = active_component_rel_path(app) else {
        return sorted;
    };
    let base = target_base(app);
    sorted
        .into_iter()
        .filter(|(_, index)| {
            app.findings
                .get(*index)
                .is_some_and(|finding| finding_in_component(finding, &prefix, base.as_deref()))
        })
        .collect()
}

pub(crate) fn visible_findings_len(app: &ShellApp) -> usize {
    visible_sorted_finding_alias_indices(app).len()
}

fn cached_alias_for_fingerprint(app: &ShellApp, fingerprint: &str) -> Option<String> {
    cached_sorted_finding_alias_indices(app)
        .into_iter()
        .find_map(|(alias, index)| {
            app.findings
                .get(index)
                .is_some_and(|finding| finding.fingerprint == fingerprint)
                .then_some(alias)
        })
}

/// The canonical absolute target path, used to relativize finding locations so
/// the list shows `crates/foo.rs:12` instead of a full `/Users/...` path. Shared
/// with the Workbench SOURCE tree so both surfaces relativize identically.
pub(crate) fn target_base(app: &ShellApp) -> Option<String> {
    app.workbench_cache
        .borrow_mut()
        .target_base(app.target.as_deref())
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

fn visible_triaged_count(app: &ShellApp, visible: &[(String, usize)]) -> usize {
    visible
        .iter()
        .filter_map(|(_, index)| app.findings.get(*index))
        .filter(|finding| finding.triage.is_some())
        .count()
}

fn visible_severity_counts(app: &ShellApp, visible: &[(String, usize)]) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for finding in visible
        .iter()
        .filter_map(|(_, index)| app.findings.get(*index))
    {
        counts.add(finding.severity);
    }
    counts
}

fn active_component_rel_path(app: &ShellApp) -> Option<String> {
    let active = app.active_scope.as_ref()?;
    if active.rel_path == "." || active.rel_path.trim().is_empty() {
        return None;
    }
    let target = app.target.as_deref()?;
    let state = app
        .workbench_cache
        .borrow_mut()
        .project_scope_tree(Some(target))?;
    let tree = match &state {
        crate::app::ProjectScopeTreeState::Persisted(tree)
        | crate::app::ProjectScopeTreeState::Discovered(tree) => tree,
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
    state.clean_scan = clean_scan_empty_state(&run_summary_index(app), SystemTime::now());
    state
}

fn context_empty_state(context_state: &'static str) -> FindingsEmptyState {
    let (hint, context_cta) = match context_state {
        "present" => (
            "opens the guided hunt workflow for the active target.",
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
        selected: Option<&str>,
        alias: String,
        finding: &Finding,
        base: Option<&str>,
        provenance: FindingRunProvenance,
    ) -> Self {
        let projection = project_finding(finding, Some(alias.clone()));
        let proof = finding_proof_badge(finding);
        Self {
            alias,
            severity_tone: SeverityTone::from_severity(projection.severity),
            severity_label: projection.severity_label,
            title: projection.title,
            location: relativize_location(projection.location, base),
            run_label: provenance.run_label,
            revision_label: provenance.revision_label,
            verdict: projection.verdict_label,
            confidence: projection.confidence_label,
            proof_label: proof.label,
            proof_marker: proof.marker,
            proof_tier: proof.tier,
            cwe: projection.cwe_label,
            source: finding_source_label(finding),
            evidence: projection.evidence_preview,
            selected: selected.is_some_and(|fingerprint| fingerprint == projection.fingerprint),
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
        .or_else(|| rejected_triage_label(finding))
        .or_else(|| static_proof_label(finding))
        .or_else(|| triage_proof_label(finding))
        .unwrap_or_else(|| proof_badge("unverified", ProofTier::Suspected))
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

fn rejected_triage_label(finding: &Finding) -> Option<ProofBadge> {
    finding
        .triage
        .as_ref()
        .is_some_and(|triage| {
            matches!(
                triage.verdict,
                TriageVerdict::FalsePositive | TriageVerdict::ByDesign
            )
        })
        .then(|| proof_badge("rejected", ProofTier::Rejected))
}

fn static_proof_label(finding: &Finding) -> Option<ProofBadge> {
    match finding.static_proof_state? {
        StaticProofState::StaticallyConfirmed => {
            Some(proof_badge("static-ok", ProofTier::StaticLinked))
        }
        StaticProofState::StaticallyRejected => Some(proof_badge("static-no", ProofTier::Rejected)),
        StaticProofState::SourceSinkLinked | StaticProofState::SanitizerChecked => {
            Some(proof_badge("path-linked", ProofTier::StaticLinked))
        }
        StaticProofState::CodeCited => Some(proof_badge("code-cited", ProofTier::StaticLinked)),
        StaticProofState::NeedsRuntimeEvidence => {
            Some(proof_badge("needs-runtime", ProofTier::Suspected))
        }
        StaticProofState::SignalOnly if triaged_true_positive(finding) => None,
        StaticProofState::SignalOnly => Some(proof_badge("signal-only", ProofTier::Suspected)),
    }
}

fn triage_proof_label(finding: &Finding) -> Option<ProofBadge> {
    if triaged_true_positive(finding) {
        return Some(proof_badge("triaged-tp", ProofTier::Confirmed));
    }
    finding
        .triage
        .is_some()
        .then(|| proof_badge("needs-review", ProofTier::Suspected))
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
        ProofTier::Confirmed => "◇",
        ProofTier::StaticLinked => "◇",
        ProofTier::Suspected => "?",
        ProofTier::Rejected => "!",
    }
}

fn triaged_true_positive(finding: &Finding) -> bool {
    finding
        .triage
        .as_ref()
        .is_some_and(|triage| triage.verdict == TriageVerdict::TruePositive)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FindingRunProvenance {
    run_label: String,
    revision_label: String,
}

fn run_summary_index(app: &ShellApp) -> BTreeMap<String, RunSummary> {
    app.workbench_cache
        .borrow_mut()
        .run_summary_index(app.target.as_deref(), finding_scan_ids(app))
}

fn finding_scan_ids(app: &ShellApp) -> Vec<String> {
    app.findings
        .iter()
        .filter_map(|finding| finding.scan_id.as_deref())
        .filter(|scan_id| !scan_id.is_empty())
        .map(ToString::to_string)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
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
        return FindingRunProvenance {
            run_label: "run:unknown".to_string(),
            revision_label: "rev:unknown".to_string(),
        };
    };
    FindingRunProvenance {
        run_label: format!("run:{}", compact_run_id(run_id)),
        revision_label: runs
            .get(run_id)
            .and_then(run_revision_label)
            .unwrap_or_else(|| "rev:unknown".to_string()),
    }
}

fn run_revision_label(summary: &RunSummary) -> Option<String> {
    summary.target_git.as_ref().map(target_git_revision_label)
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
    fn from_finding(finding: &Finding, alias: Option<String>, base: Option<&str>) -> Self {
        let projection = project_finding(finding, alias);
        let proof = finding_proof_badge(finding);
        let status = detail_status_fields(finding, projection.alias.as_deref());
        let body = detail_body_fields(finding);
        Self::from_parts(finding, projection, proof, status, body, base)
    }

    fn from_parts(
        finding: &Finding,
        projection: FindingProjection,
        proof: ProofBadge,
        status: DetailStatusFields,
        body: DetailBodyFields,
        base: Option<&str>,
    ) -> Self {
        Self {
            alias: projection.alias,
            severity_tone: SeverityTone::from_severity(projection.severity),
            severity_label: finding.severity.as_str().to_string(),
            title: projection.title,
            location: relativize_location(projection.location, base),
            rule: projection.rule,
            tool: projection.tool,
            fingerprint: projection.fingerprint,
            proof_label: proof.label,
            proof_marker: proof.marker,
            proof_tier: proof.tier,
            proof_state: projection.proof_state,
            runtime_verification: projection.runtime_validation,
            static_proof_label: status.static_proof_label,
            static_proof_explanation: status.static_proof_explanation,
            runtime_label: status.runtime_label,
            runtime_explanation: status.runtime_explanation,
            next_action_label: status.next_action_label,
            next_command: status.next_command,
            next_detail: status.next_detail,
            remediation_hint: status.remediation_hint,
            evidence: body.evidence,
            message_overflow: body.message_overflow,
            evidence_overflow: body.evidence_overflow,
            message_lines: body.message_lines,
            triage: body.triage,
        }
    }
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
}

fn detail_status_fields(finding: &Finding, alias: Option<&str>) -> DetailStatusFields {
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
    }
}

struct DetailBodyFields {
    evidence: Vec<FindingEvidenceRow>,
    message_lines: Vec<String>,
    message_overflow: usize,
    evidence_overflow: usize,
    triage: Option<TriageSummaryModel>,
}

fn detail_body_fields(finding: &Finding) -> DetailBodyFields {
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
        triage: finding.triage.as_ref().map(TriageSummaryModel::from_triage),
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
            header: format!(
                "{} · conf {} · {}:{}",
                evidence.kind, evidence.confidence, evidence.file_path, evidence.line
            ),
            snippet: evidence.snippet.clone(),
            rationale: evidence.rationale.clone(),
        }
    }
}

impl TriageSummaryModel {
    fn from_triage(triage: &kuzushi_core::TriageOutcome) -> Self {
        Self {
            verdict: triage.verdict.as_str().to_string(),
            confidence: format!("{:.2}", triage.confidence),
            rationale: triage.rationale.clone(),
        }
    }
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
