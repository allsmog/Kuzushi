//! Coverage matrix fold: shards × threat sources with per-cell campaign
//! progress and per-shard finding counts.
//!
//! Answers the campaign operator's planning question — "where have we
//! looked, what did we find, and where is risk with no coverage yet?" —
//! from artifacts that already exist: the shard manifest, every campaign's
//! plan/queue fold, and the findings the caller projects in. Read-only.

use super::shards::load_campaign_shards;
use super::snapshot::{campaign_ids, load_campaign_snapshot, CampaignJobSnapshot};
use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;

/// One finding projected into the fold. Callers own the store access (the
/// shell passes its loaded findings; the tool executor reads the store) so
/// this fold stays free of persistence concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageFinding {
    /// Workspace-relative file path.
    pub file_path: String,
    pub confirmed: bool,
}

/// How the projected findings were obtained. Zero findings from a store the
/// fold could not read is not the same claim as zero findings from a store it
/// read: only the second means a shard is clean, and the matrix exists to
/// answer exactly that question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingLedgerRead {
    /// Findings and their review decisions both read.
    Read,
    /// No findings store was attached to this execution.
    NoStore,
    /// The findings could not be read; every shard count is zero for that
    /// reason alone.
    FindingsUnreadable,
    /// Findings read, but their review decisions could not be. The confirmed
    /// counts then rest on embedded triage verdicts alone, which carry no
    /// review reversal, so they are not a measurement in either direction.
    DecisionsUnreadable,
}

impl FindingLedgerRead {
    pub fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::NoStore => "no-store",
            Self::FindingsUnreadable => "findings-unreadable",
            Self::DecisionsUnreadable => "decisions-unreadable",
        }
    }

    /// What the operator must be told before reading a count, or `None` when
    /// the counts are a measurement.
    pub fn degraded_note(self) -> Option<&'static str> {
        match self {
            Self::Read => None,
            Self::NoStore => Some(" — no findings store; shard finding counts are NOT measured"),
            Self::FindingsUnreadable => {
                Some(" — findings unreadable; shard finding counts are NOT measured")
            }
            Self::DecisionsUnreadable => {
                Some(" — review decisions unreadable; confirmed counts are NOT measured")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoverageCellState {
    /// No campaign has ever planned this shard × source combination.
    Never,
    Planned,
    Failed,
    /// Some of this source's threats completed for the shard, others did
    /// not — the cell must not claim full coverage it does not have.
    Partial,
    Running,
    Completed,
}

impl CoverageCellState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Planned => "planned",
            Self::Failed => "failed",
            Self::Partial => "partial",
            Self::Running => "running",
            Self::Completed => "completed",
        }
    }

    fn from_job_state(state: &str) -> Self {
        match state {
            "completed" => Self::Completed,
            "running" => Self::Running,
            "failed" | "parked" => Self::Failed,
            _ => Self::Planned,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CoverageRow {
    pub shard: String,
    /// Workspace-relative scope roots; empty means the whole workspace.
    pub paths: Vec<String>,
    /// Aligned with `CoverageReport::columns`.
    pub cells: Vec<CoverageCellState>,
    pub finding_count: usize,
    pub confirmed_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CoverageReport {
    /// Threat sources seen across campaign plans, sorted. Jobs without a
    /// threat source aggregate under the trailing "(unseasoned)" column.
    pub columns: Vec<String>,
    pub rows: Vec<CoverageRow>,
    pub campaign_count: usize,
    /// Campaign directories whose plan could not be read. Their jobs are
    /// absent from every cell, so the matrix may under-report coverage —
    /// the operator must see that, not a silently smaller fold.
    pub unreadable_campaigns: usize,
    /// Modern scope studies, preparation and unclassified jobs cannot populate
    /// the legacy shard/discovery progress cells.
    pub excluded_jobs: usize,
}

pub const UNSEASONED_COLUMN: &str = "(unseasoned)";

pub fn coverage_report(root: &Path, findings: &[CoverageFinding]) -> Result<CoverageReport> {
    let shards = load_campaign_shards(root)?;
    let jobs = all_campaign_jobs(root)?;
    let columns = source_columns(&jobs.jobs);
    let cell_states = folded_cell_states(&jobs.jobs);
    let rows = shards
        .iter()
        .map(|shard| CoverageRow {
            shard: shard.name.clone(),
            paths: shard.paths.clone(),
            cells: row_cells(&columns, &cell_states, &shard.name),
            finding_count: shard_findings(&shard.paths, findings, false),
            confirmed_count: shard_findings(&shard.paths, findings, true),
        })
        .collect();
    Ok(CoverageReport {
        columns,
        rows,
        campaign_count: jobs.campaigns,
        unreadable_campaigns: jobs.unreadable,
        excluded_jobs: jobs.excluded,
    })
}

struct CampaignJobsFold {
    campaigns: usize,
    unreadable: usize,
    jobs: Vec<CampaignJobSnapshot>,
    excluded: usize,
}

fn all_campaign_jobs(root: &Path) -> Result<CampaignJobsFold> {
    let ids = campaign_ids(root)?;
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let mut fold = CampaignJobsFold {
        campaigns: 0,
        unreadable: 0,
        jobs: Vec::new(),
        excluded: 0,
    };
    for id in &ids {
        // Unreadable plans are skipped rather than failing the whole matrix
        // (one corrupt campaign directory must not blind coverage entirely),
        // but the skip is COUNTED so the report can disclose it.
        let Ok(snapshot) = load_campaign_snapshot(root, id) else {
            fold.unreadable += 1;
            continue;
        };
        fold.campaigns += 1;
        append_discovery_jobs(&mut fold, snapshot, &registry);
    }
    Ok(fold)
}

fn append_discovery_jobs(
    fold: &mut CampaignJobsFold,
    snapshot: super::snapshot::CampaignSnapshot,
    registry: &crate::ModuleRegistry,
) {
    for job in snapshot.jobs {
        if legacy_discovery_job(&job, snapshot.tool.as_deref(), registry) {
            fold.jobs.push(job);
        } else {
            fold.excluded += 1;
        }
    }
}

fn legacy_discovery_job(
    job: &CampaignJobSnapshot,
    owner: Option<&str>,
    registry: &crate::ModuleRegistry,
) -> bool {
    job.shard.is_some()
        && job
            .tool
            .as_deref()
            .or(owner)
            .and_then(|name| registry.resolve_tool(name))
            .is_some_and(|tool| tool.phase == crate::modules::ToolPhase::Scan)
}

fn source_columns(jobs: &[CampaignJobSnapshot]) -> Vec<String> {
    let mut columns: Vec<String> = jobs
        .iter()
        .filter_map(|job| job.threat_source.clone())
        .collect();
    columns.sort();
    columns.dedup();
    if jobs.iter().any(|job| job.threat_source.is_none()) {
        columns.push(UNSEASONED_COLUMN.to_string());
    }
    columns
}

/// Best observed progress per (shard, source, threat) — the same
/// granularity the planner creates jobs at. "Best" is deliberate — the
/// matrix reports whether a combination has EVER been covered, not the
/// latest attempt's mood.
fn folded_threat_states(
    jobs: &[CampaignJobSnapshot],
) -> BTreeMap<(String, String, String), CoverageCellState> {
    let mut states = BTreeMap::new();
    for job in jobs {
        let Some(shard) = job.shard.clone() else {
            continue;
        };
        let source = job
            .threat_source
            .clone()
            .unwrap_or_else(|| UNSEASONED_COLUMN.to_string());
        let state = CoverageCellState::from_job_state(&job.state);
        let entry = states
            .entry((shard, source, threat_slot(job)))
            .or_insert(CoverageCellState::Never);
        *entry = (*entry).max(state);
    }
    states
}

/// A source document holds many threats, and jobs are planned per threat;
/// the per-threat slot keeps one threat's completed job from claiming the
/// whole document is covered for the shard.
fn threat_slot(job: &CampaignJobSnapshot) -> String {
    job.threat_id
        .clone()
        .unwrap_or_else(|| UNSEASONED_COLUMN.to_string())
}

/// The display matrix stays at shard × source granularity, but its cell
/// state aggregates honestly over the source's planned threats.
fn folded_cell_states(
    jobs: &[CampaignJobSnapshot],
) -> BTreeMap<(String, String), CoverageCellState> {
    let mut grouped = BTreeMap::<(String, String), Vec<CoverageCellState>>::new();
    for ((shard, source, _), state) in folded_threat_states(jobs) {
        grouped.entry((shard, source)).or_default().push(state);
    }
    grouped
        .into_iter()
        .map(|(cell, states)| (cell, aggregate_cell_state(&states)))
        .collect()
}

/// Completed only when EVERY planned threat completed; active work shows
/// Running; a mix of completed and pending is Partial — never full credit
/// for partial coverage. Without any completion, best-of as before.
fn aggregate_cell_state(states: &[CoverageCellState]) -> CoverageCellState {
    if states
        .iter()
        .all(|state| *state == CoverageCellState::Completed)
    {
        return CoverageCellState::Completed;
    }
    let best_incomplete = states
        .iter()
        .filter(|state| **state != CoverageCellState::Completed)
        .copied()
        .max()
        .unwrap_or(CoverageCellState::Never);
    if best_incomplete == CoverageCellState::Running {
        return CoverageCellState::Running;
    }
    if states
        .iter()
        .any(|state| *state == CoverageCellState::Completed)
    {
        return CoverageCellState::Partial;
    }
    best_incomplete
}

/// Threat-granular cells whose folded state says the combination is already
/// being (or has been) scanned: `Completed` or `Running` across every
/// campaign in the workspace. Keys match `campaign:plan`'s per-job cells
/// (source and threat id joined by NUL), so `fillGaps` skips exactly the
/// threats that ran — never a whole document because one of its threats
/// finished. Planned-but-never-dispatched and failed cells remain gaps.
pub fn covered_cells(root: &Path) -> Result<std::collections::BTreeSet<(String, String)>> {
    let jobs = all_campaign_jobs(root)?.jobs;
    Ok(folded_threat_states(&jobs)
        .into_iter()
        .filter(|(_, state)| {
            matches!(
                state,
                CoverageCellState::Completed | CoverageCellState::Running
            )
        })
        .map(|((shard, source, threat), _)| (shard, threat_cell_column(&source, &threat)))
        .collect())
}

/// The composite coverage-cell column: source stem + NUL + threat id. NUL
/// cannot appear in either component, so distinct pairs never collide.
pub fn threat_cell_column(source: &str, threat: &str) -> String {
    format!("{source}\u{0}{threat}")
}

fn row_cells(
    columns: &[String],
    states: &BTreeMap<(String, String), CoverageCellState>,
    shard: &str,
) -> Vec<CoverageCellState> {
    columns
        .iter()
        .map(|column| {
            states
                .get(&(shard.to_string(), column.clone()))
                .copied()
                .unwrap_or(CoverageCellState::Never)
        })
        .collect()
}

fn shard_findings(paths: &[String], findings: &[CoverageFinding], confirmed_only: bool) -> usize {
    findings
        .iter()
        .filter(|finding| !confirmed_only || finding.confirmed)
        .filter(|finding| shard_contains(paths, &finding.file_path))
        .count()
}

/// Empty shard paths mean the whole workspace. A path prefix only matches on
/// a path-component boundary so `src/api` never claims `src/api2/...`.
fn shard_contains(paths: &[String], file_path: &str) -> bool {
    if paths.is_empty() {
        return true;
    }
    paths.iter().any(|prefix| {
        let prefix = prefix.trim_end_matches('/');
        file_path == prefix
            || file_path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_state_precedence_prefers_best_progress() {
        assert!(CoverageCellState::Completed > CoverageCellState::Running);
        assert!(CoverageCellState::Running > CoverageCellState::Failed);
        assert!(CoverageCellState::Failed > CoverageCellState::Planned);
        assert!(CoverageCellState::Planned > CoverageCellState::Never);
    }

    fn empty_report(unreadable_campaigns: usize) -> CoverageReport {
        CoverageReport {
            columns: vec!["threat-model.json".to_string()],
            rows: Vec::new(),
            campaign_count: 1,
            unreadable_campaigns,
            excluded_jobs: 0,
        }
    }

    #[test]
    fn counts_from_a_store_the_fold_could_not_read_are_disclosed_as_unmeasured() {
        let report = empty_report(0);

        let read = coverage_output_line(&report, FindingLedgerRead::Read);
        assert!(!read.contains("NOT measured"), "{read}");
        for ledger in [
            FindingLedgerRead::NoStore,
            FindingLedgerRead::FindingsUnreadable,
        ] {
            let line = coverage_output_line(&report, ledger);
            assert!(
                line.contains("shard finding counts are NOT measured"),
                "{line}"
            );
        }
        // Confirmed counts fall back on embedded triage verdicts that carry no
        // review reversal, so the note claims no direction, not a lower bound.
        let decisions = coverage_output_line(&report, FindingLedgerRead::DecisionsUnreadable);
        assert!(
            decisions.contains("confirmed counts are NOT measured"),
            "{decisions}"
        );
        assert!(!decisions.contains("lower bound"), "{decisions}");
        assert_eq!(
            coverage_report_json(&report, FindingLedgerRead::FindingsUnreadable)["findingLedger"],
            "findings-unreadable"
        );
        assert_eq!(
            coverage_report_json(&report, FindingLedgerRead::Read)["findingLedger"],
            "read"
        );
    }

    #[test]
    fn an_unreadable_campaign_dir_and_an_unreadable_ledger_are_both_stated() {
        let line = coverage_output_line(&empty_report(2), FindingLedgerRead::FindingsUnreadable);

        assert!(line.contains("2 campaign dir(s) unreadable"), "{line}");
        assert!(line.contains("findings unreadable"), "{line}");
    }

    #[test]
    fn shard_prefix_matching_stops_at_path_component_boundaries() {
        let paths = vec!["src/api".to_string()];
        assert!(shard_contains(&paths, "src/api/handler.rs"));
        assert!(shard_contains(&paths, "src/api"));
        assert!(!shard_contains(&paths, "src/api2/handler.rs"));
        assert!(shard_contains(&[], "anything/at/all.rs"));
    }

    #[test]
    fn human_review_reversal_overrides_cached_auto_triage_in_coverage() {
        use crate::findings::{
            Finding, ReviewDecision, ReviewDecisionRecord, ReviewDecisionVerdict, Severity,
            TriageAuthor, TriageOutcome, TriageVerdict,
        };

        let mut finding = Finding::new_tool(
            "semgrep",
            "rules.example",
            "src/api.rs",
            7,
            Some(7),
            Severity::High,
            "example finding",
        );
        finding.id = Some(7);
        finding.identity_id = Some("finding_identity_shared".to_string());
        finding.triage = Some(TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.9,
            rationale: "automated triage marked this real".to_string(),
            ..TriageOutcome::default()
        });
        finding.triaged_by = Some(TriageAuthor::Auto);

        let auto_only = coverage_findings_from_review_state(std::slice::from_ref(&finding), &[]);
        assert!(auto_only[0].confirmed);

        let human_rejection = ReviewDecisionRecord {
            id: 11,
            finding_id: 8,
            identity_id: Some("finding_identity_shared".to_string()),
            decision: ReviewDecision {
                verdict: ReviewDecisionVerdict::RejectedFalsePositive,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "operator rejected the durable security case".to_string(),
                dismiss_reason: None,
                actor: Some("operator".to_string()),
            },
            triage_verdict: Some(TriageVerdict::FalsePositive),
            created_at: "2026-09-24T00:00:00Z".to_string(),
            provenance: None,
        };
        let reviewed = coverage_findings_from_review_state(&[finding], &[human_rejection]);
        assert!(!reviewed[0].confirmed);
    }
}

/// `campaign:coverage` — the matrix fold rendered as a tool result. Headless
/// parity for the cockpit coverage deck; both consume `coverage_report`.
pub fn execute_campaign_coverage(
    _input: &serde_json::Value,
    ctx: &crate::modules::ToolExecutionContext<'_>,
) -> Result<serde_json::Value> {
    use anyhow::Context;
    let workspace = ctx
        .workspace
        .context("campaign:coverage requires an active workspace target")?;
    let (findings, ledger) = store_coverage_findings(ctx);
    let report = coverage_report(workspace.root(), &findings)?;
    let output = coverage_output_line(&report, ledger);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        coverage_report_json(&report, ledger),
    ))
}

/// The one-line result. Both ways the fold can be short of the truth — a
/// campaign dir it could not read, a finding ledger it could not read —
/// travel with the counts they weaken.
fn coverage_output_line(report: &CoverageReport, ledger: FindingLedgerRead) -> String {
    let covered = report
        .rows
        .iter()
        .filter(|row| {
            row.cells
                .iter()
                .any(|cell| *cell == CoverageCellState::Completed)
        })
        .count();
    let campaigns = unreadable_campaigns_note(report);
    let findings = ledger.degraded_note().unwrap_or_default();
    format!(
        "Historical shard progress: {} shard(s) × {} threat source(s), {} shard(s) with completed discovery jobs, {} campaign(s){campaigns}{findings}. {} preparation, unclassified or non-shard job(s) excluded. Job completion does not establish repository coverage or current-source applicability.",
        report.rows.len(),
        report.columns.len(),
        covered,
        report.campaign_count,
        report.excluded_jobs,
    )
}

fn unreadable_campaigns_note(report: &CoverageReport) -> String {
    if report.unreadable_campaigns == 0 {
        return String::new();
    }
    format!(
        " — {} campaign dir(s) unreadable; their coverage is NOT counted",
        report.unreadable_campaigns
    )
}

/// Project the store's findings, reporting which of the two reads it took
/// actually succeeded. A caller that only received the findings would have
/// no way to tell an empty workspace from an unopenable database.
pub fn store_coverage_findings(
    ctx: &crate::modules::ToolExecutionContext<'_>,
) -> (Vec<CoverageFinding>, FindingLedgerRead) {
    let Some(store) = ctx.findings_store else {
        return (Vec::new(), FindingLedgerRead::NoStore);
    };
    let Ok(findings) = store.list_all_findings() else {
        return (Vec::new(), FindingLedgerRead::FindingsUnreadable);
    };
    let (records, ledger) = match store.list_review_decisions_for_findings(&findings) {
        Ok(records) => (records, FindingLedgerRead::Read),
        Err(_) => (Vec::new(), FindingLedgerRead::DecisionsUnreadable),
    };
    (
        coverage_findings_from_review_state(&findings, &records),
        ledger,
    )
}

/// Project campaign coverage through the same effective-review authority used
/// by review lists and proof gating. A cached auto-triage verdict is only the
/// fallback when no applicable review decision exists; human decisions and
/// durable-identity decisions keep their normal precedence instead of being
/// re-derived from a row-id-only confirmed set.
pub fn coverage_findings_from_review_state(
    findings: &[crate::findings::Finding],
    records: &[crate::findings::ReviewDecisionRecord],
) -> Vec<CoverageFinding> {
    let review_state =
        crate::findings::EffectiveReviewStateIndex::from_findings_and_decisions(findings, records);
    findings
        .iter()
        .map(|finding| {
            let effective = review_state.effective_decision_for(finding);
            CoverageFinding {
                file_path: finding.file_path.clone(),
                confirmed: crate::findings::decision_is_review_actionable(
                    finding,
                    effective.as_ref(),
                ),
            }
        })
        .collect()
}

/// Compatibility summary for callers that need only the row ids whose latest
/// recorded review decision is confirming. Campaign coverage itself must use
/// `coverage_findings_from_review_state` so negative human decisions and
/// durable-identity decisions are not lost before triage fallback is applied.
pub fn confirmed_finding_ids_from_decisions(
    records: &[crate::findings::ReviewDecisionRecord],
) -> std::collections::BTreeSet<i64> {
    let mut latest: BTreeMap<i64, (i64, bool)> = BTreeMap::new();
    for record in records {
        let confirmed = matches!(
            record.decision.verdict,
            crate::findings::ReviewDecisionVerdict::Confirmed
                | crate::findings::ReviewDecisionVerdict::ToFix
        );
        let entry = latest
            .entry(record.finding_id)
            .or_insert((record.id, confirmed));
        if record.id >= entry.0 {
            *entry = (record.id, confirmed);
        }
    }
    latest
        .into_iter()
        .filter_map(|(finding_id, (_, confirmed))| confirmed.then_some(finding_id))
        .collect()
}

/// Compatibility projection for callers that already resolved the effective
/// confirmed set. Raw review ledgers should use
/// `coverage_findings_from_review_state` so a negative review can override a
/// cached positive triage verdict.
pub fn coverage_finding(
    finding: &crate::findings::Finding,
    confirmed_ids: &std::collections::BTreeSet<i64>,
) -> CoverageFinding {
    let reviewed_confirmed = finding.id.is_some_and(|id| confirmed_ids.contains(&id));
    let triaged_confirmed = finding
        .triage
        .as_ref()
        .is_some_and(|triage| triage.verdict == crate::findings::TriageVerdict::TruePositive);
    CoverageFinding {
        file_path: finding.file_path.clone(),
        confirmed: reviewed_confirmed || triaged_confirmed,
    }
}

fn coverage_report_json(report: &CoverageReport, ledger: FindingLedgerRead) -> serde_json::Value {
    serde_json::json!({
        "columns": report.columns,
        "campaignCount": report.campaign_count,
        "unreadableCampaigns": report.unreadable_campaigns,
        "excludedJobs": report.excluded_jobs,
        "coverageMeaning": "historical-shard-job-progress",
        "limitations": ["Job completion is not repository coverage or current-source applicability.", "Accepted scope studies and non-discovery jobs do not populate this legacy matrix; use the investigation report."],
        "findingLedger": ledger.label(),
        "rows": report.rows.iter().map(|row| serde_json::json!({
            "shard": row.shard,
            "paths": row.paths,
            "cells": row.cells.iter().map(|cell| cell.label()).collect::<Vec<_>>(),
            "findingCount": row.finding_count,
            "confirmedCount": row.confirmed_count,
        })).collect::<Vec<_>>(),
    })
}
