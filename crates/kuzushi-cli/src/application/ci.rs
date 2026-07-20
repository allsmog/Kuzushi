//! `kuzushi ci` — read-only pipeline gate over persisted workspace state.
//!
//! Prints a plain campaign/trend/findings summary, writes a machine JSON
//! summary, and gates on NEW confirmed findings: findings whose latest
//! review decision confirms them (same reversal rule as the trend fold)
//! and whose fingerprint is not in the committed baseline
//! (`.kuzushi/ci-baseline.json`). Exit codes: 0 clean, 1 gate tripped,
//! 2 error (mapped by `ci_process_exit`). Deterministic; no model calls.

use anyhow::{Context, Result};
use kuzushi_core::capabilities::campaign::snapshot::{campaign_ids, load_campaign_snapshot};
use kuzushi_core::capabilities::campaign::trend::{
    latest_confirmed_finding_ids, trend_json, trend_metrics, workspace_campaign_spend,
    TrendMetrics,
};
use kuzushi_core::findings::ReviewDecisionRecord;
use kuzushi_core::{Finding, FindingStore, Severity, WorkspaceTarget};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub(crate) const CI_BASELINE_FILE: &str = ".kuzushi/ci-baseline.json";
const CI_SUMMARY_DEFAULT: &str = "reports/ci-summary.json";

pub(crate) struct CiOptions {
    pub(crate) fail_on: Severity,
    pub(crate) update_baseline: bool,
    pub(crate) summary_path: Option<PathBuf>,
}

/// Map the command result onto the documented exit-code contract. Pure so
/// the 2-on-error branch is testable without exiting the test process.
pub(crate) fn ci_process_exit(result: Result<i32>) -> i32 {
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("kuzushi ci error: {error:#}");
            2
        }
    }
}

pub(crate) fn ci_command(target: PathBuf, options: CiOptions) -> Result<i32> {
    let workspace = WorkspaceTarget::new(&target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let findings = store.list_all_findings()?;
    let records = store.list_review_decisions_for_findings(&findings)?;
    let confirmed = confirmed_findings(&findings, &records);
    if options.update_baseline {
        return update_baseline(workspace.root(), &confirmed);
    }
    evaluate_and_report(&workspace, &options, &findings, &records, &confirmed)
}

fn confirmed_findings<'a>(
    findings: &'a [Finding],
    records: &[ReviewDecisionRecord],
) -> Vec<&'a Finding> {
    let confirmed_ids = latest_confirmed_finding_ids(records);
    findings
        .iter()
        .filter(|finding| finding.id.is_some_and(|id| confirmed_ids.contains(&id)))
        .collect()
}

fn evaluate_and_report(
    workspace: &WorkspaceTarget,
    options: &CiOptions,
    findings: &[Finding],
    records: &[ReviewDecisionRecord],
    confirmed: &[&Finding],
) -> Result<i32> {
    let root = workspace.root();
    let baseline = load_baseline(root)?;
    let gate = evaluate_gate(confirmed, baseline.as_ref(), options.fail_on);
    let trend = trend_metrics(records, workspace_campaign_spend(root));
    let summary_path = write_summary(root, options, findings, confirmed, &gate, &trend)?;
    print_plain_summary(root, findings, confirmed, baseline.as_ref(), &gate, &trend);
    println!("ci: summary written to {}", summary_path.display());
    println!("{}", gate.outcome_line(options.fail_on));
    Ok(gate.exit_code())
}

/// The gate decision, kept pure over already-loaded data so every exit
/// path is unit-testable.
pub(crate) struct CiGate {
    pub(crate) new_confirmed: Vec<NewConfirmedFinding>,
    pub(crate) blocking_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NewConfirmedFinding {
    pub(crate) fingerprint: String,
    pub(crate) severity: String,
    pub(crate) title: String,
    pub(crate) file_path: String,
    pub(crate) start_line: u32,
    pub(crate) blocking: bool,
}

impl CiGate {
    pub(crate) fn exit_code(&self) -> i32 {
        if self.blocking_count > 0 {
            1
        } else {
            0
        }
    }

    fn outcome_line(&self, fail_on: Severity) -> String {
        if self.blocking_count > 0 {
            format!(
                "ci: FAIL — {} new confirmed finding(s) at or above {} (exit 1)",
                self.blocking_count,
                fail_on.as_str()
            )
        } else {
            "ci: PASS (exit 0)".to_string()
        }
    }
}

/// New confirmed = confirmed finding whose fingerprint the baseline does not
/// know. A missing baseline counts every confirmed finding as new — run
/// `kuzushi ci --update-baseline` once to accept the current state.
pub(crate) fn evaluate_gate(
    confirmed: &[&Finding],
    baseline: Option<&CiBaseline>,
    fail_on: Severity,
) -> CiGate {
    let known: &BTreeSet<String> = baseline.map(|doc| &doc.fingerprints).unwrap_or(EMPTY);
    let new_confirmed = confirmed
        .iter()
        .filter(|finding| !known.contains(&finding.fingerprint))
        .map(|finding| new_confirmed_row(finding, fail_on))
        .collect::<Vec<_>>();
    let blocking_count = new_confirmed.iter().filter(|row| row.blocking).count();
    CiGate {
        new_confirmed,
        blocking_count,
    }
}

static EMPTY: &BTreeSet<String> = &BTreeSet::new();

fn new_confirmed_row(finding: &Finding, fail_on: Severity) -> NewConfirmedFinding {
    NewConfirmedFinding {
        fingerprint: finding.fingerprint.clone(),
        severity: finding.severity.as_str().to_string(),
        title: finding.title.clone(),
        file_path: finding.file_path.clone(),
        start_line: finding.start_line,
        blocking: severity_blocks(finding.severity, fail_on),
    }
}

/// Same rank rule as `scan --fail-on`: unknown severity never trips a CI
/// gate — it stays visible in reports instead.
fn severity_blocks(severity: Severity, fail_on: Severity) -> bool {
    match (severity_rank(severity), severity_rank(fail_on)) {
        (Some(rank), Some(threshold)) => rank >= threshold,
        _ => false,
    }
}

fn severity_rank(severity: Severity) -> Option<u8> {
    match severity {
        Severity::Info => Some(0),
        Severity::Low => Some(1),
        Severity::Medium => Some(2),
        Severity::High => Some(3),
        Severity::Critical => Some(4),
        Severity::Unknown => None,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CiBaseline {
    pub(crate) schema_version: u32,
    pub(crate) fingerprints: BTreeSet<String>,
}

pub(crate) fn baseline_path(root: &Path) -> PathBuf {
    root.join(CI_BASELINE_FILE)
}

fn load_baseline(root: &Path) -> Result<Option<CiBaseline>> {
    let path = baseline_path(root);
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("Could not read {}", path.display()))?;
    let baseline = serde_json::from_str(&body)
        .with_context(|| format!("{} is malformed", path.display()))?;
    Ok(Some(baseline))
}

fn update_baseline(root: &Path, confirmed: &[&Finding]) -> Result<i32> {
    let baseline = CiBaseline {
        schema_version: 1,
        fingerprints: confirmed
            .iter()
            .map(|finding| finding.fingerprint.clone())
            .collect(),
    };
    let path = baseline_path(root);
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Could not create {}", parent.display()))?;
    let body = serde_json::to_vec_pretty(&baseline).context("Could not serialize baseline")?;
    std::fs::write(&path, body).with_context(|| format!("Could not write {}", path.display()))?;
    println!(
        "ci: baseline updated — {} confirmed fingerprint(s) at {}",
        baseline.fingerprints.len(),
        path.display()
    );
    println!("ci: commit this file so future runs gate only on newly confirmed findings");
    Ok(0)
}

fn write_summary(
    root: &Path,
    options: &CiOptions,
    findings: &[Finding],
    confirmed: &[&Finding],
    gate: &CiGate,
    trend: &TrendMetrics,
) -> Result<PathBuf> {
    let path = summary_path(root, options);
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Could not create {}", parent.display()))?;
    let document = summary_document(root, options, findings, confirmed, gate, trend);
    let body = serde_json::to_vec_pretty(&document).context("Could not serialize summary")?;
    std::fs::write(&path, body).with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

fn summary_path(root: &Path, options: &CiOptions) -> PathBuf {
    match options.summary_path.as_ref() {
        Some(path) if path.is_absolute() => path.clone(),
        Some(path) => root.join(path),
        None => kuzushi_core::workspace::workspace_state_dir(root).join(CI_SUMMARY_DEFAULT),
    }
}

fn summary_document(
    root: &Path,
    options: &CiOptions,
    findings: &[Finding],
    confirmed: &[&Finding],
    gate: &CiGate,
    trend: &TrendMetrics,
) -> Value {
    json!({
        "schemaVersion": 1,
        "target": root.display().to_string(),
        "totalFindings": findings.len(),
        "findingsBySeverity": severity_counts(findings),
        "confirmedCount": confirmed.len(),
        "newConfirmedCount": gate.new_confirmed.len(),
        "newConfirmed": gate.new_confirmed,
        "blockingCount": gate.blocking_count,
        "failOn": options.fail_on.as_str(),
        "baselinePath": baseline_path(root).display().to_string(),
        "campaigns": campaign_rows(root),
        "trend": trend_json(trend),
        "exitCode": gate.exit_code(),
    })
}

fn severity_counts(findings: &[Finding]) -> Value {
    let count = |severity: Severity| {
        findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    };
    json!({
        "critical": count(Severity::Critical),
        "high": count(Severity::High),
        "medium": count(Severity::Medium),
        "low": count(Severity::Low),
        "info": count(Severity::Info),
        "unknown": count(Severity::Unknown),
    })
}

/// Per-campaign state counts; an unreadable campaign is skipped rather than
/// failing the whole gate (same tolerance as the trend spend fold).
fn campaign_rows(root: &Path) -> Vec<Value> {
    campaign_ids(root)
        .unwrap_or_default()
        .iter()
        .filter_map(|id| load_campaign_snapshot(root, id).ok())
        .map(|snapshot| {
            json!({
                "campaignId": snapshot.campaign_id,
                "states": snapshot.state_counts(),
                "costUsd": snapshot.total_cost_usd,
            })
        })
        .collect()
}

fn print_plain_summary(
    root: &Path,
    findings: &[Finding],
    confirmed: &[&Finding],
    baseline: Option<&CiBaseline>,
    gate: &CiGate,
    trend: &TrendMetrics,
) {
    println!("ci: target {}", root.display());
    println!(
        "ci: findings {} — {}",
        findings.len(),
        severity_strip(findings)
    );
    println!("ci: confirmed {} (latest review decision wins)", confirmed.len());
    match baseline {
        Some(doc) => println!(
            "ci: baseline {} known confirmed fingerprint(s) at {}",
            doc.fingerprints.len(),
            baseline_path(root).display()
        ),
        None => println!(
            "ci: baseline absent — every confirmed finding counts as new (run --update-baseline to accept current state)"
        ),
    }
    println!("ci: new confirmed since baseline: {}", gate.new_confirmed.len());
    for campaign in campaign_lines(root) {
        println!("ci: {campaign}");
    }
    println!("{}", trend.strip_label());
}

fn severity_strip(findings: &[Finding]) -> String {
    [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .iter()
    .map(|severity| {
        let count = findings
            .iter()
            .filter(|finding| finding.severity == *severity)
            .count();
        format!("{} {}", severity.as_str(), count)
    })
    .collect::<Vec<_>>()
    .join(" · ")
}

fn campaign_lines(root: &Path) -> Vec<String> {
    campaign_ids(root)
        .unwrap_or_default()
        .iter()
        .filter_map(|id| load_campaign_snapshot(root, id).ok())
        .map(|snapshot| {
            let states = snapshot
                .state_counts()
                .into_iter()
                .map(|(state, count)| format!("{state} {count}"))
                .collect::<Vec<_>>()
                .join(" · ");
            format!("campaign {} — {}", snapshot.campaign_id, states)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};

    fn decision(verdict: ReviewDecisionVerdict) -> ReviewDecision {
        ReviewDecision {
            verdict,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: "ci test".to_string(),
            dismiss_reason: None,
            actor: None,
        }
    }

    fn workspace_with_confirmed(
        severities: &[Severity],
    ) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("ci-run", tmp.path(), "running")
            .unwrap();
        for (index, severity) in severities.iter().enumerate() {
            let finding = Finding::new_tool(
                "semgrep",
                format!("ci-rule-{index}"),
                "src/app.c",
                10 + index as u32,
                None,
                *severity,
                format!("ci finding {index}"),
            );
            let id = store.insert_finding("ci-run", &finding).unwrap();
            store
                .append_user_review_decision(id, &decision(ReviewDecisionVerdict::Confirmed))
                .unwrap();
        }
        let target = tmp.path().to_path_buf();
        (tmp, target)
    }

    fn options(fail_on: Severity, update_baseline: bool) -> CiOptions {
        CiOptions {
            fail_on,
            update_baseline,
            summary_path: None,
        }
    }

    #[test]
    fn new_confirmed_finding_at_threshold_exits_one_and_writes_summary() {
        let (_tmp, target) = workspace_with_confirmed(&[Severity::High, Severity::Low]);

        let code = ci_command(target.clone(), options(Severity::High, false)).unwrap();

        assert_eq!(code, 1);
        let summary_body =
            std::fs::read_to_string(summary_path(&target, &options(Severity::High, false)))
                .unwrap();
        let summary: Value = serde_json::from_str(&summary_body).unwrap();
        assert_eq!(summary["exitCode"], 1);
        assert_eq!(summary["confirmedCount"], 2);
        assert_eq!(summary["newConfirmedCount"], 2);
        assert_eq!(summary["blockingCount"], 1);
        assert_eq!(summary["findingsBySeverity"]["high"], 1);
        assert_eq!(summary["failOn"], "high");
        assert!(summary["trend"]["fpRate"].is_number() || summary["trend"]["fpRate"].is_null());
    }

    #[test]
    fn new_confirmed_below_threshold_exits_zero() {
        let (_tmp, target) = workspace_with_confirmed(&[Severity::Low]);

        let code = ci_command(target, options(Severity::High, false)).unwrap();

        assert_eq!(code, 0);
    }

    #[test]
    fn update_baseline_round_trip_turns_fail_into_pass() {
        let (_tmp, target) = workspace_with_confirmed(&[Severity::Critical]);
        assert_eq!(
            ci_command(target.clone(), options(Severity::Low, false)).unwrap(),
            1
        );

        assert_eq!(
            ci_command(target.clone(), options(Severity::Low, true)).unwrap(),
            0
        );
        let baseline: CiBaseline =
            serde_json::from_str(&std::fs::read_to_string(baseline_path(&target)).unwrap())
                .unwrap();
        assert_eq!(baseline.fingerprints.len(), 1);

        assert_eq!(ci_command(target, options(Severity::Low, false)).unwrap(), 0);
    }

    #[test]
    fn unknown_severity_never_blocks_but_is_reported_as_new() {
        let (_tmp, target) = workspace_with_confirmed(&[Severity::Unknown]);

        let code = ci_command(target.clone(), options(Severity::Low, false)).unwrap();

        assert_eq!(code, 0);
        let summary_body =
            std::fs::read_to_string(summary_path(&target, &options(Severity::Low, false)))
                .unwrap();
        let summary: Value = serde_json::from_str(&summary_body).unwrap();
        assert_eq!(summary["newConfirmedCount"], 1);
        assert_eq!(summary["blockingCount"], 0);
    }

    #[test]
    fn unconfirmed_findings_never_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("ci-run", tmp.path(), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "undecided",
            "src/app.c",
            5,
            None,
            Severity::Critical,
            "undecided critical",
        );
        store.insert_finding("ci-run", &finding).unwrap();

        let code = ci_command(tmp.path().to_path_buf(), options(Severity::Low, false)).unwrap();

        assert_eq!(code, 0);
    }

    #[test]
    fn error_path_maps_to_exit_two() {
        let missing = PathBuf::from("/nonexistent/kuzushi-ci-target");

        let result = ci_command(missing, options(Severity::Low, false));

        assert!(result.is_err());
        assert_eq!(ci_process_exit(result), 2);
        assert_eq!(ci_process_exit(Ok(1)), 1);
        assert_eq!(ci_process_exit(Ok(0)), 0);
    }
}
