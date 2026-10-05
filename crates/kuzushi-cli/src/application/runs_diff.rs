//! `kz runs diff` — scan-to-scan comparison over the durable finding history.
//!
//! Presentation over `kuzushi_core::findings::compare_scan_runs`, which
//! classifies by durable identity and refuses to call a finding `resolved`
//! unless the compare run provably re-examined it. Findings the compare run
//! cannot honestly retire surface as `not_rescanned` with the missing proof.

use anyhow::{Context, Result};
use kuzushi_core::findings::{
    compare_scan_runs, ReviewDecisionVerdict, ScanComparisonClass, ScanFindingSignature,
    ScanRunComparison, ScanUncertainMatch, TriageVerdict,
};
use kuzushi_core::{
    read_run_artifact_text, tool_result_artifact_spec, FindingStore, RunArtifactRead, RunId,
    WorkspaceTarget,
};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub(crate) fn runs_diff_command(
    target: PathBuf,
    base_run_id: &str,
    compare_run_id: &str,
    json: bool,
) -> Result<()> {
    let workspace = WorkspaceTarget::new(target)?;
    let diff = runs_diff(workspace.root(), base_run_id, compare_run_id)?;
    print!("{}", runs_diff_output(&diff, json)?);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunsDiff {
    pub(crate) comparison: ScanRunComparison,
    pub(crate) base_source: kuzushi_core::run_artifacts::RunSourceRevision,
    pub(crate) compare_source: kuzushi_core::run_artifacts::RunSourceRevision,
    pub(crate) base_context: kuzushi_core::run_artifacts::RunThreatModelContext,
    pub(crate) compare_context: kuzushi_core::run_artifacts::RunThreatModelContext,
    pub(crate) warnings: Vec<String>,
    pub(crate) decision_summary: Option<RunsDiffDecisionSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunsFindingChange {
    pub(crate) finding_key: String,
    pub(crate) before: ScanFindingSignature,
    pub(crate) after: ScanFindingSignature,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RunsDiffDecisionSummary {
    pub(crate) identities: usize,
    pub(crate) with_stored_decision: usize,
    pub(crate) carry_forward: usize,
    pub(crate) conflicts: usize,
}

impl RunsDiff {
    pub(crate) fn base_status(&self) -> &str {
        &self.comparison.base_status
    }

    pub(crate) fn compare_status(&self) -> &str {
        &self.comparison.compare_status
    }

    pub(crate) fn keys_of(&self, class: ScanComparisonClass) -> Vec<&str> {
        self.comparison
            .findings
            .iter()
            .filter(|finding| finding.class == class)
            .map(|finding| finding.stable_key.as_str())
            .collect()
    }

    pub(crate) fn not_rescanned(&self) -> Vec<(&str, &str)> {
        self.comparison
            .findings
            .iter()
            .filter(|finding| finding.class == ScanComparisonClass::NotRescanned)
            .map(|finding| {
                (
                    finding.stable_key.as_str(),
                    finding.reason.as_deref().unwrap_or("coverage not proven"),
                )
            })
            .collect()
    }

    pub(crate) fn changed(&self) -> Vec<RunsFindingChange> {
        self.comparison
            .findings
            .iter()
            .filter(|finding| finding.signature_changed())
            .map(|finding| RunsFindingChange {
                finding_key: finding.stable_key.clone(),
                before: finding.before.clone().unwrap_or_default(),
                after: finding.after.clone().unwrap_or_default(),
            })
            .collect()
    }

    /// Findings present in both runs whose review-relevant surface held still.
    pub(crate) fn stable_count(&self) -> usize {
        self.comparison
            .findings
            .iter()
            .filter(|finding| {
                finding.before.is_some() && finding.after.is_some() && !finding.signature_changed()
            })
            .count()
    }
}

pub(crate) fn runs_diff(
    target: &Path,
    base_run_id: &str,
    compare_run_id: &str,
) -> Result<RunsDiff> {
    RunId::parse(base_run_id).context("invalid base run id")?;
    RunId::parse(compare_run_id).context("invalid compare run id")?;
    let workspace = WorkspaceTarget::new(target)?;
    let db_path = workspace.findings_db_path();
    anyhow::ensure!(
        db_path.exists(),
        "No recorded findings database at {}. Run a scan against this target first.",
        db_path.display()
    );
    let store = FindingStore::open(&db_path)?;
    let comparison = compare_scan_runs(&store, base_run_id, compare_run_id)?;
    let mut warnings = Vec::new();
    append_result_artifact_warning(target, base_run_id, &mut warnings);
    append_result_artifact_warning(target, compare_run_id, &mut warnings);
    let decision_summary = decision_summary_from_store(&store, &comparison, &mut warnings);
    Ok(RunsDiff {
        base_source: run_source_revision(target, base_run_id),
        compare_source: run_source_revision(target, compare_run_id),
        base_context: run_threat_model_context(target, base_run_id),
        compare_context: run_threat_model_context(target, compare_run_id),
        comparison,
        warnings,
        decision_summary,
    })
}

fn run_source_revision(target: &Path, run: &str) -> kuzushi_core::run_artifacts::RunSourceRevision {
    let summary = run_artifact_json(target, run, "run.json");
    let result = run_artifact_json(target, run, "result.json");
    kuzushi_core::run_artifacts::RunSourceRevision::from_artifacts(
        summary.as_ref(),
        result.as_ref(),
    )
}

fn run_artifact_json(target: &Path, run: &str, leaf: &str) -> Option<Value> {
    let RunArtifactRead::Ready { value, .. } = read_run_artifact_text(target, run, leaf) else {
        return None;
    };
    serde_json::from_str(&value).ok()
}

fn run_threat_model_context(
    target: &Path,
    run: &str,
) -> kuzushi_core::run_artifacts::RunThreatModelContext {
    let input = run_artifact_json(target, run, "scan-input.json");
    kuzushi_core::run_artifacts::RunThreatModelContext::from_scan_input(input.as_ref())
}

fn append_result_artifact_warning(target: &Path, run_id: &str, warnings: &mut Vec<String>) {
    if let Some(warning) = result_artifact_warning(target, run_id) {
        warnings.push(warning);
    }
}

fn result_artifact_warning(target: &Path, run_id: &str) -> Option<String> {
    match read_run_artifact_text(target, run_id, run_result_artifact_leaf()) {
        RunArtifactRead::Ready { value, .. } => serde_json::from_str::<Value>(&value)
            .err()
            .map(|error| format!("run {run_id} result artifact is malformed JSON: {error}")),
        RunArtifactRead::Missing { .. } => None,
        RunArtifactRead::NonFile { .. } => Some(format!(
            "run {run_id} result artifact is not a regular file"
        )),
        RunArtifactRead::Unsafe { error } | RunArtifactRead::Unreadable { error, .. } => Some(
            format!("run {run_id} result artifact is unreadable: {error}"),
        ),
    }
}

fn run_result_artifact_leaf() -> &'static str {
    tool_result_artifact_spec("result.json")
        .expect("tool result artifact must be in shared spec")
        .leaf
}

fn decision_summary_from_store(
    store: &FindingStore,
    comparison: &ScanRunComparison,
    warnings: &mut Vec<String>,
) -> Option<RunsDiffDecisionSummary> {
    let mut summary = RunsDiffDecisionSummary::default();
    for finding in &comparison.findings {
        let (Some(after), true) = (&finding.after, is_identity_key(&finding.stable_key)) else {
            continue;
        };
        summary.identities += 1;
        match store.latest_review_decision_for_identity(&finding.stable_key) {
            Ok(Some(record)) => summary.add_stored_decision(&record.decision.verdict, after),
            Ok(None) => {}
            Err(error) => warnings.push(format!(
                "decision summary unavailable for {}: {error:#}",
                finding.stable_key
            )),
        }
    }
    Some(summary)
}

fn is_identity_key(key: &str) -> bool {
    key.starts_with("fi_")
}

impl RunsDiffDecisionSummary {
    fn add_stored_decision(
        &mut self,
        stored: &ReviewDecisionVerdict,
        signature: &ScanFindingSignature,
    ) {
        self.with_stored_decision += 1;
        match snapshot_review_verdict(signature) {
            Some(snapshot) if snapshot != *stored => self.conflicts += 1,
            Some(_) => {}
            None => self.carry_forward += 1,
        }
    }
}

fn snapshot_review_verdict(signature: &ScanFindingSignature) -> Option<ReviewDecisionVerdict> {
    let verdict = signature.verdict.as_deref()?;
    ReviewDecisionVerdict::from_str(verdict).or_else(|| {
        TriageVerdict::try_from(verdict)
            .ok()
            .map(ReviewDecisionVerdict::from_triage_verdict)
    })
}

pub(crate) fn runs_diff_output(diff: &RunsDiff, json: bool) -> Result<String> {
    if json {
        return Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&runs_diff_json(diff))?
        ));
    }
    Ok(runs_diff_plain(diff))
}

fn runs_diff_json(diff: &RunsDiff) -> Value {
    let changed = diff.changed();
    serde_json::json!({
        "baseRunId": diff.comparison.base_run_id,
        "compareRunId": diff.comparison.compare_run_id,
        "baseSource": diff.base_source,
        "compareSource": diff.compare_source,
        "baseContext": diff.base_context,
        "compareContext": diff.compare_context,
        "contextComparison": diff.base_context.comparison_label(&diff.compare_context),
        "baseStatus": diff.base_status(),
        "compareStatus": diff.compare_status(),
        "counts": {
            "new": diff.keys_of(ScanComparisonClass::New).len(),
            "reopened": diff.keys_of(ScanComparisonClass::Reopened).len(),
            "persisting": diff.keys_of(ScanComparisonClass::Persisting).len(),
            "resolved": diff.keys_of(ScanComparisonClass::Resolved).len(),
            "notRescanned": diff.keys_of(ScanComparisonClass::NotRescanned).len(),
            "uncertainMatches": diff.comparison.uncertain.len(),
            "changed": changed.len(),
            "stable": diff.stable_count(),
        },
        "warnings": diff.warnings,
        "decisionSummary": diff.decision_summary.as_ref().map(decision_summary_json),
        "new": diff.keys_of(ScanComparisonClass::New),
        "reopened": diff.keys_of(ScanComparisonClass::Reopened),
        "resolved": diff.keys_of(ScanComparisonClass::Resolved),
        "absenceCoverage": absence_coverage_json(&diff.comparison),
        "notRescanned": diff.not_rescanned().iter().map(|(key, reason)| {
            serde_json::json!({"findingKey": key, "reason": reason})
        }).collect::<Vec<_>>(),
        "uncertainMatches": diff.comparison.uncertain.iter().map(uncertain_match_json).collect::<Vec<_>>(),
        "changed": changed.iter().map(runs_change_json).collect::<Vec<_>>(),
    })
}

fn absence_coverage_json(comparison: &ScanRunComparison) -> Vec<Value> {
    comparison.findings.iter().filter(|row| row.after.is_none()).map(|row| {
        serde_json::json!({
            "findingKey": row.stable_key,
            "status": if row.reassessment_block.is_some() { "not_reassessed" } else { "not_observed" },
            "reason": row.reassessment_block,
        })
    }).collect()
}

fn decision_summary_json(summary: &RunsDiffDecisionSummary) -> Value {
    serde_json::json!({
        "identities": summary.identities,
        "withStoredDecision": summary.with_stored_decision,
        "carryForward": summary.carry_forward,
        "conflicts": summary.conflicts,
    })
}

fn uncertain_match_json(row: &ScanUncertainMatch) -> Value {
    serde_json::json!({
        "baseFindingKey": row.base_key,
        "compareFindingKey": row.compare_key,
        "before": signature_json(&row.before),
        "after": signature_json(&row.after),
        "reason": row.reason,
    })
}

fn runs_change_json(change: &RunsFindingChange) -> Value {
    serde_json::json!({
        "findingKey": change.finding_key,
        "before": signature_json(&change.before),
        "after": signature_json(&change.after),
    })
}

fn signature_json(signature: &ScanFindingSignature) -> Value {
    serde_json::json!({
        "severity": signature.severity,
        "confidence": signature.confidence,
        "verdict": signature.verdict,
    })
}

fn runs_diff_plain(diff: &RunsDiff) -> String {
    let mut lines = vec![diff_title(diff), diff_status(diff), diff_counts(diff)];
    lines.push(format!("Base source: {}", diff.base_source.label()));
    lines.push(format!("Later source: {}", diff.compare_source.label()));
    lines.push(format!(
        "Threat model: {}",
        diff.base_context.comparison_label(&diff.compare_context)
    ));
    lines.push(format!("Base threat model: {}", diff.base_context.label()));
    lines.push(format!(
        "Later threat model: {}",
        diff.compare_context.label()
    ));
    append_absence_coverage(&mut lines, &diff.comparison);
    append_warnings(&mut lines, &diff.warnings);
    append_decision_summary(&mut lines, diff.decision_summary.as_ref());
    append_named_ids(&mut lines, "New", &diff.keys_of(ScanComparisonClass::New));
    append_named_ids(
        &mut lines,
        "Reopened",
        &diff.keys_of(ScanComparisonClass::Reopened),
    );
    append_uncertain_rows(&mut lines, &diff.comparison.uncertain);
    append_named_ids(
        &mut lines,
        "Resolved",
        &diff.keys_of(ScanComparisonClass::Resolved),
    );
    append_not_rescanned(&mut lines, &diff.not_rescanned());
    append_change_rows(&mut lines, &diff.changed());
    format!("{}\n", lines.join("\n"))
}

fn append_absence_coverage(lines: &mut Vec<String>, comparison: &ScanRunComparison) {
    for row in comparison.findings.iter().filter(|row| row.after.is_none()) {
        let assessment = row
            .reassessment_block
            .as_deref()
            .unwrap_or("covered but not observed; absence alone is not a fix");
        lines.push(format!("Reassessment {}: {assessment}", row.stable_key));
    }
}

fn diff_title(diff: &RunsDiff) -> String {
    format!(
        "Run diff {} -> {}",
        diff.comparison.base_run_id, diff.comparison.compare_run_id
    )
}

fn diff_counts(diff: &RunsDiff) -> String {
    format!(
        "new={} reopened={} persisting={} resolved={} not_rescanned={} uncertain={} changed={} stable={}",
        diff.keys_of(ScanComparisonClass::New).len(),
        diff.keys_of(ScanComparisonClass::Reopened).len(),
        diff.keys_of(ScanComparisonClass::Persisting).len(),
        diff.keys_of(ScanComparisonClass::Resolved).len(),
        diff.keys_of(ScanComparisonClass::NotRescanned).len(),
        diff.comparison.uncertain.len(),
        diff.changed().len(),
        diff.stable_count(),
    )
}

fn diff_status(diff: &RunsDiff) -> String {
    format!(
        "status: {} -> {}",
        diff.base_status(),
        diff.compare_status()
    )
}

fn append_warnings(lines: &mut Vec<String>, warnings: &[String]) {
    lines.extend(warnings.iter().map(|warning| format!("warning: {warning}")));
}

fn append_decision_summary(lines: &mut Vec<String>, summary: Option<&RunsDiffDecisionSummary>) {
    let Some(summary) = summary else {
        return;
    };
    lines.push(format!(
        "decisions: identities={} stored={} carry_forward={} conflicts={}",
        summary.identities, summary.with_stored_decision, summary.carry_forward, summary.conflicts
    ));
}

fn append_named_ids(lines: &mut Vec<String>, label: &str, finding_keys: &[&str]) {
    if !finding_keys.is_empty() {
        lines.push(format!("{label}:"));
        lines.extend(
            finding_keys
                .iter()
                .map(|finding_key| format!("  {finding_key}")),
        );
    }
}

fn append_not_rescanned(lines: &mut Vec<String>, rows: &[(&str, &str)]) {
    if rows.is_empty() {
        return;
    }
    lines.push("Not rescanned (absence unproven):".to_string());
    lines.extend(
        rows.iter()
            .map(|(finding_key, reason)| format!("  {finding_key} — {reason}")),
    );
}

fn append_uncertain_rows(lines: &mut Vec<String>, rows: &[ScanUncertainMatch]) {
    if rows.is_empty() {
        return;
    }
    lines.push("Uncertain matches:".to_string());
    lines.extend(rows.iter().map(format_uncertain_row));
}

fn format_uncertain_row(row: &ScanUncertainMatch) -> String {
    format!(
        "  {} -> {} severity:{} -> {} confidence:{} -> {} verdict:{} -> {} ({})",
        row.base_key,
        row.compare_key,
        display_option(&row.before.severity),
        display_option(&row.after.severity),
        display_option(&row.before.confidence),
        display_option(&row.after.confidence),
        display_option(&row.before.verdict),
        display_option(&row.after.verdict),
        row.reason
    )
}

fn append_change_rows(lines: &mut Vec<String>, changed: &[RunsFindingChange]) {
    if changed.is_empty() {
        return;
    }
    lines.push("Changed:".to_string());
    lines.extend(changed.iter().map(format_change_row));
}

fn format_change_row(change: &RunsFindingChange) -> String {
    format!(
        "  {} severity:{} -> {} confidence:{} -> {} verdict:{} -> {}",
        change.finding_key,
        display_option(&change.before.severity),
        display_option(&change.after.severity),
        display_option(&change.before.confidence),
        display_option(&change.after.confidence),
        display_option(&change.before.verdict),
        display_option(&change.after.verdict)
    )
}

fn display_option(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("-")
}
