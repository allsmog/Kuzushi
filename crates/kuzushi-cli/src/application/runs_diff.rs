use anyhow::{Context, Result};
use kuzushi_core::findings::{ReviewDecisionVerdict, TriageVerdict};
use kuzushi_core::{
    load_run_summary, run_artifact_path, workspace_findings_db_path, FindingStore, WorkspaceTarget,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
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
    pub(crate) base_run_id: String,
    pub(crate) compare_run_id: String,
    pub(crate) base_status: String,
    pub(crate) compare_status: String,
    pub(crate) new: Vec<String>,
    pub(crate) not_seen: Vec<String>,
    pub(crate) uncertain_matches: Vec<RunsUncertainMatch>,
    pub(crate) changed: Vec<RunsFindingChange>,
    pub(crate) stable: usize,
    pub(crate) warnings: Vec<String>,
    pub(crate) decision_summary: Option<RunsDiffDecisionSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunsFindingChange {
    pub(crate) finding_key: String,
    pub(crate) before: RunsFindingSignature,
    pub(crate) after: RunsFindingSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunsUncertainMatch {
    pub(crate) base_finding_key: String,
    pub(crate) compare_finding_key: String,
    pub(crate) before: RunsFindingSignature,
    pub(crate) after: RunsFindingSignature,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunsFindingSignature {
    pub(crate) severity: Option<String>,
    pub(crate) confidence: Option<String>,
    pub(crate) verdict: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunsFindingRow {
    signature: RunsFindingSignature,
    match_key: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RunsDiffDecisionSummary {
    pub(crate) identities: usize,
    pub(crate) with_stored_decision: usize,
    pub(crate) carry_forward: usize,
    pub(crate) conflicts: usize,
}

pub(crate) fn runs_diff(
    target: &Path,
    base_run_id: &str,
    compare_run_id: &str,
) -> Result<RunsDiff> {
    let base_status = load_run_status(target, base_run_id);
    let compare_status = load_run_status(target, compare_run_id);
    let base = load_run_findings(target, base_run_id)?;
    let compare = load_run_findings(target, compare_run_id)?;
    let mut warnings =
        runs_diff_warnings(base_run_id, &base_status, compare_run_id, &compare_status);
    let decision_summary = load_decision_summary(target, &compare, &mut warnings);
    let uncertain_matches = uncertain_finding_matches(&base, &compare);
    let uncertain_base_keys = uncertain_base_keys(&uncertain_matches);
    let uncertain_compare_keys = uncertain_compare_keys(&uncertain_matches);
    Ok(RunsDiff {
        base_run_id: base_run_id.to_string(),
        compare_run_id: compare_run_id.to_string(),
        warnings,
        base_status,
        compare_status,
        new: only_in(&compare, &base, &uncertain_compare_keys),
        not_seen: only_in(&base, &compare, &uncertain_base_keys),
        uncertain_matches,
        changed: changed_findings(&base, &compare),
        stable: stable_finding_count(&base, &compare),
        decision_summary,
    })
}

fn uncertain_base_keys(matches: &[RunsUncertainMatch]) -> BTreeSet<String> {
    matches
        .iter()
        .map(|row| row.base_finding_key.clone())
        .collect()
}

fn uncertain_compare_keys(matches: &[RunsUncertainMatch]) -> BTreeSet<String> {
    matches
        .iter()
        .map(|row| row.compare_finding_key.clone())
        .collect()
}

fn load_run_status(target: &Path, run_id: &str) -> String {
    load_run_summary(target, run_id)
        .map(|summary| normalize_run_status(&summary.status))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn normalize_run_status(status: &str) -> String {
    match status.trim().to_ascii_lowercase().as_str() {
        "" => "unknown".to_string(),
        other => other.to_string(),
    }
}

fn runs_diff_warnings(
    base_run_id: &str,
    base_status: &str,
    compare_run_id: &str,
    compare_status: &str,
) -> Vec<String> {
    [
        run_status_warning(base_run_id, base_status),
        run_status_warning(compare_run_id, compare_status),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn run_status_warning(run_id: &str, status: &str) -> Option<String> {
    if matches!(status, "completed" | "unknown") {
        return None;
    }
    Some(format!(
        "{run_id}: run status {status}; not_seen entries may reflect incomplete coverage"
    ))
}

fn load_decision_summary(
    target: &Path,
    compare: &BTreeMap<String, RunsFindingRow>,
    warnings: &mut Vec<String>,
) -> Option<RunsDiffDecisionSummary> {
    let db_path = workspace_findings_db_path(target);
    if !db_path.exists() {
        return None;
    }
    let store = match FindingStore::open(&db_path) {
        Ok(store) => store,
        Err(error) => {
            warnings.push(format!("decision summary unavailable: {error:#}"));
            return None;
        }
    };
    Some(decision_summary_from_store(&store, compare, warnings))
}

fn decision_summary_from_store(
    store: &FindingStore,
    compare: &BTreeMap<String, RunsFindingRow>,
    warnings: &mut Vec<String>,
) -> RunsDiffDecisionSummary {
    let mut summary = RunsDiffDecisionSummary::default();
    for (identity_id, row) in compare.iter().filter(|(key, _)| is_identity_key(key)) {
        summary.identities += 1;
        match store.latest_review_decision_for_identity(identity_id) {
            Ok(Some(record)) => {
                summary.add_stored_decision(&record.decision.verdict, &row.signature)
            }
            Ok(None) => {}
            Err(error) => warnings.push(format!(
                "decision summary unavailable for {identity_id}: {error:#}"
            )),
        }
    }
    summary
}

fn is_identity_key(key: &str) -> bool {
    key.starts_with("fi_")
}

impl RunsDiffDecisionSummary {
    fn add_stored_decision(
        &mut self,
        stored: &ReviewDecisionVerdict,
        signature: &RunsFindingSignature,
    ) {
        self.with_stored_decision += 1;
        match snapshot_review_verdict(signature) {
            Some(snapshot) if snapshot != *stored => self.conflicts += 1,
            Some(_) => {}
            None => self.carry_forward += 1,
        }
    }
}

fn snapshot_review_verdict(signature: &RunsFindingSignature) -> Option<ReviewDecisionVerdict> {
    let verdict = signature.verdict.as_deref()?;
    ReviewDecisionVerdict::from_str(verdict).or_else(|| {
        TriageVerdict::try_from(verdict)
            .ok()
            .map(ReviewDecisionVerdict::from_triage_verdict)
    })
}

fn only_in(
    left: &BTreeMap<String, RunsFindingRow>,
    right: &BTreeMap<String, RunsFindingRow>,
    excluded: &BTreeSet<String>,
) -> Vec<String> {
    left.keys()
        .filter(|finding_key| !right.contains_key(*finding_key) && !excluded.contains(*finding_key))
        .cloned()
        .collect()
}

fn stable_finding_count(
    base: &BTreeMap<String, RunsFindingRow>,
    compare: &BTreeMap<String, RunsFindingRow>,
) -> usize {
    base.iter()
        .filter(|(finding_key, before)| {
            compare
                .get(*finding_key)
                .is_some_and(|after| after.signature == before.signature)
        })
        .count()
}

fn changed_findings(
    base: &BTreeMap<String, RunsFindingRow>,
    compare: &BTreeMap<String, RunsFindingRow>,
) -> Vec<RunsFindingChange> {
    base.iter()
        .filter_map(|(finding_key, before)| changed_finding(finding_key, before, compare))
        .collect()
}

fn changed_finding(
    finding_key: &str,
    before: &RunsFindingRow,
    compare: &BTreeMap<String, RunsFindingRow>,
) -> Option<RunsFindingChange> {
    let after = compare.get(finding_key)?;
    (after.signature != before.signature).then(|| RunsFindingChange {
        finding_key: finding_key.to_string(),
        before: before.signature.clone(),
        after: after.signature.clone(),
    })
}

fn load_run_findings(target: &Path, run_id: &str) -> Result<BTreeMap<String, RunsFindingRow>> {
    let path = run_artifact_path(target, run_id, run_findings_artifact_leaf());
    let body =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let value = serde_json::from_str::<Value>(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    Ok(finding_array(&value)
        .into_iter()
        .filter_map(finding_row)
        .collect())
}

fn run_findings_artifact_leaf() -> &'static str {
    "findings.json"
}

fn finding_array(value: &Value) -> Vec<&Value> {
    value
        .as_array()
        .map(|items| items.iter().collect())
        .or_else(|| {
            value
                .get("findings")
                .and_then(Value::as_array)
                .map(|items| items.iter().collect())
        })
        .unwrap_or_default()
}

fn finding_row(finding: &Value) -> Option<(String, RunsFindingRow)> {
    let finding_key = finding_key(finding)?;
    Some((
        finding_key,
        RunsFindingRow {
            signature: RunsFindingSignature {
                severity: string_field(
                    finding,
                    &["severity", "displaySeverity", "display_severity"],
                ),
                confidence: nested_scalar_field(finding, "triage", &["confidence"]),
                verdict: nested_string_field(finding, "triage", &["verdict"]),
            },
            match_key: finding_uncertain_match_key(finding),
        },
    ))
}

fn uncertain_finding_matches(
    base: &BTreeMap<String, RunsFindingRow>,
    compare: &BTreeMap<String, RunsFindingRow>,
) -> Vec<RunsUncertainMatch> {
    let base_candidates = unmatched_by_match_key(base, compare);
    let compare_candidates = unmatched_by_match_key(compare, base);
    base_candidates
        .iter()
        .filter_map(|(match_key, base_rows)| {
            uncertain_match_row(base_rows, compare_candidates.get(match_key)?)
        })
        .collect()
}

fn unmatched_by_match_key(
    source: &BTreeMap<String, RunsFindingRow>,
    other: &BTreeMap<String, RunsFindingRow>,
) -> BTreeMap<String, Vec<(String, RunsFindingRow)>> {
    let mut grouped = BTreeMap::<String, Vec<(String, RunsFindingRow)>>::new();
    for (key, row) in source.iter().filter(|(key, _)| !other.contains_key(*key)) {
        let Some(match_key) = row.match_key.as_ref() else {
            continue;
        };
        grouped
            .entry(match_key.clone())
            .or_default()
            .push((key.clone(), row.clone()));
    }
    grouped
}

fn uncertain_match_row(
    base_rows: &[(String, RunsFindingRow)],
    compare_rows: &[(String, RunsFindingRow)],
) -> Option<RunsUncertainMatch> {
    let ([(base_key, base)], [(compare_key, compare)]) = (base_rows, compare_rows) else {
        return None;
    };
    Some(RunsUncertainMatch {
        base_finding_key: base_key.clone(),
        compare_finding_key: compare_key.clone(),
        before: base.signature.clone(),
        after: compare.signature.clone(),
        reason: "same tool/rule/file/title but different identity or fingerprint; review before carrying decisions".to_string(),
    })
}

fn finding_key(finding: &Value) -> Option<String> {
    string_field(
        finding,
        &[
            "identityId",
            "identity_id",
            "fingerprint",
            "id",
            "dedupKey",
            "dedup_key",
        ],
    )
}

fn finding_uncertain_match_key(finding: &Value) -> Option<String> {
    let tool = normalized_optional_field(finding, &["tool", "source"]);
    let rule = normalized_optional_field(finding, &["ruleId", "rule_id", "rule"])?;
    let file = normalized_path_field(finding, &["filePath", "file_path", "path"])?;
    let title = normalize_match_token(&finding_title(finding));
    (!title.is_empty()).then(|| {
        format!(
            "{}\u{1f}{rule}\u{1f}{file}\u{1f}{title}",
            tool.unwrap_or_else(|| "-".to_string())
        )
    })
}

fn finding_title(finding: &Value) -> String {
    string_field(finding, &["title", "message", "summary"])
        .or_else(|| {
            finding
                .pointer("/message/text")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .or_else(|| string_field(finding, &["ruleId", "rule_id"]))
        .unwrap_or_else(|| "untitled finding".to_string())
}

fn normalized_optional_field(value: &Value, keys: &[&str]) -> Option<String> {
    string_field(value, keys)
        .map(|value| normalize_match_token(&value))
        .filter(|value| !value.is_empty())
}

fn normalized_path_field(value: &Value, keys: &[&str]) -> Option<String> {
    string_field(value, keys)
        .map(|value| normalize_match_token(&value.replace('\\', "/")))
        .filter(|value| !value.is_empty())
}

fn normalize_match_token(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn nested_string_field(value: &Value, child: &str, keys: &[&str]) -> Option<String> {
    string_field(value, keys).or_else(|| {
        value
            .get(child)
            .and_then(|nested| string_field(nested, keys))
    })
}

fn nested_scalar_field(value: &Value, child: &str, keys: &[&str]) -> Option<String> {
    scalar_field(value, keys).or_else(|| {
        value
            .get(child)
            .and_then(|nested| scalar_field(nested, keys))
    })
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::to_string)
        .next()
}

fn scalar_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .filter(|field| field.is_string() || field.is_number() || field.is_boolean())
        .map(scalar_string)
        .next()
}

fn scalar_string(field: &Value) -> String {
    field
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| field.to_string())
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
    serde_json::json!({
        "baseRunId": diff.base_run_id,
        "compareRunId": diff.compare_run_id,
        "baseStatus": diff.base_status,
        "compareStatus": diff.compare_status,
        "counts": {
            "new": diff.new.len(),
            "notSeen": diff.not_seen.len(),
            "uncertainMatches": diff.uncertain_matches.len(),
            "changed": diff.changed.len(),
            "stable": diff.stable,
        },
        "warnings": diff.warnings,
        "decisionSummary": diff.decision_summary.as_ref().map(decision_summary_json),
        "new": diff.new,
        "notSeen": diff.not_seen,
        "uncertainMatches": diff.uncertain_matches.iter().map(uncertain_match_json).collect::<Vec<_>>(),
        "changed": diff.changed.iter().map(runs_change_json).collect::<Vec<_>>(),
    })
}

fn decision_summary_json(summary: &RunsDiffDecisionSummary) -> Value {
    serde_json::json!({
        "identities": summary.identities,
        "withStoredDecision": summary.with_stored_decision,
        "carryForward": summary.carry_forward,
        "conflicts": summary.conflicts,
    })
}

fn uncertain_match_json(row: &RunsUncertainMatch) -> Value {
    serde_json::json!({
        "baseFindingKey": row.base_finding_key,
        "compareFindingKey": row.compare_finding_key,
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

fn signature_json(signature: &RunsFindingSignature) -> Value {
    serde_json::json!({
        "severity": signature.severity,
        "confidence": signature.confidence,
        "verdict": signature.verdict,
    })
}

fn runs_diff_plain(diff: &RunsDiff) -> String {
    let mut lines = vec![diff_title(diff), diff_status(diff), diff_counts(diff)];
    append_warnings(&mut lines, &diff.warnings);
    append_decision_summary(&mut lines, diff.decision_summary.as_ref());
    append_named_ids(&mut lines, "New", &diff.new);
    append_uncertain_rows(&mut lines, &diff.uncertain_matches);
    append_named_ids(&mut lines, "Not seen in compare run", &diff.not_seen);
    append_change_rows(&mut lines, &diff.changed);
    format!("{}\n", lines.join("\n"))
}

fn diff_title(diff: &RunsDiff) -> String {
    format!("Run diff {} -> {}", diff.base_run_id, diff.compare_run_id)
}

fn diff_counts(diff: &RunsDiff) -> String {
    format!(
        "new={} not_seen={} uncertain={} changed={} stable={}",
        diff.new.len(),
        diff.not_seen.len(),
        diff.uncertain_matches.len(),
        diff.changed.len(),
        diff.stable
    )
}

fn diff_status(diff: &RunsDiff) -> String {
    format!("status: {} -> {}", diff.base_status, diff.compare_status)
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

fn append_named_ids(lines: &mut Vec<String>, label: &str, run_ids: &[String]) {
    if !run_ids.is_empty() {
        lines.push(format!("{label}:"));
        lines.extend(run_ids.iter().map(|finding_key| format!("  {finding_key}")));
    }
}

fn append_uncertain_rows(lines: &mut Vec<String>, rows: &[RunsUncertainMatch]) {
    if rows.is_empty() {
        return;
    }
    lines.push("Uncertain matches:".to_string());
    lines.extend(rows.iter().map(format_uncertain_row));
}

fn format_uncertain_row(row: &RunsUncertainMatch) -> String {
    format!(
        "  {} -> {} severity:{} -> {} confidence:{} -> {} verdict:{} -> {} ({})",
        row.base_finding_key,
        row.compare_finding_key,
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
