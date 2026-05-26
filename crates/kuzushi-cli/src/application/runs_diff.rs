use anyhow::{Context, Result};
use kuzushi_core::run_artifacts::canonical_run_artifact_spec;
use kuzushi_core::{run_artifact_path, WorkspaceTarget};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn runs_diff_command(
    target: Option<PathBuf>,
    base_run_id: &str,
    compare_run_id: &str,
    json: bool,
) -> Result<()> {
    let workspace = WorkspaceTarget::new(target.unwrap_or_else(|| PathBuf::from(".")))?;
    let diff = runs_diff(workspace.root(), base_run_id, compare_run_id)?;
    print!("{}", runs_diff_output(&diff, json)?);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunsDiff {
    pub(crate) base_run_id: String,
    pub(crate) compare_run_id: String,
    pub(crate) new: Vec<String>,
    pub(crate) fixed: Vec<String>,
    pub(crate) drifted: Vec<RunsFindingDrift>,
    pub(crate) stable: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunsFindingDrift {
    pub(crate) fingerprint: String,
    pub(crate) before: RunsFindingSignature,
    pub(crate) after: RunsFindingSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunsFindingSignature {
    pub(crate) severity: Option<String>,
    pub(crate) confidence: Option<String>,
    pub(crate) verdict: Option<String>,
}

pub(crate) fn runs_diff(
    target: &Path,
    base_run_id: &str,
    compare_run_id: &str,
) -> Result<RunsDiff> {
    let base = load_run_findings(target, base_run_id)?;
    let compare = load_run_findings(target, compare_run_id)?;
    Ok(RunsDiff {
        base_run_id: base_run_id.to_string(),
        compare_run_id: compare_run_id.to_string(),
        new: only_in(&compare, &base),
        fixed: only_in(&base, &compare),
        drifted: drifted_findings(&base, &compare),
        stable: stable_finding_count(&base, &compare),
    })
}

fn only_in(
    left: &BTreeMap<String, RunsFindingSignature>,
    right: &BTreeMap<String, RunsFindingSignature>,
) -> Vec<String> {
    left.keys()
        .filter(|fingerprint| !right.contains_key(*fingerprint))
        .cloned()
        .collect()
}

fn stable_finding_count(
    base: &BTreeMap<String, RunsFindingSignature>,
    compare: &BTreeMap<String, RunsFindingSignature>,
) -> usize {
    base.iter()
        .filter(|(fingerprint, before)| {
            compare
                .get(*fingerprint)
                .is_some_and(|after| after == *before)
        })
        .count()
}

fn drifted_findings(
    base: &BTreeMap<String, RunsFindingSignature>,
    compare: &BTreeMap<String, RunsFindingSignature>,
) -> Vec<RunsFindingDrift> {
    base.iter()
        .filter_map(|(fingerprint, before)| drifted_finding(fingerprint, before, compare))
        .collect()
}

fn drifted_finding(
    fingerprint: &str,
    before: &RunsFindingSignature,
    compare: &BTreeMap<String, RunsFindingSignature>,
) -> Option<RunsFindingDrift> {
    let after = compare.get(fingerprint)?;
    (after != before).then(|| RunsFindingDrift {
        fingerprint: fingerprint.to_string(),
        before: before.clone(),
        after: after.clone(),
    })
}

fn load_run_findings(
    target: &Path,
    run_id: &str,
) -> Result<BTreeMap<String, RunsFindingSignature>> {
    let path = run_artifact_path(target, run_id, run_findings_artifact_leaf());
    let body =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let value = serde_json::from_str::<Value>(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    Ok(finding_array(&value)
        .into_iter()
        .filter_map(finding_signature)
        .collect())
}

fn run_findings_artifact_leaf() -> &'static str {
    canonical_run_artifact_spec("findings.json")
        .expect("findings artifact must be in shared canonical spec")
        .leaf
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

fn finding_signature(finding: &Value) -> Option<(String, RunsFindingSignature)> {
    let object = finding.as_object()?;
    let fingerprint = object.get("fingerprint")?.as_str()?.to_string();
    Some((
        fingerprint,
        RunsFindingSignature {
            severity: string_field(
                finding,
                &["severity", "displaySeverity", "display_severity"],
            ),
            confidence: nested_scalar_field(finding, "triage", &["confidence"]),
            verdict: nested_string_field(finding, "triage", &["verdict"]),
        },
    ))
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

fn runs_diff_output(diff: &RunsDiff, json: bool) -> Result<String> {
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
        "counts": {
            "new": diff.new.len(),
            "fixed": diff.fixed.len(),
            "drifted": diff.drifted.len(),
            "stable": diff.stable,
        },
        "new": diff.new,
        "fixed": diff.fixed,
        "drifted": diff.drifted.iter().map(runs_drift_json).collect::<Vec<_>>(),
    })
}

fn runs_drift_json(drift: &RunsFindingDrift) -> Value {
    serde_json::json!({
        "fingerprint": drift.fingerprint,
        "before": signature_json(&drift.before),
        "after": signature_json(&drift.after),
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
    let mut lines = vec![diff_title(diff), diff_counts(diff)];
    append_named_ids(&mut lines, "New", &diff.new);
    append_named_ids(&mut lines, "Fixed", &diff.fixed);
    append_drift_rows(&mut lines, &diff.drifted);
    format!("{}\n", lines.join("\n"))
}

fn diff_title(diff: &RunsDiff) -> String {
    format!("Run diff {} -> {}", diff.base_run_id, diff.compare_run_id)
}

fn diff_counts(diff: &RunsDiff) -> String {
    format!(
        "new={} fixed={} drifted={} stable={}",
        diff.new.len(),
        diff.fixed.len(),
        diff.drifted.len(),
        diff.stable
    )
}

fn append_named_ids(lines: &mut Vec<String>, label: &str, run_ids: &[String]) {
    if !run_ids.is_empty() {
        lines.push(format!("{label}:"));
        lines.extend(run_ids.iter().map(|fingerprint| format!("  {fingerprint}")));
    }
}

fn append_drift_rows(lines: &mut Vec<String>, drifted: &[RunsFindingDrift]) {
    if drifted.is_empty() {
        return;
    }
    lines.push("Drifted:".to_string());
    lines.extend(drifted.iter().map(format_drift_row));
}

fn format_drift_row(drift: &RunsFindingDrift) -> String {
    format!(
        "  {} severity:{} -> {} confidence:{} -> {} verdict:{} -> {}",
        drift.fingerprint,
        display_option(&drift.before.severity),
        display_option(&drift.after.severity),
        display_option(&drift.before.confidence),
        display_option(&drift.after.confidence),
        display_option(&drift.before.verdict),
        display_option(&drift.after.verdict)
    )
}

fn display_option(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("-")
}
