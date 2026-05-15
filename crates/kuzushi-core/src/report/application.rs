use super::failure_handoff::load_report_failure_handoffs;
use super::markdown::render_report_markdown;
use super::{CanonicalReportArtifact, RunReportBuild};
use crate::run_artifacts::{
    list_run_summaries, load_run_artifacts, load_run_summary, run_dir, write_run_artifact_text,
    RunSummary,
};
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const CANONICAL_JSON_FILES: &[(&str, &str)] = &[
    ("run.json", "run metadata"),
    ("artifacts.json", "artifact manifest"),
    ("context.json", "context"),
    ("attack-surface.json", "attack surface"),
    ("threat-model.json", "threat model"),
    ("recommendations.json", "recommendations"),
    ("findings.json", "findings"),
    ("proof.json", "proof"),
    ("failures.json", "failure handoff"),
];

const CANONICAL_TEXT_FILES: &[(&str, &str)] = &[
    ("events.jsonl", "run events"),
    ("trace.jsonl", "run trace"),
];

const OPTIONAL_TEXT_FILES: &[(&str, &str, &str)] = &[("report.sarif", "SARIF report", "SARIF report")];

pub fn build_run_report(target: impl AsRef<Path>, run_id: Option<&str>) -> Result<RunReportBuild> {
    let target = target.as_ref();
    let summary = source_summary(target, run_id)?;
    let declared_artifacts = load_run_artifacts(target, &summary.run_id).unwrap_or_default();
    let canonical_artifacts = load_canonical_artifacts(target, &summary.run_id);
    let failure_handoffs = load_report_failure_handoffs(target, &summary.run_id);
    let markdown = render_report_markdown(
        &summary,
        &canonical_artifacts,
        &declared_artifacts,
        &failure_handoffs,
    );
    let report_path = write_report_markdown(target, &summary.run_id, &markdown)?;
    Ok(RunReportBuild::new(
        summary,
        report_path.display().to_string(),
        markdown,
        canonical_artifacts,
        declared_artifacts,
        failure_handoffs,
    ))
}

fn source_summary(target: &Path, run_id: Option<&str>) -> Result<RunSummary> {
    match run_id.filter(|id| !id.trim().is_empty()) {
        Some(run_id) => load_run_summary(target, run_id.trim()),
        None => latest_report_source_summary(target),
    }
}

fn latest_report_source_summary(target: &Path) -> Result<RunSummary> {
    let mut candidates = list_run_summaries(target)?
        .into_iter()
        .filter(report_source_candidate)
        .collect::<Vec<_>>();
    candidates.sort_by_key(report_time_key);
    candidates
        .pop()
        .context("No completed Kuzushi run is available for report:build")
}

fn report_source_candidate(summary: &RunSummary) -> bool {
    summary.status != "running" && summary.tool.as_deref() != Some("report:build")
}

fn report_time_key(summary: &RunSummary) -> (u64, u64, String) {
    (
        summary.completed_at_unix.unwrap_or(summary.started_at_unix),
        summary.started_at_unix,
        summary.run_id.clone(),
    )
}

fn load_canonical_artifacts(target: &Path, run_id: &str) -> Vec<CanonicalReportArtifact> {
    let dir = run_dir(target, run_id);
    let mut artifacts = CANONICAL_JSON_FILES
        .iter()
        .map(|(file, label)| load_canonical_artifact(&dir, file, label))
        .collect::<Vec<_>>();
    artifacts.extend(load_canonical_text_artifacts(&dir));
    artifacts.push(generated_report_artifact(&dir));
    artifacts.extend(load_optional_text_artifacts(&dir));
    artifacts
}

fn load_canonical_artifact(
    run_dir: &Path,
    file: &str,
    label: &str,
) -> CanonicalReportArtifact {
    let path = run_dir.join(file);
    let Some(value) = read_json_file(&path) else {
        return CanonicalReportArtifact::missing(file, label, path.display().to_string());
    };
    CanonicalReportArtifact::present(
        file,
        label,
        path.display().to_string(),
        summarize_json_artifact(&value),
    )
}

fn load_canonical_text_artifacts(run_dir: &Path) -> Vec<CanonicalReportArtifact> {
    CANONICAL_TEXT_FILES
        .iter()
        .map(|(file, label)| load_canonical_text_artifact(run_dir, file, label))
        .collect()
}

fn load_canonical_text_artifact(
    run_dir: &Path,
    file: &str,
    label: &str,
) -> CanonicalReportArtifact {
    let path = run_dir.join(file);
    let Some(body) = read_text_file(&path) else {
        return CanonicalReportArtifact::missing(file, label, path.display().to_string());
    };
    CanonicalReportArtifact::present(
        file,
        label,
        path.display().to_string(),
        summarize_text_artifact(&body),
    )
}

fn load_optional_text_artifacts(run_dir: &Path) -> Vec<CanonicalReportArtifact> {
    OPTIONAL_TEXT_FILES
        .iter()
        .filter_map(|(file, label, summary)| load_optional_text_artifact(run_dir, file, label, summary))
        .collect()
}

fn load_optional_text_artifact(
    run_dir: &Path,
    file: &str,
    label: &str,
    summary: &str,
) -> Option<CanonicalReportArtifact> {
    let path = run_dir.join(file);
    path.exists().then(|| {
        CanonicalReportArtifact::present(file, label, path.display().to_string(), summary)
    })
}

fn read_json_file(path: &Path) -> Option<Value> {
    let body = fs::read_to_string(path).ok()?;
    serde_json::from_str(&body).ok()
}

fn read_text_file(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn summarize_text_artifact(body: &str) -> String {
    format!("{} line(s)", body.lines().count())
}

fn generated_report_artifact(run_dir: &Path) -> CanonicalReportArtifact {
    let path = run_dir.join("report.md");
    CanonicalReportArtifact::present(
        "report.md",
        "human-readable report",
        path.display().to_string(),
        "generated report",
    )
}

fn summarize_json_artifact(value: &Value) -> String {
    if let Some(summary) = text_summary(value) {
        return summary;
    }
    match value {
        Value::Array(items) => format!("{} record(s)", items.len()),
        Value::Object(object) => format!("{} top-level field(s)", object.len()),
        _ => "present".to_string(),
    }
}

fn text_summary(value: &Value) -> Option<String> {
    value
        .get("summary")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| attack_surface_summary(value))
}

fn attack_surface_summary(value: &Value) -> Option<String> {
    let summary = value.get("summary")?.as_object()?;
    let total = summary.get("surfaceCount")?.as_u64()?;
    let high = summary.get("highRisk").and_then(Value::as_u64).unwrap_or(0);
    let mut parts = vec![format!("{total} surface(s)"), format!("{high} high risk")];
    if let Some(max) = summary.get("maxRiskScore").and_then(Value::as_u64) {
        parts.push(format!("max {max}"));
    }
    if let Some(tiers) = risk_tier_summary(summary.get("byRiskTier")) {
        parts.push(format!("tiers {tiers}"));
    }
    Some(parts.join(", "))
}

fn risk_tier_summary(value: Option<&Value>) -> Option<String> {
    let object = value?.as_object()?;
    let mut tiers = object.keys().collect::<Vec<_>>();
    tiers.sort_by(|left, right| {
        tier_rank(left)
            .cmp(&tier_rank(right))
            .then_with(|| left.cmp(right))
    });
    let summary = tiers
        .into_iter()
        .filter_map(|tier| tier_count_segment(tier, object.get(tier)))
        .collect::<Vec<_>>()
        .join(", ");
    (!summary.is_empty()).then_some(summary)
}

fn tier_count_segment(tier: &str, count: Option<&Value>) -> Option<String> {
    let count = count.and_then(Value::as_u64).filter(|count| *count > 0)?;
    Some(format!("{tier}={count}"))
}

fn tier_rank(tier: &str) -> usize {
    match tier {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn write_report_markdown(target: &Path, run_id: &str, markdown: &str) -> Result<PathBuf> {
    let artifact = write_run_artifact_text(
        target,
        run_id,
        "report.md",
        "report",
        "markdown",
        markdown,
    )?;
    Ok(PathBuf::from(artifact.path))
}
