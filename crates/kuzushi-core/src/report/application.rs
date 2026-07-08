use super::artifact_summary::{summarize_json_artifact, summarize_text_artifact};
use super::failure_handoff::load_report_failure_handoffs;
use super::markdown::render_report_markdown;
use super::{CanonicalReportArtifact, RunReportBuild};
use crate::artifact_contract::{
    canonical_run_artifact_spec, CanonicalRunArtifactSpec, CANONICAL_RUN_ARTIFACTS,
    OPTIONAL_RUN_ARTIFACTS,
    TOOL_INPUT_ARTIFACTS, TOOL_RESULT_ARTIFACTS,
};
use crate::run_artifacts::{
    list_run_summaries, load_run_artifacts, load_run_summary, run_dir, write_run_artifact_text,
    RunArtifact, RunSummary,
};
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub fn build_run_report(target: impl AsRef<Path>, run_id: Option<&str>) -> Result<RunReportBuild> {
    let target = target.as_ref();
    let summary = source_summary(target, run_id)?;
    let declared_artifacts = load_run_artifacts(target, &summary.run_id)?;
    let canonical_artifacts = load_canonical_artifacts(target, &summary.run_id, &declared_artifacts);
    let failure_handoffs = load_report_failure_handoffs(target, &summary.run_id)?;
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

fn load_canonical_artifacts(
    target: &Path,
    run_id: &str,
    declared_artifacts: &[RunArtifact],
) -> Vec<CanonicalReportArtifact> {
    let dir = run_dir(target, run_id);
    let mut artifacts = canonical_report_json_specs()
        .into_iter()
        .map(|spec| load_canonical_artifact(&dir, spec))
        .collect::<Vec<_>>();
    artifacts.extend(load_declared_json_artifacts(&dir, declared_artifacts));
    artifacts.extend(load_canonical_text_artifacts(&dir));
    artifacts.push(generated_report_artifact(&dir));
    artifacts.extend(load_optional_json_artifacts(&dir));
    artifacts.extend(load_optional_text_artifacts(&dir));
    artifacts
}

fn load_declared_json_artifacts(run_dir: &Path, artifacts: &[RunArtifact]) -> Vec<CanonicalReportArtifact> {
    artifacts
        .iter()
        .filter(|artifact| artifact.kind == "json")
        .filter(|artifact| !is_shared_report_leaf(&artifact_leaf(&artifact.path)))
        .filter_map(|artifact| load_declared_json_artifact(run_dir, artifact))
        .collect()
}

fn load_declared_json_artifact(
    run_dir: &Path,
    artifact: &RunArtifact,
) -> Option<CanonicalReportArtifact> {
    let path = declared_artifact_path(run_dir, &artifact.path);
    let file = artifact_leaf(&artifact.path);
    match read_json_file(&path) {
        JsonArtifactRead::Present(value) => Some(CanonicalReportArtifact::present(
            file,
            artifact.label.clone(),
            path.display().to_string(),
            summarize_json_artifact(&value),
        )),
        JsonArtifactRead::Malformed(summary) => Some(CanonicalReportArtifact::present(
            file,
            artifact.label.clone(),
            path.display().to_string(),
            summary,
        )),
        JsonArtifactRead::Missing => None,
    }
}

fn declared_artifact_path(run_dir: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        run_dir.join(path)
    }
}

fn artifact_leaf(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|leaf| leaf.to_str())
        .unwrap_or(path)
        .to_string()
}

fn is_shared_report_leaf(leaf: &str) -> bool {
    CANONICAL_RUN_ARTIFACTS
        .iter()
        .chain(OPTIONAL_RUN_ARTIFACTS.iter())
        .chain(TOOL_INPUT_ARTIFACTS.iter())
        .chain(TOOL_RESULT_ARTIFACTS.iter())
        .any(|spec| spec.leaf == leaf)
}

fn load_canonical_artifact(
    run_dir: &Path,
    spec: &CanonicalRunArtifactSpec,
) -> CanonicalReportArtifact {
    let path = run_dir.join(spec.leaf);
    match read_canonical_json_file(spec.leaf, &path) {
        JsonArtifactRead::Present(value) => CanonicalReportArtifact::present(
            spec.leaf,
            spec.label,
            path.display().to_string(),
            summarize_json_artifact(&value),
        ),
        JsonArtifactRead::Malformed(summary) => CanonicalReportArtifact::present(
            spec.leaf,
            spec.label,
            path.display().to_string(),
            summary,
        ),
        JsonArtifactRead::Missing => {
            CanonicalReportArtifact::missing(spec.leaf, spec.label, path.display().to_string())
        }
    }
}

fn load_canonical_text_artifacts(run_dir: &Path) -> Vec<CanonicalReportArtifact> {
    canonical_report_text_specs()
        .into_iter()
        .map(|spec| load_canonical_text_artifact(run_dir, spec))
        .collect()
}

fn load_canonical_text_artifact(
    run_dir: &Path,
    spec: &CanonicalRunArtifactSpec,
) -> CanonicalReportArtifact {
    let path = run_dir.join(spec.leaf);
    match read_text_file(&path) {
        TextArtifactRead::Present(body) => CanonicalReportArtifact::present(
            spec.leaf,
            spec.label,
            path.display().to_string(),
            summarize_text_artifact(spec.leaf, &body),
        ),
        TextArtifactRead::Malformed(summary) => CanonicalReportArtifact::present(
            spec.leaf,
            spec.label,
            path.display().to_string(),
            summary,
        ),
        TextArtifactRead::Missing => {
            CanonicalReportArtifact::missing(spec.leaf, spec.label, path.display().to_string())
        }
    }
}

fn canonical_report_spec(file: &str) -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec(file).expect("report canonical artifact must be in shared spec")
}

fn canonical_report_json_specs() -> Vec<&'static CanonicalRunArtifactSpec> {
    CANONICAL_RUN_ARTIFACTS
        .iter()
        .filter(|spec| spec.kind == "json")
        .collect()
}

fn canonical_report_text_specs() -> Vec<&'static CanonicalRunArtifactSpec> {
    CANONICAL_RUN_ARTIFACTS
        .iter()
        .filter(|spec| spec.kind == "jsonl")
        .collect()
}

fn load_optional_text_artifacts(run_dir: &Path) -> Vec<CanonicalReportArtifact> {
    OPTIONAL_RUN_ARTIFACTS
        .iter()
        .filter_map(|spec| load_optional_text_artifact(run_dir, spec))
        .collect()
}

fn load_optional_json_artifacts(run_dir: &Path) -> Vec<CanonicalReportArtifact> {
    TOOL_INPUT_ARTIFACTS
        .iter()
        .chain(TOOL_RESULT_ARTIFACTS.iter())
        .filter_map(|spec| load_optional_json_artifact(run_dir, spec))
        .collect()
}

fn load_optional_json_artifact(
    run_dir: &Path,
    spec: &CanonicalRunArtifactSpec,
) -> Option<CanonicalReportArtifact> {
    let path = run_dir.join(spec.leaf);
    match read_json_file(&path) {
        JsonArtifactRead::Present(value) => Some(CanonicalReportArtifact::present(
            spec.leaf,
            spec.label,
            path.display().to_string(),
            summarize_json_artifact(&value),
        )),
        JsonArtifactRead::Malformed(summary) => Some(CanonicalReportArtifact::present(
            spec.leaf,
            spec.label,
            path.display().to_string(),
            summary,
        )),
        JsonArtifactRead::Missing => None,
    }
}

fn load_optional_text_artifact(
    run_dir: &Path,
    spec: &CanonicalRunArtifactSpec,
) -> Option<CanonicalReportArtifact> {
    let path = run_dir.join(spec.leaf);
    match read_text_file(&path) {
        TextArtifactRead::Present(body) => Some(CanonicalReportArtifact::present(
            spec.leaf,
            spec.label,
            path.display().to_string(),
            optional_text_summary(spec.leaf, &body),
        )),
        TextArtifactRead::Malformed(summary) => Some(CanonicalReportArtifact::present(
            spec.leaf,
            spec.label,
            path.display().to_string(),
            summary,
        )),
        TextArtifactRead::Missing => None,
    }
}

fn optional_text_summary(file: &str, body: &str) -> String {
    match file {
        "report.sarif" => sarif_summary(body),
        _ => "artifact present".to_string(),
    }
}

fn sarif_summary(body: &str) -> String {
    let value = match serde_json::from_str::<Value>(body) {
        Ok(value) => value,
        Err(error) => return format!("malformed SARIF JSON: {error}"),
    };
    let Some(runs) = value.get("runs").and_then(Value::as_array) else {
        return "malformed SARIF: missing runs array".to_string();
    };
    let results = sarif_results(runs);
    let mut parts = vec![format!(
        "SARIF report, {} run(s), {} result(s)",
        runs.len(),
        results.len()
    )];
    parts.extend(sarif_count_segment("levels", sarif_level_counts(&results)));
    parts.extend(sarif_count_segment("rules", sarif_rule_counts(&results)));
    parts.extend(sarif_count_segment("files", sarif_file_counts(&results)));
    parts.join(", ")
}

fn sarif_results<'a>(runs: &'a [Value]) -> Vec<&'a Value> {
    runs.iter()
        .filter_map(|run| run.get("results").and_then(Value::as_array))
        .flat_map(|results| results.iter())
        .collect()
}

fn sarif_level_counts(results: &[&Value]) -> BTreeMap<String, usize> {
    count_string_values(results.iter().filter_map(|result| result.get("level")))
}

fn sarif_rule_counts(results: &[&Value]) -> BTreeMap<String, usize> {
    count_string_values(results.iter().filter_map(|result| result.get("ruleId")))
}

fn sarif_file_counts(results: &[&Value]) -> BTreeMap<String, usize> {
    count_string_values(results.iter().flat_map(|result| sarif_result_uris(result)))
}

fn sarif_result_uris(result: &Value) -> Vec<&Value> {
    result
        .get("locations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|location| location.pointer("/physicalLocation/artifactLocation/uri"))
        .collect()
}

fn count_string_values<'a>(values: impl Iterator<Item = &'a Value>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for value in values.filter_map(Value::as_str).filter(|value| !value.trim().is_empty()) {
        *counts.entry(value.to_string()).or_insert(0) += 1;
    }
    counts
}

fn sarif_count_segment(label: &str, counts: BTreeMap<String, usize>) -> Option<String> {
    if counts.is_empty() {
        return None;
    }
    Some(format!("{label} {}", sarif_count_segments(&counts).join(", ")))
}

fn sarif_count_segments(counts: &BTreeMap<String, usize>) -> Vec<String> {
    counts
        .iter()
        .take(8)
        .map(|(value, count)| format!("{value}={count}"))
        .collect()
}

enum JsonArtifactRead {
    Present(Value),
    Malformed(String),
    Missing,
}

enum TextArtifactRead {
    Present(String),
    Malformed(String),
    Missing,
}

fn read_json_file(path: &Path) -> JsonArtifactRead {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return JsonArtifactRead::Malformed("JSON artifact is not a file".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return JsonArtifactRead::Missing;
        }
        Err(_) => return JsonArtifactRead::Malformed("unreadable JSON artifact".to_string()),
    }
    let Ok(body) = fs::read_to_string(path) else {
        return JsonArtifactRead::Malformed("unreadable JSON artifact".to_string());
    };
    match serde_json::from_str(&body) {
        Ok(value) => JsonArtifactRead::Present(value),
        Err(error) => JsonArtifactRead::Malformed(format!("malformed JSON: {error}")),
    }
}

fn read_canonical_json_file(file: &str, path: &Path) -> JsonArtifactRead {
    match read_json_file(path) {
        JsonArtifactRead::Present(value) if !canonical_json_shape_matches(file, &value) => {
            JsonArtifactRead::Malformed("malformed JSON: expected object".to_string())
        }
        result => result,
    }
}

fn canonical_json_shape_matches(file: &str, value: &Value) -> bool {
    let _ = file;
    value.is_object()
}

fn read_text_file(path: &Path) -> TextArtifactRead {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => read_text_artifact_body(path),
        Ok(_) => TextArtifactRead::Malformed("text artifact is not a file".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => TextArtifactRead::Missing,
        Err(_) => TextArtifactRead::Malformed("unreadable text artifact".to_string()),
    }
}

fn read_text_artifact_body(path: &Path) -> TextArtifactRead {
    match fs::read_to_string(path) {
        Ok(body) => TextArtifactRead::Present(body),
        Err(_) => TextArtifactRead::Malformed("unreadable text artifact".to_string()),
    }
}

fn generated_report_artifact(run_dir: &Path) -> CanonicalReportArtifact {
    let spec = canonical_report_spec("report.md");
    let path = run_dir.join(spec.leaf);
    CanonicalReportArtifact::present(
        spec.leaf,
        spec.label,
        path.display().to_string(),
        "generated report",
    )
}

fn write_report_markdown(target: &Path, run_id: &str, markdown: &str) -> Result<PathBuf> {
    let spec = canonical_report_spec("report.md");
    let artifact = write_run_artifact_text(target, run_id, spec.leaf, spec.label, spec.kind, markdown)?;
    Ok(PathBuf::from(artifact.path))
}
