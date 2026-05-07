use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunArtifact {
    pub label: String,
    pub path: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunSummary {
    pub run_id: String,
    pub kind: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub target: String,
    pub started_at_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<RunArtifact>,
}

impl RunSummary {
    pub fn running(
        run_id: impl Into<String>,
        kind: impl Into<String>,
        tool: Option<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            kind: kind.into(),
            status: "running".to_string(),
            tool,
            target: target.into(),
            started_at_unix: now_unix(),
            completed_at_unix: None,
            findings: None,
            cost_usd: None,
            error: None,
            artifacts: Vec::new(),
        }
    }

    pub fn complete(mut self) -> Self {
        self.status = "complete".to_string();
        self.completed_at_unix = Some(now_unix());
        self
    }

    pub fn failed(mut self, error: impl Into<String>) -> Self {
        self.status = "failed".to_string();
        self.completed_at_unix = Some(now_unix());
        self.error = Some(error.into());
        self
    }

    pub fn with_findings(mut self, findings: Option<u64>) -> Self {
        self.findings = findings;
        self
    }

    pub fn with_cost(mut self, cost_usd: Option<f64>) -> Self {
        self.cost_usd = cost_usd;
        self
    }

    pub fn with_artifact(mut self, artifact: RunArtifact) -> Self {
        self.artifacts.push(artifact);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct RunTraceStep {
    pub n: usize,
    pub kind: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
}

impl RunTraceStep {
    pub fn new(n: usize, kind: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            n,
            kind: kind.into(),
            label: label.into(),
            latency_ms: None,
            cost_usd: None,
        }
    }

    pub fn with_latency_ms(mut self, latency_ms: Option<u64>) -> Self {
        self.latency_ms = latency_ms;
        self
    }

    pub fn with_cost_usd(mut self, cost_usd: Option<f64>) -> Self {
        self.cost_usd = cost_usd;
        self
    }
}

pub fn new_run_id(prefix: &str) -> String {
    let prefix = prefix
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_ascii_lowercase();
    let prefix = if prefix.is_empty() { "run" } else { &prefix };
    let suffix = Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}-{}", now_unix(), &suffix[..12])
}

pub fn runs_root(target: impl AsRef<Path>) -> PathBuf {
    target.as_ref().join(".kuzushi").join("runs")
}

pub fn run_dir(target: impl AsRef<Path>, run_id: &str) -> PathBuf {
    runs_root(target).join(run_id)
}

pub fn write_run_summary(target: impl AsRef<Path>, summary: &RunSummary) -> Result<PathBuf> {
    let dir = run_dir(target, &summary.run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join("summary.json");
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(summary)?),
    )
    .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

pub fn load_run_summary(target: impl AsRef<Path>, run_id: &str) -> Result<RunSummary> {
    let path = run_dir(target, run_id).join("summary.json");
    let body =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    serde_json::from_str(&body).with_context(|| format!("Could not parse {}", path.display()))
}

pub fn list_run_summaries(target: impl AsRef<Path>) -> Result<Vec<RunSummary>> {
    let root = runs_root(target);
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut summaries = collect_run_summaries(&root)?;
    sort_run_summaries(&mut summaries);
    Ok(summaries)
}

fn collect_run_summaries(root: &Path) -> Result<Vec<RunSummary>> {
    let mut summaries = Vec::new();
    for entry in
        fs::read_dir(&root).with_context(|| format!("Could not read {}", root.display()))?
    {
        let entry = entry?;
        if let Some(summary) = read_run_summary_entry(&entry) {
            summaries.push(summary);
        }
    }
    Ok(summaries)
}

fn read_run_summary_entry(entry: &fs::DirEntry) -> Option<RunSummary> {
    if !is_directory_entry(entry) {
        return None;
    }
    let summary_path = entry.path().join("summary.json");
    read_run_summary_file(&summary_path)
}

fn is_directory_entry(entry: &fs::DirEntry) -> bool {
    entry
        .file_type()
        .map(|file_type| file_type.is_dir())
        .unwrap_or(false)
}

fn read_run_summary_file(summary_path: &Path) -> Option<RunSummary> {
    let body = fs::read_to_string(summary_path).ok()?;
    serde_json::from_str::<RunSummary>(&body).ok()
}

fn sort_run_summaries(summaries: &mut [RunSummary]) {
    summaries.sort_by(|left, right| right.run_id.cmp(&left.run_id));
}

pub fn write_run_artifact_json(
    target: impl AsRef<Path>,
    run_id: &str,
    leaf: &str,
    label: impl Into<String>,
    value: &Value,
) -> Result<RunArtifact> {
    let dir = run_dir(&target, run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join(leaf);
    fs::write(&path, format!("{}\n", serde_json::to_string_pretty(value)?))
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(RunArtifact {
        label: label.into(),
        path: path.display().to_string(),
        kind: "json".to_string(),
    })
}

pub fn append_run_trace_step(
    target: impl AsRef<Path>,
    run_id: &str,
    step: &RunTraceStep,
) -> Result<PathBuf> {
    let dir = run_dir(target, run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join("trace.jsonl");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("Could not open {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(step)?)
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_summary_artifact_and_trace_under_run_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = new_run_id("tool");
        let summary = RunSummary::running(
            run_id.clone(),
            "tool",
            Some("context:build".to_string()),
            tmp.path().display().to_string(),
        );

        let summary_path = write_run_summary(tmp.path(), &summary).unwrap();
        assert!(summary_path.ends_with("summary.json"));
        let result = serde_json::json!({"ok": true});
        let artifact =
            write_run_artifact_json(tmp.path(), &run_id, "result.json", "result", &result).unwrap();
        append_run_trace_step(
            tmp.path(),
            &run_id,
            &RunTraceStep::new(1, "tool", "context:build started"),
        )
        .unwrap();
        write_run_summary(tmp.path(), &summary.complete().with_artifact(artifact)).unwrap();

        let loaded = load_run_summary(tmp.path(), &run_id).unwrap();
        assert_eq!(loaded.status, "complete");
        assert_eq!(loaded.tool.as_deref(), Some("context:build"));
        assert_eq!(loaded.artifacts.len(), 1);
        let trace = fs::read_to_string(run_dir(tmp.path(), &run_id).join("trace.jsonl")).unwrap();
        assert!(trace.contains("context:build started"));
    }

    #[test]
    fn lists_run_summaries_sorted_and_ignores_incomplete_entries() {
        let tmp = tempfile::tempdir().unwrap();

        assert!(list_run_summaries(tmp.path()).unwrap().is_empty());

        let first = RunSummary::running("run-a", "scan", None, "target-a").complete();
        let second =
            RunSummary::running("run-b", "tool", Some("ctx:build".to_string()), "target-b")
                .complete();
        write_run_summary(tmp.path(), &first).unwrap();
        write_run_summary(tmp.path(), &second).unwrap();

        let root = runs_root(tmp.path());
        fs::write(root.join("not-a-run"), "ignored").unwrap();
        fs::create_dir_all(root.join("missing-summary")).unwrap();
        fs::create_dir_all(root.join("invalid-summary")).unwrap();
        fs::write(root.join("invalid-summary").join("summary.json"), "{").unwrap();

        let run_ids = list_run_summaries(tmp.path())
            .unwrap()
            .into_iter()
            .map(|summary| summary.run_id)
            .collect::<Vec<_>>();

        assert_eq!(run_ids, vec!["run-b", "run-a"]);
    }
}
