use crate::ShellApp;
use kuzushi_core::sorted_finding_aliases;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AliasReferenceModel {
    pub(crate) rows: Vec<AliasReferenceRow>,
    pub(crate) empty_message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AliasReferenceRow {
    pub(crate) alias: String,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReplayModel {
    pub(crate) run_id: String,
    pub(crate) artifacts: Vec<RunArtifactDetail>,
    pub(crate) metadata_missing: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TraceModel {
    pub(crate) run_id: String,
    pub(crate) artifacts: Vec<RunArtifactDetail>,
    pub(crate) trace_exists: bool,
    pub(crate) steps: Vec<TraceStep>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RunArtifactDetail {
    pub(crate) label: &'static str,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TraceStep {
    pub(crate) n: usize,
    pub(crate) kind: String,
    pub(crate) label: String,
    pub(crate) latency_ms: Option<u64>,
    pub(crate) cost_usd: Option<f64>,
    pub(crate) module_id: Option<String>,
    pub(crate) verb: Option<String>,
    pub(crate) parent_step: Option<usize>,
    pub(crate) severity: Option<String>,
    pub(crate) started_at_ms: Option<u64>,
}

pub(crate) fn replay_model(app: &ShellApp, run_id: &str) -> ReplayModel {
    let metadata = run_metadata_artifact_detail(app, run_id);
    let triage = run_artifact_detail(app, run_id, "triage", "triage.jsonl");
    ReplayModel {
        run_id: run_id.to_string(),
        metadata_missing: !metadata.path.exists(),
        artifacts: vec![metadata.into_display(), triage.into_display()],
    }
}

pub(crate) fn trace_model(app: &ShellApp, run_id: &str) -> TraceModel {
    let trace = run_artifact_detail(app, run_id, "trace", "trace.jsonl");
    let triage = run_artifact_detail(app, run_id, "triage", "triage.jsonl");
    let verify = run_artifact_detail(app, run_id, "verify", "verify.jsonl");
    TraceModel {
        run_id: run_id.to_string(),
        trace_exists: trace.path.exists(),
        steps: parse_trace_jsonl(&trace.path),
        artifacts: vec![
            trace.into_display(),
            triage.into_display(),
            verify.into_display(),
        ],
    }
}

pub(crate) fn alias_reference_model(app: &ShellApp) -> AliasReferenceModel {
    AliasReferenceModel {
        rows: sorted_finding_aliases(&app.findings)
            .into_iter()
            .take(3)
            .map(|(alias, finding)| AliasReferenceRow {
                alias,
                detail: format!(
                    "{} {}",
                    short_fingerprint(&finding.fingerprint),
                    finding.title
                ),
            })
            .collect(),
        empty_message: "aliases: load findings first with findings",
    }
}

fn run_artifact_detail(
    app: &ShellApp,
    run_id: &str,
    label: &'static str,
    leaf: &str,
) -> RunArtifactPath {
    RunArtifactPath {
        label,
        path: run_artifact_path(app, run_id, leaf),
    }
}

fn run_metadata_artifact_detail(app: &ShellApp, run_id: &str) -> RunArtifactPath {
    let canonical = run_artifact_path(app, run_id, "run.json");
    let path = if canonical.exists() {
        canonical
    } else {
        legacy_metadata_path(app, run_id).unwrap_or(canonical)
    };
    RunArtifactPath {
        label: "metadata",
        path,
    }
}

fn legacy_metadata_path(app: &ShellApp, run_id: &str) -> Option<PathBuf> {
    let legacy = run_artifact_path(app, run_id, "summary.json");
    legacy.exists().then_some(legacy)
}

fn run_artifact_path(app: &ShellApp, run_id: &str, leaf: &str) -> PathBuf {
    runs_root(app).join(run_id).join(leaf)
}

fn runs_root(app: &ShellApp) -> PathBuf {
    app.target
        .as_deref()
        .map(|target| target.join(".kuzushi/runs"))
        .unwrap_or_else(|| PathBuf::from(".kuzushi/runs"))
}

fn parse_trace_jsonl(path: &Path) -> Vec<TraceStep> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Vec::new();
    };
    trace_steps_from_text(text)
}

fn trace_steps_from_text(text: &str) -> Vec<TraceStep> {
    text.lines()
        .enumerate()
        .filter_map(|(idx, raw)| trace_step_from_line(idx, raw))
        .collect()
}

fn trace_step_from_line(idx: usize, raw: &str) -> Option<TraceStep> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let value = serde_json::from_str::<serde_json::Value>(raw).ok()?;
    Some(TraceStep {
        n: step_number(&value, idx),
        kind: string_field(&value, "kind").unwrap_or_else(|| "step".to_string()),
        label: string_field(&value, "label").unwrap_or_else(|| "(no label)".to_string()),
        latency_ms: u64_field(&value, "latency_ms"),
        cost_usd: value.get("cost_usd").and_then(serde_json::Value::as_f64),
        module_id: string_field(&value, "module_id"),
        verb: string_field(&value, "verb"),
        parent_step: u64_field(&value, "parent_step").map(|n| n as usize),
        severity: string_field(&value, "severity"),
        started_at_ms: u64_field(&value, "started_at_ms"),
    })
}

fn step_number(value: &serde_json::Value, idx: usize) -> usize {
    u64_field(value, "n").map(|n| n as usize).unwrap_or(idx + 1)
}

fn u64_field(value: &serde_json::Value, key: &str) -> Option<u64> {
    value.get(key).and_then(serde_json::Value::as_u64)
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn short_fingerprint(value: &str) -> String {
    value.chars().take(8).collect()
}

struct RunArtifactPath {
    label: &'static str,
    path: PathBuf,
}

impl RunArtifactPath {
    fn into_display(self) -> RunArtifactDetail {
        let display = self.path.display().to_string();
        let detail = if self.path.exists() {
            display
        } else {
            format!("{display} (missing)")
        };
        RunArtifactDetail {
            label: self.label,
            detail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{Finding, Severity, V2Config};

    #[test]
    fn alias_reference_model_projects_top_aliases() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.findings = vec![
            named_finding("bbbb2222bbbb", "second"),
            named_finding("aaaa1111aaaa", "first"),
            named_finding("cccc3333cccc", "third"),
            named_finding("dddd4444dddd", "hidden fourth"),
        ];

        let model = alias_reference_model(&app);

        assert_eq!(model.rows.len(), 3);
        assert_eq!(model.rows[0].alias, "F-0001");
        assert_eq!(model.rows[0].detail, "aaaa1111 first");
        assert!(model.rows.iter().all(|row| !row.detail.contains("hidden")));
    }

    #[test]
    fn alias_reference_model_explains_empty_findings() {
        let app = ShellApp::new(V2Config::default(), None);

        let model = alias_reference_model(&app);

        assert!(model.rows.is_empty());
        assert_eq!(
            model.empty_message,
            "aliases: load findings first with findings"
        );
    }

    fn named_finding(fingerprint: &str, title: &str) -> Finding {
        let mut finding =
            Finding::new_semgrep("demo.rule", "src/app.rs", 1, None, Severity::High, title);
        finding.fingerprint = fingerprint.to_string();
        finding.title = title.to_string();
        finding
    }
}
