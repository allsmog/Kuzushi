use super::ui_runs_root;
use crate::ShellApp;
use kuzushi_core::run_artifacts::canonical_run_artifact_spec;
use std::path::{Path, PathBuf};

const RUN_TRIAGE_FILE: &str = "triage.jsonl";
const RUN_VERIFY_FILE: &str = "verify.jsonl";

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
    let triage = run_artifact_detail(app, run_id, "triage", RUN_TRIAGE_FILE);
    let metadata_missing = metadata.artifact_state() == RunArtifactState::Missing;
    ReplayModel {
        run_id: run_id.to_string(),
        metadata_missing,
        artifacts: vec![metadata.into_display(), triage.into_display()],
    }
}

pub(crate) fn trace_model(app: &ShellApp, run_id: &str) -> TraceModel {
    let trace = run_artifact_detail(app, run_id, "trace", run_trace_artifact_leaf());
    let triage = run_artifact_detail(app, run_id, "triage", RUN_TRIAGE_FILE);
    let verify = run_artifact_detail(app, run_id, "verify", RUN_VERIFY_FILE);
    let trace_exists = trace.artifact_state() == RunArtifactState::File;
    TraceModel {
        run_id: run_id.to_string(),
        trace_exists,
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
        rows: super::findings::cached_sorted_finding_alias_indices(app)
            .into_iter()
            .take(3)
            .filter_map(|(alias, index)| {
                let finding = app.findings().get(index)?;
                Some(AliasReferenceRow {
                    alias,
                    detail: format!(
                        "{} {}",
                        short_fingerprint(&finding.fingerprint),
                        finding.title
                    ),
                })
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
    RunArtifactPath {
        label: "metadata",
        path: run_artifact_path(app, run_id, run_metadata_artifact_leaf()),
    }
}

fn run_artifact_path(app: &ShellApp, run_id: &str, leaf: &str) -> PathBuf {
    runs_root(app).join(run_id).join(leaf)
}

fn run_metadata_artifact_leaf() -> &'static str {
    canonical_run_artifact_spec("run.json")
        .expect("run metadata artifact must be in shared canonical spec")
        .leaf
}

fn run_trace_artifact_leaf() -> &'static str {
    canonical_run_artifact_spec("trace.jsonl")
        .expect("trace artifact must be in shared canonical spec")
        .leaf
}

fn runs_root(app: &ShellApp) -> PathBuf {
    ui_runs_root(app.target())
}

fn parse_trace_jsonl(path: &Path) -> Vec<TraceStep> {
    match artifact_state(path) {
        RunArtifactState::Missing => return Vec::new(),
        RunArtifactState::NonFile => return vec![non_file_trace_artifact_step()],
        RunArtifactState::Invalid => return vec![malformed_trace_artifact_step()],
        RunArtifactState::File => {}
    }

    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return vec![malformed_trace_artifact_step()],
    };
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(_) => return vec![malformed_trace_artifact_step()],
    };
    trace_steps_from_text(text)
}

fn trace_steps_from_text(text: &str) -> Vec<TraceStep> {
    text.lines()
        .enumerate()
        .filter_map(|(idx, raw)| trace_step_from_line(idx, raw.trim()))
        .collect()
}

fn trace_step_from_line(idx: usize, raw: &str) -> Option<TraceStep> {
    if raw.is_empty() {
        return None;
    }
    let value = match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(value) if value.is_object() => value,
        Ok(_) | Err(_) => return Some(malformed_trace_step(idx)),
    };
    Some(TraceStep {
        n: step_number(&value, idx),
        kind: string_field(&value, "kind").unwrap_or_else(|| "step".to_string()),
        label: string_field(&value, "label").unwrap_or_else(|| "(no label)".to_string()),
        latency_ms: u64_alias_field(&value, "latency_ms", "latencyMs"),
        cost_usd: f64_alias_field(&value, "cost_usd", "costUsd"),
        module_id: string_alias_field(&value, "module_id", "moduleId"),
        verb: string_field(&value, "verb"),
        parent_step: u64_alias_field(&value, "parent_step", "parentStep").map(|n| n as usize),
        severity: string_field(&value, "severity"),
        started_at_ms: u64_alias_field(&value, "started_at_ms", "startedAtMs"),
    })
}

fn malformed_trace_step(idx: usize) -> TraceStep {
    TraceStep {
        n: idx + 1,
        kind: "malformed".to_string(),
        label: "malformed trace JSONL line".to_string(),
        latency_ms: None,
        cost_usd: None,
        module_id: None,
        verb: None,
        parent_step: None,
        severity: Some("warn".to_string()),
        started_at_ms: None,
    }
}

fn malformed_trace_artifact_step() -> TraceStep {
    TraceStep {
        n: 1,
        kind: "malformed".to_string(),
        label: "malformed trace artifact".to_string(),
        latency_ms: None,
        cost_usd: None,
        module_id: None,
        verb: None,
        parent_step: None,
        severity: Some("warn".to_string()),
        started_at_ms: None,
    }
}

fn non_file_trace_artifact_step() -> TraceStep {
    TraceStep {
        n: 1,
        kind: "malformed".to_string(),
        label: "trace artifact path is not a file".to_string(),
        latency_ms: None,
        cost_usd: None,
        module_id: None,
        verb: None,
        parent_step: None,
        severity: Some("warn".to_string()),
        started_at_ms: None,
    }
}

fn step_number(value: &serde_json::Value, idx: usize) -> usize {
    u64_field(value, "n").map(|n| n as usize).unwrap_or(idx + 1)
}

fn u64_field(value: &serde_json::Value, key: &str) -> Option<u64> {
    value.get(key).and_then(serde_json::Value::as_u64)
}

fn u64_alias_field(value: &serde_json::Value, canonical: &str, alias: &str) -> Option<u64> {
    u64_field(value, canonical).or_else(|| u64_field(value, alias))
}

fn f64_alias_field(value: &serde_json::Value, canonical: &str, alias: &str) -> Option<f64> {
    value
        .get(canonical)
        .or_else(|| value.get(alias))
        .and_then(serde_json::Value::as_f64)
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn string_alias_field(value: &serde_json::Value, canonical: &str, alias: &str) -> Option<String> {
    string_field(value, canonical).or_else(|| string_field(value, alias))
}

fn short_fingerprint(value: &str) -> String {
    value.chars().take(8).collect()
}

struct RunArtifactPath {
    label: &'static str,
    path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunArtifactState {
    File,
    Invalid,
    Missing,
    NonFile,
}

impl RunArtifactPath {
    fn artifact_state(&self) -> RunArtifactState {
        artifact_state(&self.path)
    }

    fn into_display(self) -> RunArtifactDetail {
        let display = self.path.display().to_string();
        let detail = match artifact_state(&self.path) {
            RunArtifactState::File
                if self.label == "metadata" && metadata_json_malformed(&self.path) =>
            {
                format!("{display} (malformed)")
            }
            RunArtifactState::File => display,
            RunArtifactState::Invalid => format!("{display} (invalid)"),
            RunArtifactState::Missing => format!("{display} (missing)"),
            RunArtifactState::NonFile => format!("{display} (not a file)"),
        };
        RunArtifactDetail {
            label: self.label,
            detail,
        }
    }
}

fn metadata_json_malformed(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return true;
    };
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .map(|value| !value.is_object())
        .unwrap_or(true)
}

fn artifact_state(path: &Path) -> RunArtifactState {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => RunArtifactState::File,
        Ok(_) => RunArtifactState::NonFile,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => RunArtifactState::Missing,
        Err(_) => RunArtifactState::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{Finding, Severity, V2Config};

    #[test]
    fn alias_reference_model_projects_top_aliases() {
        let mut app = ShellApp::new(V2Config::default(), None);
        *app.findings_mut() = vec![
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

    #[test]
    fn trace_steps_accept_camel_case_artifact_schema_aliases() {
        let steps = trace_steps_from_text(
            r#"{"n":1,"kind":"reasoning","label":"query","latencyMs":25,"costUsd":0.02,"moduleId":"triage","verb":"run","parentStep":7,"severity":"info","startedAtMs":1700000000000}"#,
        );

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].latency_ms, Some(25));
        assert_eq!(steps[0].cost_usd, Some(0.02));
        assert_eq!(steps[0].module_id.as_deref(), Some("triage"));
        assert_eq!(steps[0].parent_step, Some(7));
        assert_eq!(steps[0].started_at_ms, Some(1_700_000_000_000));
    }

    #[test]
    fn trace_steps_surface_malformed_jsonl_rows() {
        let steps = trace_steps_from_text(
            [
                r#"{"n":1,"kind":"reasoning","label":"query"}"#,
                "{not-json",
                "",
                r#"{"n":4,"kind":"done","label":"complete"}"#,
            ]
            .join("\n")
            .as_str(),
        );

        assert_eq!(steps.len(), 3);
        assert_eq!(steps[1].n, 2);
        assert_eq!(steps[1].kind, "malformed");
        assert_eq!(steps[1].severity.as_deref(), Some("warn"));
        assert_eq!(steps[1].label, "malformed trace JSONL line");
        assert_eq!(steps[2].n, 4);
    }

    #[test]
    fn trace_steps_surface_non_object_jsonl_rows() {
        let steps = trace_steps_from_text(
            [
                r#"{"n":1,"kind":"reasoning","label":"query"}"#,
                "[]",
                r#"{"n":3,"kind":"done","label":"complete"}"#,
            ]
            .join("\n")
            .as_str(),
        );

        assert_eq!(steps.len(), 3);
        assert_eq!(steps[1].n, 2);
        assert_eq!(steps[1].kind, "malformed");
        assert_eq!(steps[1].severity.as_deref(), Some("warn"));
        assert_eq!(steps[1].label, "malformed trace JSONL line");
        assert_eq!(steps[2].n, 3);
    }

    #[test]
    fn trace_steps_surface_non_file_trace_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(run_trace_artifact_leaf());
        std::fs::create_dir(&path).unwrap();

        let steps = parse_trace_jsonl(&path);

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].kind, "malformed");
        assert_eq!(steps[0].severity.as_deref(), Some("warn"));
        assert_eq!(steps[0].label, "trace artifact path is not a file");
    }

    #[test]
    fn replay_model_surfaces_non_file_run_metadata_as_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = kuzushi_core::run_dir(temp.path(), "r-invalid");
        std::fs::create_dir_all(run_dir.join(run_metadata_artifact_leaf())).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));

        let model = replay_model(&app, "r-invalid");

        assert!(!model.metadata_missing);
        assert_eq!(model.artifacts[0].label, "metadata");
        assert!(model.artifacts[0].detail.ends_with("run.json (not a file)"));
    }

    #[test]
    fn replay_model_surfaces_malformed_run_metadata_as_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = kuzushi_core::run_dir(temp.path(), "r-malformed");
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(run_dir.join(run_metadata_artifact_leaf()), "{not-json").unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));

        let model = replay_model(&app, "r-malformed");

        assert!(!model.metadata_missing);
        assert_eq!(model.artifacts[0].label, "metadata");
        assert!(model.artifacts[0].detail.ends_with("run.json (malformed)"));
    }

    #[test]
    fn replay_model_surfaces_non_object_run_metadata_as_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = kuzushi_core::run_dir(temp.path(), "r-non-object");
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(run_dir.join(run_metadata_artifact_leaf()), "[]").unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));

        let model = replay_model(&app, "r-non-object");

        assert!(!model.metadata_missing);
        assert_eq!(model.artifacts[0].label, "metadata");
        assert!(model.artifacts[0].detail.ends_with("run.json (malformed)"));
    }

    #[test]
    fn trace_model_surfaces_non_file_trace_artifact_as_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = kuzushi_core::run_dir(temp.path(), "r-invalid-trace");
        std::fs::create_dir_all(run_dir.join(run_trace_artifact_leaf())).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));

        let model = trace_model(&app, "r-invalid-trace");

        assert!(!model.trace_exists);
        assert_eq!(model.artifacts[0].label, "trace");
        assert!(model.artifacts[0]
            .detail
            .ends_with("trace.jsonl (not a file)"));
        assert_eq!(model.steps.len(), 1);
        assert_eq!(model.steps[0].label, "trace artifact path is not a file");
    }

    #[test]
    fn trace_steps_surface_non_utf8_trace_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(run_trace_artifact_leaf());
        std::fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();

        let steps = parse_trace_jsonl(&path);

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].kind, "malformed");
        assert_eq!(steps[0].label, "malformed trace artifact");
    }

    fn named_finding(fingerprint: &str, title: &str) -> Finding {
        let mut finding =
            Finding::new_semgrep("demo.rule", "src/app.rs", 1, None, Severity::High, title);
        finding.fingerprint = fingerprint.to_string();
        finding.title = title.to_string();
        finding
    }
}
