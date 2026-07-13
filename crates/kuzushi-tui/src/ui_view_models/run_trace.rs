use crate::{
    app::{RunTraceCacheState, ViewDataState},
    ReconSnapshot, ShellApp,
};
use kuzushi_core::run_artifacts::canonical_run_artifact_spec;
use kuzushi_core::{RunArtifactRead, RunArtifactTextRead, RunTraceStep};

const RUN_TRIAGE_FILE: &str = "triage.jsonl";
const RUN_VERIFY_FILE: &str = "verify.jsonl";
const RUN_PATCH_FILE: &str = "patch.jsonl";
const RUN_RESULT_FILE: &str = "result.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AliasReferenceModel {
    pub(crate) rows: Vec<AliasReferenceRow>,
    pub(crate) overflow_count: usize,
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
    pub(crate) recon: Option<ReconSnapshot>,
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
    display_state: RunArtifactDisplayState,
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
    let result = run_artifact_detail(app, run_id, "result", RUN_RESULT_FILE);
    let triage = run_artifact_detail(app, run_id, "triage", RUN_TRIAGE_FILE);
    let metadata_missing = metadata.artifact_state() == RunArtifactState::Missing;
    ReplayModel {
        run_id: run_id.to_string(),
        metadata_missing,
        artifacts: vec![
            metadata.into_display(),
            result.into_display(),
            triage.into_display(),
        ],
        recon: replay_recon_snapshot(app, run_id),
    }
}

fn replay_recon_snapshot(app: &ShellApp, run_id: &str) -> Option<ReconSnapshot> {
    let ViewDataState::Ready(RunArtifactRead::Ready { value, .. }) =
        cached_artifact_text(app, run_id, RUN_RESULT_FILE)
    else {
        return None;
    };
    serde_json::from_str(&value)
        .ok()
        .and_then(|result| crate::app::recon_snapshot_from_result(&result))
        .filter(ReconSnapshot::has_evidence)
}

pub(crate) fn trace_model(app: &ShellApp, run_id: &str) -> TraceModel {
    let trace = run_artifact_detail(app, run_id, "trace", run_trace_artifact_leaf());
    let triage = run_artifact_detail(app, run_id, "triage", RUN_TRIAGE_FILE);
    let verify = run_artifact_detail(app, run_id, "verify", RUN_VERIFY_FILE);
    let patch = run_artifact_detail(app, run_id, "patch", RUN_PATCH_FILE);
    let trace_exists = trace.artifact_state() == RunArtifactState::File;
    TraceModel {
        run_id: run_id.to_string(),
        trace_exists,
        steps: trace_steps(app, run_id, trace.artifact_state()),
        artifacts: vec![
            trace.into_display(),
            triage.into_display(),
            verify.into_display(),
            patch.into_display(),
        ],
    }
}

pub(crate) fn alias_reference_model(app: &ShellApp) -> AliasReferenceModel {
    let aliases = super::findings::cached_sorted_finding_alias_indices(app);
    let overflow_count = aliases.len().saturating_sub(3);
    AliasReferenceModel {
        rows: aliases
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
        overflow_count,
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
        state: cached_artifact_text(app, run_id, leaf),
    }
}

fn run_metadata_artifact_detail(app: &ShellApp, run_id: &str) -> RunArtifactPath {
    RunArtifactPath {
        label: "metadata",
        state: cached_artifact_text(app, run_id, run_metadata_artifact_leaf()),
    }
}

fn cached_artifact_text(
    app: &ShellApp,
    run_id: &str,
    leaf: &str,
) -> ViewDataState<RunArtifactTextRead> {
    let Some(target) = app.target() else {
        return ViewDataState::Ready(RunArtifactRead::Unsafe {
            error: "no active target".to_string(),
        });
    };
    app.workbench_cache()
        .borrow()
        .cached_run_artifact_text(target, run_id, leaf)
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

fn trace_steps(app: &ShellApp, run_id: &str, state: RunArtifactState) -> Vec<TraceStep> {
    match state {
        RunArtifactState::Missing => return Vec::new(),
        RunArtifactState::NonFile => return vec![non_file_trace_artifact_step()],
        RunArtifactState::Invalid => return vec![malformed_trace_artifact_step()],
        RunArtifactState::Loading => return Vec::new(),
        RunArtifactState::File => {}
    }
    let Some(target) = app.target() else {
        return Vec::new();
    };
    match app
        .workbench_cache()
        .borrow()
        .cached_run_trace(target, run_id)
    {
        ViewDataState::Ready(RunTraceCacheState::Ready(read)) => {
            trace_steps_from_core_read(read.steps, read.malformed_lines)
        }
        ViewDataState::Ready(RunTraceCacheState::Invalid) => vec![malformed_trace_artifact_step()],
        ViewDataState::NotRequested | ViewDataState::Loading => Vec::new(),
    }
}

fn trace_steps_from_core_read(steps: Vec<RunTraceStep>, malformed_lines: usize) -> Vec<TraceStep> {
    let next_number = steps.iter().map(|step| step.n).max().unwrap_or(0) + 1;
    let mut projected = steps.into_iter().map(TraceStep::from).collect::<Vec<_>>();
    if malformed_lines > 0 {
        projected.push(TraceStep {
            n: next_number,
            kind: "malformed".to_string(),
            label: format!("{malformed_lines} malformed trace JSONL line(s) ignored"),
            latency_ms: None,
            cost_usd: None,
            module_id: None,
            verb: None,
            parent_step: None,
            severity: Some("warn".to_string()),
            started_at_ms: None,
        });
    }
    projected
}

impl From<RunTraceStep> for TraceStep {
    fn from(step: RunTraceStep) -> Self {
        Self {
            n: step.n,
            kind: step.kind,
            label: step.label,
            latency_ms: step.latency_ms,
            cost_usd: step.cost_usd,
            module_id: step.module_id,
            verb: step.verb,
            parent_step: step.parent_step,
            severity: step.severity,
            started_at_ms: step.started_at_ms,
        }
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

fn short_fingerprint(value: &str) -> String {
    value.chars().take(8).collect()
}

struct RunArtifactPath {
    label: &'static str,
    state: ViewDataState<RunArtifactTextRead>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunArtifactState {
    File,
    Invalid,
    Missing,
    NonFile,
    Loading,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunArtifactDisplayState {
    Ready,
    Malformed,
    Invalid,
    Missing,
    NonFile,
    Loading,
}

impl RunArtifactDetail {
    pub(crate) fn state_label(&self) -> Option<&'static str> {
        match self.display_state {
            RunArtifactDisplayState::Ready => None,
            RunArtifactDisplayState::Malformed => Some("MALFORMED"),
            RunArtifactDisplayState::Invalid => Some("INVALID"),
            RunArtifactDisplayState::Missing => Some("MISSING"),
            RunArtifactDisplayState::NonFile => Some("NOT A FILE"),
            RunArtifactDisplayState::Loading => Some("LOADING"),
        }
    }
}

impl RunArtifactPath {
    fn artifact_state(&self) -> RunArtifactState {
        artifact_state(&self.state)
    }

    fn into_display(self) -> RunArtifactDetail {
        let display = match &self.state {
            ViewDataState::Ready(state) => state.display_path(),
            ViewDataState::NotRequested | ViewDataState::Loading => "artifact metadata".to_string(),
        };
        let display_state = match artifact_state(&self.state) {
            RunArtifactState::File
                if self.label == "metadata" && metadata_json_malformed(&self.state) =>
            {
                RunArtifactDisplayState::Malformed
            }
            RunArtifactState::File => RunArtifactDisplayState::Ready,
            RunArtifactState::Invalid => RunArtifactDisplayState::Invalid,
            RunArtifactState::Missing => RunArtifactDisplayState::Missing,
            RunArtifactState::NonFile => RunArtifactDisplayState::NonFile,
            RunArtifactState::Loading => RunArtifactDisplayState::Loading,
        };
        RunArtifactDetail {
            label: self.label,
            detail: display,
            display_state,
        }
    }
}

fn metadata_json_malformed(state: &ViewDataState<RunArtifactTextRead>) -> bool {
    let ViewDataState::Ready(RunArtifactRead::Ready { value: text, .. }) = state else {
        return true;
    };
    serde_json::from_str::<serde_json::Value>(text)
        .map(|value| !value.is_object())
        .unwrap_or(true)
}

fn artifact_state(state: &ViewDataState<RunArtifactTextRead>) -> RunArtifactState {
    match state {
        ViewDataState::NotRequested | ViewDataState::Loading => RunArtifactState::Loading,
        ViewDataState::Ready(RunArtifactRead::Ready { .. }) => RunArtifactState::File,
        ViewDataState::Ready(RunArtifactRead::Missing { .. }) => RunArtifactState::Missing,
        ViewDataState::Ready(RunArtifactRead::NonFile { .. }) => RunArtifactState::NonFile,
        ViewDataState::Ready(
            RunArtifactRead::Unsafe { .. } | RunArtifactRead::Unreadable { .. },
        ) => RunArtifactState::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{Finding, Severity, V2Config};

    fn hydrate_replay(app: &mut ShellApp, run_id: &str) {
        app.open_replay_for_test(run_id);
        app.hydrate_active_view_blocking();
    }

    fn hydrate_trace(app: &mut ShellApp, run_id: &str) {
        app.open_trace_for_test(run_id);
        app.hydrate_active_view_blocking();
    }

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
        assert_eq!(model.overflow_count, 1);
        assert_eq!(model.rows[0].alias, "F-0001");
        assert_eq!(model.rows[0].detail, "aaaa1111 first");
    }

    #[test]
    fn alias_reference_model_explains_empty_findings() {
        let app = ShellApp::new(V2Config::default(), None);

        let model = alias_reference_model(&app);

        assert!(model.rows.is_empty());
        assert_eq!(model.overflow_count, 0);
        assert_eq!(
            model.empty_message,
            "aliases: load findings first with findings"
        );
    }

    #[test]
    fn trace_model_rejects_traversal_run_id_without_displaying_it() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        hydrate_trace(&mut app, "../../outside\nrun");

        let model = trace_model(&app, "../../outside\nrun");

        assert!(!model.trace_exists);
        assert_eq!(model.steps[0].label, "malformed trace artifact");
        assert!(model
            .artifacts
            .iter()
            .all(|artifact| artifact.detail == "<unsafe run artifact path>"));
        assert!(model
            .artifacts
            .iter()
            .all(|artifact| artifact.state_label() == Some("INVALID")));
    }

    #[test]
    fn trace_steps_project_the_canonical_core_schema() {
        let steps = trace_steps_from_core_read(
            vec![RunTraceStep {
                n: 1,
                kind: "reasoning".to_string(),
                label: "query".to_string(),
                latency_ms: Some(25),
                cost_usd: Some(0.02),
                observed_cost_usd: None,
                provider_spend_unresolved: false,
                call_attempted: None,
                module_id: Some("triage".to_string()),
                verb: Some("run".to_string()),
                parent_step: Some(7),
                severity: Some("info".to_string()),
                started_at_ms: Some(1_700_000_000_000),
                model: None,
                provider: None,
                prompt_hash: None,
            }],
            0,
        );

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].latency_ms, Some(25));
        assert_eq!(steps[0].cost_usd, Some(0.02));
        assert_eq!(steps[0].module_id.as_deref(), Some("triage"));
        assert_eq!(steps[0].parent_step, Some(7));
        assert_eq!(steps[0].started_at_ms, Some(1_700_000_000_000));
    }

    #[test]
    fn trace_steps_summarize_malformed_canonical_rows() {
        let steps = trace_steps_from_core_read(Vec::new(), 2);

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].n, 1);
        assert_eq!(steps[0].kind, "malformed");
        assert_eq!(steps[0].severity.as_deref(), Some("warn"));
        assert_eq!(steps[0].label, "2 malformed trace JSONL line(s) ignored");
    }

    #[test]
    fn replay_model_surfaces_non_file_run_metadata_as_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = kuzushi_core::run_dir(temp.path(), "r-invalid");
        std::fs::create_dir_all(run_dir.join(run_metadata_artifact_leaf())).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        hydrate_replay(&mut app, "r-invalid");

        let model = replay_model(&app, "r-invalid");

        assert!(!model.metadata_missing);
        assert_eq!(model.artifacts[0].label, "metadata");
        assert!(model.artifacts[0].detail.ends_with("run.json"));
        assert_eq!(model.artifacts[0].state_label(), Some("NOT A FILE"));
    }

    #[test]
    fn replay_model_surfaces_malformed_run_metadata_as_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = kuzushi_core::run_dir(temp.path(), "r-malformed");
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(run_dir.join(run_metadata_artifact_leaf()), "{not-json").unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        hydrate_replay(&mut app, "r-malformed");

        let model = replay_model(&app, "r-malformed");

        assert!(!model.metadata_missing);
        assert_eq!(model.artifacts[0].label, "metadata");
        assert!(model.artifacts[0].detail.ends_with("run.json"));
        assert_eq!(model.artifacts[0].state_label(), Some("MALFORMED"));
    }

    #[test]
    fn replay_model_surfaces_non_object_run_metadata_as_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = kuzushi_core::run_dir(temp.path(), "r-non-object");
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(run_dir.join(run_metadata_artifact_leaf()), "[]").unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        hydrate_replay(&mut app, "r-non-object");

        let model = replay_model(&app, "r-non-object");

        assert!(!model.metadata_missing);
        assert_eq!(model.artifacts[0].label, "metadata");
        assert!(model.artifacts[0].detail.ends_with("run.json"));
        assert_eq!(model.artifacts[0].state_label(), Some("MALFORMED"));
    }

    #[test]
    fn trace_model_surfaces_non_file_trace_artifact_as_invalid() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = kuzushi_core::run_dir(temp.path(), "r-invalid-trace");
        std::fs::create_dir_all(run_dir.join(run_trace_artifact_leaf())).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        hydrate_trace(&mut app, "r-invalid-trace");

        let model = trace_model(&app, "r-invalid-trace");

        assert!(!model.trace_exists);
        assert_eq!(model.artifacts[0].label, "trace");
        assert!(model.artifacts[0].detail.ends_with("trace.jsonl"));
        assert_eq!(model.artifacts[0].state_label(), Some("NOT A FILE"));
        assert_eq!(model.steps.len(), 1);
        assert_eq!(model.steps[0].label, "trace artifact path is not a file");
    }

    #[test]
    fn trace_steps_surface_non_utf8_trace_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let run_id = "r-non-utf8";
        let path = kuzushi_core::run_dir(temp.path(), run_id).join(run_trace_artifact_leaf());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        hydrate_trace(&mut app, run_id);

        let steps = trace_model(&app, run_id).steps;

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
