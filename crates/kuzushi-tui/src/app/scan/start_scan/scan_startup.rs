use super::*;
use kuzushi_core::{OptionScope, OptionTarget, ToolOptionStore};
use serde_json::Value;
use std::collections::BTreeMap;

const SCAN_TOOL_NAME: &str = "sast:scan";

impl ShellApp {
    pub(crate) fn open_guided_scan(&mut self, target: Option<PathBuf>) {
        if self.scan.as_ref().is_some_and(|scan| scan.running) {
            self.log("scan", "scan already running");
            return;
        }
        if !self.activate_guided_scan_target(target) {
            return;
        }
        self.workbench_cache.borrow_mut().invalidate_map_artifacts();
        let Some(journey) = crate::ui_view_models::journey_model(self) else {
            self.log(
                "journey",
                "no active workspace target; set one with `target <path>` first",
            );
            return;
        };
        self.log(
            "scan",
            "opening guided workflow — review checked tasks, then press Enter to run",
        );
        self.open_phase_picker(journey.current);
    }

    fn activate_guided_scan_target(&mut self, target: Option<PathBuf>) -> bool {
        let Some(target) = target else {
            if self.current_workspace().is_ok() {
                return true;
            }
            self.log(
                "scan",
                "no active workspace target; run `target <path>` first, or `scan .` to use cwd",
            );
            return false;
        };
        match WorkspaceTarget::new(&target) {
            Ok(workspace) => {
                self.activate_target(workspace);
                true
            }
            Err(error) => {
                self.log(
                    "error",
                    format!("invalid target {}: {error}", target.display()),
                );
                false
            }
        }
    }

    pub(crate) fn start_umbrella_sast_scan(&mut self, target: Option<PathBuf>) {
        let Some(request) = self.prepare_scan_start(target) else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        let (trace_tx, trace_rx) = mpsc::channel::<RunTraceStep>();
        let trace_handle = scan_trace_handle(&request.target_root, &request.run_id, trace_tx);
        let cancel = ScanCancellation::default();

        self.begin_scan_state(&request, rx, trace_rx, cancel.clone());
        self.spawn_scan_worker(request, tx, trace_handle, cancel);
    }

    fn spawn_scan_worker(
        &self,
        request: ScanStartRequest,
        tx: mpsc::Sender<ScanEvent>,
        trace_handle: TraceHandle,
        cancel: ScanCancellation,
    ) {
        thread::spawn(move || {
            scan_worker(
                request.target_root,
                request.db_path,
                tx,
                cancel,
                request.input,
                request.registry,
                request.config,
                request.thinking_level,
                trace_handle,
            )
        });
    }

    fn begin_scan_state(
        &mut self,
        request: &ScanStartRequest,
        rx: mpsc::Receiver<ScanEvent>,
        trace_rx: mpsc::Receiver<RunTraceStep>,
        cancel: ScanCancellation,
    ) {
        self.target = Some(request.target_root.clone());
        self.scan = Some(queued_scan_panel(&request.target_root, &request.run_id));
        self.scan_rx = Some(rx);
        self.trace_rx = Some(trace_rx);
        self.scan_cancel = Some(cancel);
        self.findings.clear();
        self.selected_finding = None;
        self.workflow_phase = Some(crate::app::WorkflowPhase::Hunt);
        self.active_model_override = active_model_override_from_input(&request.input, &self.config);
        self.activity = Some(self.pending_scan_activity(&request.run_id));
        self.shell_view = self.scan_shell_view();
        self.log_scan_start(&request.target_root, &request.effective_options);
    }

    fn pending_scan_activity(&self, run_id: &str) -> ActivitySession {
        let mut session = ActivitySession::new(run_id);
        session.seed_from_registry(&self.registry);
        session
    }

    fn scan_shell_view(&self) -> ShellView {
        if self.auto_open_activity {
            ShellView::Activity
        } else {
            ShellView::ModuleRun
        }
    }

    fn log_scan_start(&mut self, target_root: &PathBuf, effective_options: &[EffectiveScanOption]) {
        self.log(
            "phase",
            "崩 hunt (2/4): `scan` is the full-scan action for this phase",
        );
        self.log("scan", format!("starting {}", target_root.display()));
        self.log(
            "scan",
            "setup: `tasks` chooses scanners · `options sast:scan` tunes inputs · Ctrl+G opens commands",
        );
        self.log("scan", scan_options_log_message(effective_options));
        if self.auto_open_activity {
            self.log(
                "view",
                "opened activity — Ctrl+C requests abort; type `back` to leave (disable: setg ui.auto_open_activity false)",
            );
        }
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Searching,
            "sast:scan",
            format!("scanning {}", target_root.display()),
        ));
    }

    fn prepare_scan_start(&mut self, target: Option<PathBuf>) -> Option<ScanStartRequest> {
        if self.scan.as_ref().is_some_and(|scan| scan.running) {
            self.log("scan", "scan already running");
            return None;
        }
        self.resolve_scan_start_request(target)
    }

    fn resolve_scan_start_request(&mut self, target: Option<PathBuf>) -> Option<ScanStartRequest> {
        let target_path = self.scan_target_path(target);
        let workspace = self.scan_workspace(&target_path)?;
        let run_id = new_run_id("scan");
        let effective_options = effective_scan_options(&self.registry, &self.option_store);
        let input = scan_input_with_run_id(self.scan_input_or_log()?, &run_id);
        Some(ScanStartRequest {
            run_id,
            target_root: workspace.root().to_path_buf(),
            db_path: workspace.findings_db_path(),
            input,
            effective_options,
            registry: self.registry.clone(),
            config: self.config.clone(),
            thinking_level: self.session_thinking_level.clone(),
        })
    }

    fn scan_target_path(&self, target: Option<PathBuf>) -> PathBuf {
        target
            .or_else(|| self.target.clone())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    fn scan_workspace(&mut self, target_path: &PathBuf) -> Option<WorkspaceTarget> {
        match WorkspaceTarget::new(target_path) {
            Ok(workspace) => Some(workspace),
            Err(error) => {
                self.log("error", error.to_string());
                None
            }
        }
    }

    fn scan_input_or_log(&mut self) -> Option<serde_json::Value> {
        match self.scan_input_from_store() {
            Ok(input) => Some(input),
            Err(error) => {
                self.log("error", error.to_string());
                None
            }
        }
    }

    pub(crate) fn scan_input_from_store(&self) -> Result<serde_json::Value> {
        self.registry.prepare_tool_input(
            "sast:scan",
            serde_json::json!({}),
            Some(&self.option_store),
        )
    }
}

fn scan_trace_handle(
    target: &std::path::Path,
    run_id: &str,
    trace_tx: std::sync::mpsc::Sender<RunTraceStep>,
) -> TraceHandle {
    let inner_sink: Arc<dyn TraceSink> = Arc::new(JsonlSink::new(target.to_path_buf(), run_id));
    let broadcast_sink: Arc<dyn TraceSink> = Arc::new(BroadcastSink::new(inner_sink, trace_tx));
    let initial_step_number = next_run_trace_step_number(target, run_id).saturating_sub(1);
    TraceHandle::with_initial_step_number(broadcast_sink, initial_step_number)
}

fn scan_input_with_run_id(mut input: serde_json::Value, run_id: &str) -> serde_json::Value {
    if let serde_json::Value::Object(object) = &mut input {
        object.insert("runId".to_string(), serde_json::json!(run_id));
    }
    input
}

fn effective_scan_options(
    registry: &ModuleRegistry,
    store: &ToolOptionStore,
) -> Vec<EffectiveScanOption> {
    let mut options = BTreeMap::new();
    for scope in [
        OptionScope::Global,
        OptionScope::Workspace,
        OptionScope::Session,
    ] {
        merge_scan_options(registry, store, scope, &OptionTarget::All, &mut options);
        merge_scan_options(
            registry,
            store,
            scope,
            &OptionTarget::Module("sast".to_string()),
            &mut options,
        );
        merge_scan_options(
            registry,
            store,
            scope,
            &OptionTarget::Tool(SCAN_TOOL_NAME.to_string()),
            &mut options,
        );
    }
    options.into_values().collect()
}

fn merge_scan_options(
    registry: &ModuleRegistry,
    store: &ToolOptionStore,
    scope: OptionScope,
    target: &OptionTarget,
    options: &mut BTreeMap<String, EffectiveScanOption>,
) {
    let Some(values) = store.values_for(scope, target) else {
        return;
    };
    for (name, value) in values {
        if scan_descriptor_accepts_option(registry, name) {
            options.insert(name.clone(), EffectiveScanOption::new(name, value, scope));
        }
    }
}

fn scan_descriptor_accepts_option(registry: &ModuleRegistry, name: &str) -> bool {
    registry.resolve_tool(SCAN_TOOL_NAME).is_some_and(|tool| {
        tool.options
            .iter()
            .any(|spec| spec.matches_name_or_alias(name))
    })
}

fn scan_options_log_message(options: &[EffectiveScanOption]) -> String {
    if options.is_empty() {
        return "0 stored options in effect — type `options sast:scan` or `tasks` before scanning"
            .to_string();
    }
    format!(
        "{} stored {} in effect — {}",
        options.len(),
        option_count_label(options.len()),
        scan_option_preview(options)
    )
}

fn option_count_label(count: usize) -> &'static str {
    if count == 1 {
        "option"
    } else {
        "options"
    }
}

fn scan_option_preview(options: &[EffectiveScanOption]) -> String {
    let mut parts = options
        .iter()
        .take(4)
        .map(format_effective_scan_option)
        .collect::<Vec<_>>();
    if options.len() > parts.len() {
        parts.push(format!("+{} more", options.len() - parts.len()));
    }
    parts.join(", ")
}

fn format_effective_scan_option(option: &EffectiveScanOption) -> String {
    format!(
        "{}={} ({})",
        option.name,
        option_value_label(&option.value),
        scope_label(option.scope)
    )
}

fn option_value_label(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn scope_label(scope: OptionScope) -> &'static str {
    match scope {
        OptionScope::Global => "global",
        OptionScope::Workspace => "workspace",
        OptionScope::Session => "session",
    }
}

fn queued_scan_panel(target_root: &PathBuf, run_id: &str) -> ScanPanelState {
    ScanPanelState {
        run_id: Some(run_id.to_string()),
        target: target_root.clone(),
        stage: "queued".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_scan_panel_seeds_failure_handoff_run_id() {
        let temp = tempfile::tempdir().unwrap();
        let panel = queued_scan_panel(&temp.path().to_path_buf(), "scan-seeded");

        assert_eq!(panel.run_id.as_deref(), Some("scan-seeded"));
        assert!(panel.running);
    }

    #[test]
    fn scan_input_with_run_id_adds_internal_artifact_identity() {
        let input = scan_input_with_run_id(serde_json::json!({"triage": false}), "scan-tui");

        assert_eq!(input["runId"], serde_json::json!("scan-tui"));
        assert_eq!(input["triage"], serde_json::json!(false));
    }

    #[test]
    fn effective_scan_options_log_uses_descriptor_filter_and_precedence() {
        let registry = ModuleRegistry::with_v2_builtins();
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::All,
            "ui.auto_open_activity",
            serde_json::json!(false),
        );
        store.set_value(
            OptionScope::Global,
            OptionTarget::All,
            "triage",
            serde_json::json!(true),
        );
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool(SCAN_TOOL_NAME.to_string()),
            "maxFindings",
            serde_json::json!(12),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool(SCAN_TOOL_NAME.to_string()),
            "triage",
            serde_json::json!(false),
        );

        let options = effective_scan_options(&registry, &store);
        let message = scan_options_log_message(&options);

        assert_eq!(options.len(), 2);
        assert!(message.contains("2 stored options in effect"), "{message}");
        assert!(message.contains("maxFindings=12 (workspace)"), "{message}");
        assert!(message.contains("triage=false (session)"), "{message}");
        assert!(!message.contains("ui.auto_open_activity"), "{message}");
    }

    #[test]
    fn empty_scan_options_log_points_to_sast_options() {
        let message = scan_options_log_message(&[]);

        assert!(message.contains("0 stored options in effect"), "{message}");
        assert!(message.contains("options sast:scan"), "{message}");
        assert!(message.contains("before scanning"), "{message}");
    }

    #[test]
    fn scan_trace_handle_broadcasts_and_writes_trace_jsonl() {
        let temp = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel::<RunTraceStep>();
        let trace = scan_trace_handle(temp.path(), "scan-trace", tx);

        trace.step("tool", "scan", "started").emit();

        let broadcast = rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("trace step should broadcast to activity");
        let trace_path = kuzushi_core::run_artifacts::run_artifact_path(
            temp.path(),
            "scan-trace",
            "trace.jsonl",
        );
        let persisted = std::fs::read_to_string(trace_path).unwrap();

        assert_eq!(broadcast.label, "started");
        assert!(persisted.contains("\"label\":\"started\""), "{persisted}");
    }
}

#[derive(Debug, Clone, PartialEq)]
struct EffectiveScanOption {
    name: String,
    value: Value,
    scope: OptionScope,
}

impl EffectiveScanOption {
    fn new(name: &str, value: &Value, scope: OptionScope) -> Self {
        Self {
            name: name.to_string(),
            value: value.clone(),
            scope,
        }
    }
}

struct ScanStartRequest {
    run_id: String,
    target_root: PathBuf,
    db_path: PathBuf,
    input: serde_json::Value,
    effective_options: Vec<EffectiveScanOption>,
    registry: ModuleRegistry,
    config: V2Config,
    thinking_level: Option<String>,
}
