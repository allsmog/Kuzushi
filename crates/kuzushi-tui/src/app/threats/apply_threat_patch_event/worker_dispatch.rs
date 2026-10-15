use super::*;
use kuzushi_core::try_load_persistent_threat_model;

impl ShellApp {
    pub(crate) fn reduce_threat_regen(&mut self) -> Vec<ShellEffect> {
        if let Err(error) = self.open_context_regeneration_entry() {
            self.set_warn_notice("context", error.to_string());
            self.log("context", error.to_string());
        }
        Vec::new()
    }

    pub(crate) fn dispatch_threat_worker(&mut self, start: ThreatWorkerStart) {
        if self.reject_runtime_launch_while_budget_halted(true, "threat model") {
            return;
        }
        let Some(existing) = self.active_threat_model_for_worker(&start.cwd) else {
            return;
        };
        let Some(ticket) = self.try_start_exclusive_job(JobKind::Threat, "threat model") else {
            return;
        };
        let generation = ticket.generation();
        let watchdog_cancel = ticket.cancel.clone();
        let run_id = kuzushi_core::new_run_id("threat");
        self.begin_run_cost_tracking(&run_id, true);
        let session = ActivitySession::for_optional_phase(run_id.clone(), start.origin_phase);
        self.set_activity(Some(self.capture_run_focus_origin(session)));
        self.record_session_event(kuzushi_core::session_transcript::SessionEvent::RunStarted {
            run_id: run_id.clone(),
            tool_name: "threat-model:proposal".to_string(),
        });
        let runtime = self.start_threat_worker_runtime(&start, watchdog_cancel.clone(), existing);
        let loaded_modules = self.registry().loaded_module_specifiers();
        let metadata = ProposalRunMetadata {
            run_id,
            loaded_modules,
        };
        let handle = spawn_threat_worker(start, runtime, ticket, metadata);
        self.register_worker_handle_with_watchdog(
            "threat model",
            generation,
            handle,
            watchdog_cancel,
        );
    }

    fn active_threat_model_for_worker(&mut self, cwd: &PathBuf) -> Option<serde_json::Value> {
        match persistent_threat_model_or_null(cwd) {
            Ok(existing) => Some(existing),
            Err(error) => {
                self.log(
                    "error",
                    format!("cannot read the active threat model: {error:#}"),
                );
                None
            }
        }
    }

    #[cfg(test)]
    fn threat_worker_start(
        &self,
        model: String,
        message: impl Into<String>,
        cwd: PathBuf,
    ) -> ThreatWorkerStart {
        ThreatWorkerStart {
            config: self.config().clone(),
            model,
            thinking_level: self.session_thinking_level_owned(),
            cwd,
            message: message.into(),
            origin_phase: self.engagement.current_phase(),
        }
    }

    fn begin_threat_worker_state(&mut self, message: impl Into<String>, cancel: ScanCancellation) {
        self.set_threat_cancel(Some(cancel.clone()));
        self.set_threat_worker_running(true);
        self.set_threat_abort_requested(false);
        let message = message.into();
        self.log("threats", message.clone());
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::CallingModel,
            "threat model",
            message,
        ));
    }

    fn start_threat_worker_runtime(
        &mut self,
        start: &ThreatWorkerStart,
        cancel: ScanCancellation,
        existing: serde_json::Value,
    ) -> ThreatWorkerRuntime {
        self.begin_threat_worker_state(start.message.clone(), cancel);
        ThreatWorkerRuntime { existing }
    }
}

fn persistent_threat_model_or_null(cwd: &PathBuf) -> anyhow::Result<serde_json::Value> {
    Ok(try_load_persistent_threat_model(cwd)?.unwrap_or(serde_json::Value::Null))
}

pub(crate) struct ThreatWorkerStart {
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    message: String,
    origin_phase: Option<WorkflowPhase>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_start_captures_only_an_explicit_guided_phase() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let target = PathBuf::from("/explicit-threat-target");
        app.set_target(Some(target.clone()));
        let manual = app.threat_worker_start(
            "openai:gpt-test".to_string(),
            "inspect threats",
            target.clone(),
        );
        assert_eq!(manual.origin_phase, None);

        app.engagement.set_phase(WorkflowPhase::Map);
        let guided = app.threat_worker_start(
            "openai:gpt-test".to_string(),
            "build the threat model",
            target,
        );
        assert_eq!(guided.origin_phase, Some(WorkflowPhase::Map));
    }

    #[test]
    fn targetless_threat_worker_is_refused() {
        let mut app = ShellApp::new(
            V2Config {
                model: Some("openai:gpt-test".to_string()),
                ..V2Config::default()
            },
            None,
        );

        assert!(app.reduce_threat_regen().is_empty());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("requires an explicit target")));
    }
}

struct ThreatWorkerRuntime {
    existing: serde_json::Value,
}

fn spawn_threat_worker(
    start: ThreatWorkerStart,
    runtime: ThreatWorkerRuntime,
    ticket: JobTicket,
    metadata: ProposalRunMetadata,
) -> std::thread::JoinHandle<()> {
    let invocation = ThreatWorkerInvocation {
        start,
        existing: runtime.existing,
        metadata,
    };
    spawn_job_worker("threat model", ticket, move |sink, cancel| {
        invocation.run(sink, cancel)
    })
}

struct ThreatWorkerInvocation {
    start: ThreatWorkerStart,
    existing: serde_json::Value,
    metadata: ProposalRunMetadata,
}

impl ThreatWorkerInvocation {
    fn run(self, sink: JobEventSink, cancel: ScanCancellation) {
        let start = self.start;
        threat_regen_worker(
            start.config,
            start.model,
            start.thinking_level,
            start.cwd,
            self.existing,
            self.metadata,
            sink,
            cancel,
        )
    }
}
