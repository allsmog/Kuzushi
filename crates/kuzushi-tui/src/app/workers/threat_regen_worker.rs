use super::*;

#[path = "threat_regen_worker/job.rs"]
mod job;
use job::ThreatWorkerJob;

pub(crate) fn threat_regen_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    metadata: ProposalRunMetadata,
    sink: JobEventSink,
    cancel: ScanCancellation,
) {
    ThreatWorkerJob {
        config,
        model,
        thinking_level,
        cwd,
        existing,
        metadata,
        cancel,
    }
    .run_regen(sink);
}

fn settle_threat_regen_result(
    run: &ProposalRun<'_>,
    lifecycle: ProposalRunLifecycle,
    result: CostedWorkerResult<ThreatPatch>,
    audit: AgentCallAudit,
    cancellation: Option<kuzushi_core::scan::CancellationDisposition>,
) -> ThreatPatchEvent {
    match result {
        Ok((patch, cost)) => persisted_threat_patch_event(run, lifecycle, patch, cost, audit),
        Err(error) => failed_threat_event(run, lifecycle, error, audit, cancellation),
    }
}

fn persisted_threat_patch_event(
    run: &ProposalRun<'_>,
    lifecycle: ProposalRunLifecycle,
    patch: ThreatPatch,
    cost: kuzushi_core::runtime::RuntimeCostReport,
    audit: AgentCallAudit,
) -> ThreatPatchEvent {
    match run.complete_observed(
        "threat-model proposal ready",
        threat_patch_value(&patch),
        cost,
        lifecycle,
    ) {
        Ok(()) => ThreatPatchEvent::Proposed {
            patch,
            audit: audit.with_cost(cost),
        },
        Err(error) => ThreatPatchEvent::Failed {
            error: threat_terminal_persistence_error(run, error),
            audit: audit.with_cost(cost),
        },
    }
}

pub(crate) fn run_threat_regen_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    observation: kuzushi_core::run_lifecycle::RunObservationHandle,
    cancel: ScanCancellation,
) -> CostedWorkerResult<ThreatPatch> {
    let runtime = worker_runtime(&config, &cwd, thinking_level, cancel)
        .map_err(CostedWorkerError::before_call)?;
    let prompt = threat_regen_prompt(&existing);
    let (body, cost) = worker_response_text(
        runtime,
        model,
        cwd,
        THREAT_PATCH_SYSTEM_PROMPT.to_string(),
        prompt,
        "threat regen returned no content",
        &observation,
    )?;
    let patch = parse_threat_patch_json(THREAT_REGEN_PROMPT, &body)
        .map_err(|error| CostedWorkerError::observed(error, cost))?;
    Ok((patch, cost))
}

fn threat_regen_prompt(existing: &serde_json::Value) -> String {
    format!(
        "OPERATOR INTENT:\n{}\n\nCURRENT THREAT MODEL JSON:\n{}",
        THREAT_REGEN_PROMPT,
        pretty_threat_json(existing)
    )
}

fn send_threat_start_failure(sink: &JobEventSink, error: anyhow::Error, audit: AgentCallAudit) {
    sink.send(ShellEvent::Threat(ThreatPatchEvent::Failed {
        error: error.to_string(),
        audit,
    }));
}

fn failed_threat_event(
    run: &ProposalRun<'_>,
    lifecycle: ProposalRunLifecycle,
    error: CostedWorkerError,
    audit: AgentCallAudit,
    cancellation: Option<kuzushi_core::scan::CancellationDisposition>,
) -> ThreatPatchEvent {
    let message = error.error.to_string();
    let safe_message = kuzushi_core::runtime::safe_model_failure_message(&message);
    let persisted = run.fail_observed(&safe_message, cancellation, error.cost, lifecycle);
    ThreatPatchEvent::Failed {
        error: threat_persistence_aware_failure(safe_message, persisted),
        audit: audit.with_outcome(error.cost, error.call_attempted),
    }
}

fn threat_terminal_persistence_error(run: &ProposalRun<'_>, error: anyhow::Error) -> String {
    let _ = run;
    format!("threat result unavailable because persistence failed: {error:#}")
}

fn threat_persistence_aware_failure(message: String, persisted: anyhow::Result<()>) -> String {
    match persisted {
        Ok(()) => message,
        Err(_error) => format!("{message}; additionally, terminal run persistence failed"),
    }
}

fn pretty_threat_json(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".to_string())
}

fn worker_runtime(
    config: &V2Config,
    cwd: &PathBuf,
    thinking_level: Option<String>,
    cancel: ScanCancellation,
) -> Result<LangGraphRuntime> {
    Ok(LangGraphRuntime::from_config(config, cwd)?
        .with_thinking_level(thinking_level)
        .with_cancellation(cancel))
}

fn worker_response_text(
    runtime: LangGraphRuntime,
    model: String,
    cwd: PathBuf,
    system_prompt: String,
    prompt: String,
    empty_message: &str,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
) -> CostedWorkerResult<String> {
    let traced = kuzushi_core::runtime::TracedRuntime::new(&runtime, observation.trace_handle());
    let response = kuzushi_core::runtime::query_blocking_checked(
        &traced,
        AgentQueryRequest::new(model, cwd, system_prompt, prompt),
    )
    .map_err(CostedWorkerError::unresolved)?;
    let cost = response
        .checked_cost_report()
        .map_err(CostedWorkerError::unresolved)?;
    let body = non_empty_worker_response(response.text.trim(), empty_message)
        .map_err(|error| CostedWorkerError::observed(error, cost))?;
    Ok((body, cost))
}

fn start_threat_lifecycle(
    run: &ProposalRun<'_>,
    input: &serde_json::Value,
    model: String,
    config: &V2Config,
    loaded_modules: Vec<String>,
    sink: &JobEventSink,
    task_title: &str,
) -> anyhow::Result<ProposalRunLifecycle> {
    let observation = proposal_run_observation(run.target, run.run_id, sink, task_title)?;
    run.start_observed(input, model, config, loaded_modules, observation)
}

fn non_empty_worker_response(text: &str, empty_message: &str) -> Result<String> {
    if text.is_empty() {
        anyhow::bail!("{empty_message}");
    }
    Ok(text.to_string())
}
