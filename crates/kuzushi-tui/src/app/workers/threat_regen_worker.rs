use super::*;
use serde_json::json;

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
    let prompt = threat_regen_prompt(&existing);
    let audit = AgentCallAudit::for_prompt(&model, THREAT_PATCH_SYSTEM_PROMPT, &prompt);
    let run = ProposalRun {
        target: &cwd,
        run_id: &metadata.run_id,
        kind: "threat",
        tool: "threat-model:propose",
    };
    let input = threat_regen_input(&existing);
    let start = run.start(&input, model.clone(), &config, metadata.loaded_modules);
    if let Err(error) = start {
        sink.send(ShellEvent::Threat(ThreatPatchEvent::Failed {
            error: error.to_string(),
            audit,
        }));
        return;
    }
    let event = match run_threat_regen_worker(
        config,
        model,
        thinking_level,
        cwd.clone(),
        existing,
        cancel.clone(),
    ) {
        Ok((patch, cost)) => persisted_threat_patch_event(&run, patch, cost, audit),
        Err(error) => failed_threat_event(&run, error, audit, cancel.is_cancelled()),
    };
    sink.send(ShellEvent::Threat(event));
}

fn persisted_threat_patch_event(
    run: &ProposalRun<'_>,
    patch: ThreatPatch,
    cost: kuzushi_core::runtime::RuntimeCostReport,
    audit: AgentCallAudit,
) -> ThreatPatchEvent {
    match run.complete(
        "threat-model proposal ready",
        threat_patch_value(&patch),
        cost,
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

pub(crate) fn threat_ask_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    question: String,
    metadata: ProposalRunMetadata,
    sink: JobEventSink,
    cancel: ScanCancellation,
) {
    let prompt = threat_ask_prompt(&question, &existing);
    let audit = AgentCallAudit::for_prompt(&model, ASK_SYSTEM_PROMPT, &prompt);
    let run = ProposalRun {
        target: &cwd,
        run_id: &metadata.run_id,
        kind: "threat",
        tool: "threat-model:ask",
    };
    let input = threat_ask_input(&existing, &question);
    let start = run.start(&input, model.clone(), &config, metadata.loaded_modules);
    if let Err(error) = start {
        send_threat_start_failure(&sink, error, audit);
        return;
    }
    let event = match run_threat_ask_worker(
        config,
        model,
        thinking_level,
        cwd.clone(),
        existing,
        &question,
        cancel.clone(),
    ) {
        Ok((answer, cost)) => persisted_threat_answer_event(&run, answer, cost, audit),
        Err(error) => failed_threat_event(&run, error, audit, cancel.is_cancelled()),
    };
    sink.send(ShellEvent::Threat(event));
}

fn send_threat_start_failure(sink: &JobEventSink, error: anyhow::Error, audit: AgentCallAudit) {
    sink.send(ShellEvent::Threat(ThreatPatchEvent::Failed {
        error: error.to_string(),
        audit,
    }));
}

fn persisted_threat_answer_event(
    run: &ProposalRun<'_>,
    answer: String,
    cost: kuzushi_core::runtime::RuntimeCostReport,
    audit: AgentCallAudit,
) -> ThreatPatchEvent {
    match run.complete(
        "threat-model answer ready",
        json!({ "answer": answer.clone() }),
        cost,
    ) {
        Ok(()) => ThreatPatchEvent::Answer {
            text: answer,
            audit: audit.with_cost(cost),
        },
        Err(error) => ThreatPatchEvent::Failed {
            error: threat_terminal_persistence_error(run, error),
            audit: audit.with_cost(cost),
        },
    }
}

fn failed_threat_event(
    run: &ProposalRun<'_>,
    error: CostedWorkerError,
    audit: AgentCallAudit,
    canceled: bool,
) -> ThreatPatchEvent {
    let message = error.error.to_string();
    let persisted = run.fail(&message, canceled);
    ThreatPatchEvent::Failed {
        error: threat_persistence_aware_failure(message, persisted),
        audit: audit.with_outcome(error.cost, error.call_attempted),
    }
}

fn threat_terminal_persistence_error(run: &ProposalRun<'_>, error: anyhow::Error) -> String {
    let message = format!("threat result unavailable because persistence failed: {error:#}");
    threat_persistence_aware_failure(message.clone(), run.fail(&message, false))
}

fn threat_persistence_aware_failure(message: String, persisted: anyhow::Result<()>) -> String {
    match persisted {
        Ok(()) => message,
        Err(error) => {
            format!("{message}; additionally, terminal run persistence failed: {error:#}")
        }
    }
}

pub(crate) fn run_threat_ask_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    question: &str,
    cancel: ScanCancellation,
) -> CostedWorkerResult<String> {
    let runtime = worker_runtime(&config, &cwd, thinking_level, cancel)
        .map_err(CostedWorkerError::before_call)?;
    let prompt = threat_ask_prompt(question, &existing);
    let answer = worker_response_text(
        runtime,
        model,
        cwd,
        ASK_SYSTEM_PROMPT.to_string(),
        prompt,
        "threat-ask returned no content",
    )?;
    Ok((answer.0.to_string(), answer.1))
}

fn threat_ask_prompt(question: &str, existing: &serde_json::Value) -> String {
    format!(
        "OPERATOR QUESTION:\n{question}\n\nCURRENT THREAT MODEL JSON:\n{}",
        pretty_threat_json(existing)
    )
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
) -> CostedWorkerResult<String> {
    let response = kuzushi_core::runtime::query_blocking_checked(
        &runtime,
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

fn non_empty_worker_response(text: &str, empty_message: &str) -> Result<String> {
    if text.is_empty() {
        anyhow::bail!("{empty_message}");
    }
    Ok(text.to_string())
}
