use super::*;

#[path = "tool_run_status/planner_job.rs"]
mod planner_job;
#[cfg(test)]
mod tests;
use planner_job::PlannerWorkerJob;

pub(crate) fn tool_run_status(tool_name: &str) -> &'static str {
    match tool_name {
        "context:build" | "context-lite:index" => "indexing repository context",
        "semgrep:scan" | "codeql:scan" | "iac-scan:scan" | "license-scan:scan"
        | "cargo-audit:scan" | "govulncheck:scan" | "secret-scan:scan" => "searching with scanner",
        "sast:scan" => "searching SAST pipeline",
        "findings:list" => "reading persisted findings",
        "recon:http-fingerprint" | "recon:nmap" => "collecting recon evidence",
        "triage:run" => "asking model to triage persisted findings",
        "verify:finding" | "verify:exploit" => "validating finding evidence",
        "patch:finding" => "preparing remediation patch",
        _ if tool_uses_agent_runtime(tool_name) => "asking model-backed tool",
        _ => "running tool",
    }
}

pub(crate) fn agent_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    question: String,
    run_id: String,
    sink: JobEventSink,
    cancel: ScanCancellation,
) {
    let system_prompt = agent_system_prompt();
    let audit = AgentCallAudit::for_prompt(&model, &system_prompt, &question);
    let result = run_agent_worker(
        config,
        model,
        thinking_level,
        cwd,
        question,
        run_id,
        sink.clone(),
        cancel,
    );
    let event = match result {
        Ok((answer, cost)) => AgentEvent::Answered {
            text: answer.text,
            audit: audit.with_cost(cost),
        },
        Err(error) => AgentEvent::Failed {
            error: error.error.to_string(),
            audit: audit.with_outcome(error.cost, error.call_attempted),
        },
    };
    sink.send(ShellEvent::Agent(event));
}

pub(crate) struct AgentWorkerAnswer {
    pub(crate) text: String,
}

pub(crate) fn run_agent_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    question: String,
    run_id: String,
    sink: JobEventSink,
    cancel: ScanCancellation,
) -> CostedWorkerResult<AgentWorkerAnswer> {
    run_interactive_agent_worker(
        config,
        model,
        thinking_level,
        cwd,
        question,
        run_id,
        sink,
        cancel,
    )
}

fn agent_system_prompt() -> String {
    format!(
        "{ASK_SYSTEM_PROMPT}\n\nYou may call request_user_input when 1-3 concise operator choices materially affect the answer. Do not ask for credentials; direct credential work to Setup/Auth. Ask at most three times."
    )
}

#[allow(clippy::too_many_arguments)]
fn run_interactive_agent_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    question: String,
    run_id: String,
    sink: JobEventSink,
    cancel: ScanCancellation,
) -> CostedWorkerResult<AgentWorkerAnswer> {
    let (text, cost) = run_root_shell_tool_loop(
        config,
        model,
        thinking_level,
        cwd,
        agent_system_prompt(),
        question,
        None,
        RootRunIntent::interactive_answer(),
        run_id,
        sink,
        cancel,
    )?;
    Ok((AgentWorkerAnswer { text }, cost))
}

#[allow(clippy::too_many_arguments)]
fn run_root_shell_tool_loop(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    system_prompt: String,
    prompt: String,
    observation: Option<kuzushi_core::run_lifecycle::RunObservationHandle>,
    intent: RootRunIntent,
    run_id: String,
    sink: JobEventSink,
    cancel: ScanCancellation,
) -> CostedWorkerResult<String> {
    let prepared = prepare_root_shell_tool_loop(
        config,
        model,
        thinking_level,
        cwd.clone(),
        system_prompt,
        prompt,
        observation,
        intent,
        &run_id,
        &sink,
        &cancel,
    )?;
    execute_root_shell_tool_loop(prepared, &run_id, &sink, &cancel)
}

struct PreparedRootShellToolLoop {
    runtime: LangGraphRuntime,
    request: kuzushi_core::runtime::AgentToolLoopRequest,
    observation: kuzushi_core::run_lifecycle::RunObservationHandle,
    terminalize_in_loop: bool,
}

#[derive(Clone, Copy)]
struct RootRunIntent {
    task_title: &'static str,
    terminalize_in_loop: bool,
    task_already_running: bool,
}

impl RootRunIntent {
    const fn interactive_answer() -> Self {
        Self {
            task_title: "Answer the operator request",
            terminalize_in_loop: true,
            task_already_running: false,
        }
    }

    const fn planner_proposal() -> Self {
        Self {
            task_title: "Draft the requested workflow plan",
            terminalize_in_loop: false,
            task_already_running: true,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_root_shell_tool_loop(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    system_prompt: String,
    prompt: String,
    observation: Option<kuzushi_core::run_lifecycle::RunObservationHandle>,
    intent: RootRunIntent,
    run_id: &str,
    sink: &JobEventSink,
    cancel: &ScanCancellation,
) -> Result<PreparedRootShellToolLoop, CostedWorkerError> {
    let observation = match observation {
        Some(observation) => observation,
        None => root_run_observation(&cwd, run_id, sink, intent.task_title)
            .map_err(CostedWorkerError::before_call)?,
    };
    let runtime = LangGraphRuntime::from_config(&config, &cwd)
        .map_err(CostedWorkerError::before_call)?
        .with_thinking_level(thinking_level)
        .with_cancellation(cancel.clone());
    let request = root_shell_agent_request(model, cwd.clone(), system_prompt, prompt);
    if let Err(error) = runtime.preflight_tool_loop_blocking(&request) {
        settle_preflight_failure(
            &observation,
            run_id,
            intent.terminalize_in_loop,
            cancel,
            &error,
        )
        .map_err(CostedWorkerError::before_call)?;
        return Err(CostedWorkerError::before_call(error));
    }
    if !intent.task_already_running {
        mark_root_task_running(&observation).map_err(CostedWorkerError::before_call)?;
    }
    Ok(PreparedRootShellToolLoop {
        runtime,
        request,
        observation,
        terminalize_in_loop: intent.terminalize_in_loop,
    })
}

fn execute_root_shell_tool_loop(
    prepared: PreparedRootShellToolLoop,
    run_id: &str,
    sink: &JobEventSink,
    cancel: &ScanCancellation,
) -> CostedWorkerResult<String> {
    let PreparedRootShellToolLoop {
        runtime,
        request,
        observation,
        terminalize_in_loop,
    } = prepared;
    let mut question_calls = 0usize;
    let mut handler = |call: &kuzushi_core::runtime::ToolCall| {
        handle_operator_question_call(
            call,
            run_id,
            sink,
            cancel,
            &observation,
            &mut question_calls,
        )
    };
    let traced = kuzushi_core::runtime::TracedRuntime::new(&runtime, observation.trace_handle());
    run_observed_model_loop(
        &traced,
        &request,
        &mut handler,
        &observation,
        run_id,
        sink,
        cancel,
        terminalize_in_loop,
    )
}

fn run_observed_model_loop(
    runtime: &dyn AgentRuntime,
    request: &kuzushi_core::runtime::AgentToolLoopRequest,
    handler: &mut dyn kuzushi_core::runtime::ToolCallHandler,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    run_id: &str,
    sink: &JobEventSink,
    cancel: &ScanCancellation,
    terminalize_in_loop: bool,
) -> CostedWorkerResult<String> {
    let outcome = match kuzushi_core::runtime::run_tool_loop_observed(runtime, request, handler) {
        Ok(outcome) => outcome,
        Err(error) => {
            let persisted = settle_root_model_run_if_owned(
                observation,
                run_id,
                terminalize_in_loop,
                terminal_status_after_cancellation(
                    cancel,
                    kuzushi_core::run_lifecycle::RunItemStatus::Failed,
                ),
                kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
                "model-backed workflow failed",
            );
            if let Err(persistence) = persisted.as_ref() {
                sink.publish_run_item_writer_error(run_id, persistence, false);
            }
            return Err(CostedWorkerError::unresolved(error_with_lifecycle(
                error, persisted,
            )));
        }
    };
    finish_root_shell_tool_loop(
        outcome,
        observation,
        run_id,
        sink,
        cancel,
        terminalize_in_loop,
    )
}

fn finish_root_shell_tool_loop(
    outcome: kuzushi_core::runtime::Observed<kuzushi_core::runtime::AgentLoopOutcome>,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    run_id: &str,
    sink: &JobEventSink,
    cancel: &ScanCancellation,
    terminalize_in_loop: bool,
) -> CostedWorkerResult<String> {
    let outcome = outcome.value;
    let cost = agent_loop_cost_report(&outcome).map_err(CostedWorkerError::unresolved)?;
    let status = terminal_status_after_cancellation(cancel, usable_agent_outcome_status(&outcome));
    let summary = model_outcome_summary(status, outcome.steps_used);
    let settlement = settle_root_model_run_if_owned(
        observation,
        run_id,
        terminalize_in_loop,
        status,
        cost,
        &summary,
    );
    preserve_executed_outcome(settlement, sink, run_id, cost)?;
    checked_agent_loop_text(outcome, cost)
}

fn preserve_executed_outcome(
    settlement: anyhow::Result<()>,
    sink: &JobEventSink,
    run_id: &str,
    cost: kuzushi_core::runtime::RuntimeCostReport,
) -> Result<(), CostedWorkerError> {
    let Err(error) = settlement else {
        return Ok(());
    };
    if sink.publish_run_item_writer_error(run_id, &error, true) {
        return Ok(());
    }
    Err(CostedWorkerError::observed(error, cost))
}

fn root_run_observation(
    target: &std::path::Path,
    run_id: &str,
    sink: &JobEventSink,
    task_title: &str,
) -> anyhow::Result<kuzushi_core::run_lifecycle::RunObservationHandle> {
    let (item_subscriber, range_subscriber, derivative_subscriber, fault_subscriber) =
        sink.run_lifecycle_subscribers(run_id);
    kuzushi_core::run_lifecycle::RunObservationHandle::jsonl_with_derivative_delivery_subscriber(
        target,
        run_id,
        Some(item_subscriber),
        Some(range_subscriber),
        Some(derivative_subscriber),
        Some(fault_subscriber),
    )?
    .start_root_task(task_title)
}

fn error_with_lifecycle(error: anyhow::Error, persisted: anyhow::Result<()>) -> anyhow::Error {
    match persisted {
        Ok(()) => error,
        Err(persistence) => anyhow::anyhow!(
            "{error:#}; additionally, semantic model-call persistence failed: {persistence:#}"
        ),
    }
}

fn mark_root_task_running(
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
) -> anyhow::Result<()> {
    observation
        .task_handle()
        .ok_or_else(|| anyhow::anyhow!("root model run lacks its semantic task"))?
        .update_and_flush(kuzushi_core::run_lifecycle::RunItemStatus::Running, None)?;
    Ok(())
}

fn settle_preflight_failure(
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    run_id: &str,
    terminalize_in_loop: bool,
    cancel: &ScanCancellation,
    error: &anyhow::Error,
) -> anyhow::Result<()> {
    settle_root_model_run_if_owned(
        observation,
        run_id,
        terminalize_in_loop,
        terminal_status_after_cancellation(
            cancel,
            kuzushi_core::run_lifecycle::RunItemStatus::Failed,
        ),
        kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
        &format!(
            "model runtime refused execution: {}",
            safe_runtime_error_class(error)
        ),
    )
}

fn terminal_status_after_cancellation(
    cancel: &ScanCancellation,
    fallback: kuzushi_core::run_lifecycle::RunItemStatus,
) -> kuzushi_core::run_lifecycle::RunItemStatus {
    match cancel.disposition() {
        Some(kuzushi_core::scan::CancellationDisposition::Canceled) => {
            kuzushi_core::run_lifecycle::RunItemStatus::Canceled
        }
        Some(kuzushi_core::scan::CancellationDisposition::Interrupted) => {
            kuzushi_core::run_lifecycle::RunItemStatus::Interrupted
        }
        None => fallback,
    }
}

fn settle_root_model_run_if_owned(
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    run_id: &str,
    terminalize_in_loop: bool,
    status: kuzushi_core::run_lifecycle::RunItemStatus,
    cost: kuzushi_core::runtime::RuntimeCostReport,
    summary: &str,
) -> anyhow::Result<()> {
    if !terminalize_in_loop {
        return Ok(());
    }
    emit_safe_model_summary(observation, summary)?;
    observation
        .task_handle()
        .ok_or_else(|| anyhow::anyhow!("root model run lacks its semantic task"))?
        .update_and_flush(status, None)?;
    observation.emit_and_flush(kuzushi_core::run_lifecycle::RunItemRecord::new(
        kuzushi_core::run_lifecycle::RunItemId::new(),
        kuzushi_core::run_lifecycle::RunItemSource::Workflow,
        kuzushi_core::run_lifecycle::RunItemV1::TerminalOutcome {
            status,
            summary: kuzushi_core::run_lifecycle::SafeText::operator_visible(summary),
            cost,
            continuation: root_model_continuation(run_id, status)?,
        },
    ))?;
    Ok(())
}

fn emit_safe_model_summary(
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    summary: &str,
) -> anyhow::Result<()> {
    observation.emit_coalescible(kuzushi_core::run_lifecycle::RunItemRecord::new(
        kuzushi_core::run_lifecycle::RunItemId::new(),
        kuzushi_core::run_lifecycle::RunItemSource::Runtime,
        kuzushi_core::run_lifecycle::RunItemV1::SafeReasoningSummary {
            text: kuzushi_core::run_lifecycle::SafeText::operator_visible(summary),
            redaction_policy_version: 1,
        },
    ))
}

fn root_model_continuation(
    run_id: &str,
    status: kuzushi_core::run_lifecycle::RunItemStatus,
) -> anyhow::Result<kuzushi_core::run_lifecycle::WorkflowContinuation> {
    use kuzushi_core::run_lifecycle::{SafeText, WorkflowContinuation};
    if status == kuzushi_core::run_lifecycle::RunItemStatus::Completed {
        return Ok(WorkflowContinuation::NoFurtherAction {
            reason: SafeText::operator_visible("answer returned to the operator"),
        });
    }
    Ok(WorkflowContinuation::InspectRun {
        run_id: kuzushi_core::run_lifecycle::RunId::parse(run_id)?,
        reason: SafeText::operator_visible("inspect the incomplete model workflow before retry"),
    })
}

fn usable_agent_outcome_status(
    outcome: &kuzushi_core::runtime::AgentLoopOutcome,
) -> kuzushi_core::run_lifecycle::RunItemStatus {
    if outcome.truncated || outcome.text.trim().is_empty() {
        kuzushi_core::run_lifecycle::RunItemStatus::Partial
    } else {
        kuzushi_core::run_lifecycle::RunItemStatus::Completed
    }
}

fn model_outcome_summary(
    status: kuzushi_core::run_lifecycle::RunItemStatus,
    steps_used: u32,
) -> String {
    if status == kuzushi_core::run_lifecycle::RunItemStatus::Completed {
        format!("model-backed workflow completed after {steps_used} provider turn(s)")
    } else {
        format!(
            "model-backed workflow produced no complete operator result after {steps_used} provider turn(s)"
        )
    }
}

fn safe_runtime_error_class(error: &anyhow::Error) -> &'static str {
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("credential") || text.contains("unauthorized") {
        "authentication_error"
    } else if text.contains("model") {
        "model_configuration_error"
    } else {
        "runtime_preflight_error"
    }
}

fn root_shell_agent_request(
    model: String,
    cwd: PathBuf,
    system_prompt: String,
    prompt: String,
) -> kuzushi_core::runtime::AgentToolLoopRequest {
    kuzushi_core::runtime::AgentToolLoopRequest {
        model,
        cwd,
        system_prompt,
        prompt,
        tools: vec![request_user_input_tool()],
        max_steps: MAX_AGENT_STEPS,
        runtime_options: None,
        temperature: None,
    }
}

fn handle_operator_question_call(
    call: &kuzushi_core::runtime::ToolCall,
    run_id: &str,
    sink: &JobEventSink,
    cancel: &ScanCancellation,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    question_calls: &mut usize,
) -> anyhow::Result<kuzushi_core::runtime::ToolResult> {
    if let Some(error) = question_call_preflight(call, question_calls)? {
        return Ok(error);
    }
    let request = OperatorQuestionRequest::from_tool_input(run_id, call.input.clone())?;
    let observed_questions = persist_operator_questions(observation, &request)?;
    if request.requires_credential_route() {
        return route_credential_question(call, sink, observation, &observed_questions, &request);
    }
    complete_operator_question(
        call,
        run_id,
        sink,
        cancel,
        observation,
        &observed_questions,
        &request,
    )
}

fn question_call_preflight(
    call: &kuzushi_core::runtime::ToolCall,
    question_calls: &mut usize,
) -> anyhow::Result<Option<kuzushi_core::runtime::ToolResult>> {
    anyhow::ensure!(
        call.name == REQUEST_USER_INPUT_TOOL,
        "unsupported root-shell agent tool {:?}",
        call.name
    );
    *question_calls = question_calls.saturating_add(1);
    Ok((*question_calls > MAX_QUESTION_CALLS)
        .then(|| question_tool_error(call, "request_user_input call limit reached (3 per run)")))
}

fn complete_operator_question(
    call: &kuzushi_core::runtime::ToolCall,
    run_id: &str,
    sink: &JobEventSink,
    cancel: &ScanCancellation,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    observed_questions: &[ObservedOperatorQuestion],
    request: &OperatorQuestionRequest,
) -> anyhow::Result<kuzushi_core::runtime::ToolResult> {
    let resolution = match wait_for_operator_resolution(request, sink, cancel) {
        Ok(resolution) => resolution,
        Err(error) => {
            persist_operator_cancellation(observation, observed_questions)?;
            sink.send(ShellEvent::OperatorQuestionCompleted(
                OperatorQuestionCompleted::failed(request),
            ));
            return Err(error);
        }
    };
    persist_operator_decisions(observation, observed_questions, &resolution)?;
    anyhow::ensure!(
        sink.send(ShellEvent::OperatorQuestionCompleted(
            OperatorQuestionCompleted::from_resolution(run_id, &resolution)
        )),
        "operator question completion could not be delivered reliably"
    );
    Ok(kuzushi_core::runtime::ToolResult {
        call_id: call.call_id.clone(),
        output: serde_json::to_value(resolution)?,
        is_error: false,
    })
}

fn route_credential_question(
    call: &kuzushi_core::runtime::ToolCall,
    sink: &JobEventSink,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    observed_questions: &[ObservedOperatorQuestion],
    request: &OperatorQuestionRequest,
) -> anyhow::Result<kuzushi_core::runtime::ToolResult> {
    let resolution = OperatorQuestionResolution::routed_to_setup(request.request_id.clone());
    persist_operator_decisions(observation, observed_questions, &resolution)?;
    anyhow::ensure!(
        sink.send(ShellEvent::OperatorQuestionCompleted(
            OperatorQuestionCompleted::from_resolution(&request.run_id, &resolution),
        )),
        "credential question completion could not be delivered reliably"
    );
    anyhow::ensure!(
        sink.send(ShellEvent::CredentialQuestionRouted {
            request_id: request.request_id.clone(),
            run_id: request.run_id.clone(),
        }),
        "credential question could not be routed reliably"
    );
    Ok(kuzushi_core::runtime::ToolResult {
        call_id: call.call_id.clone(),
        output: serde_json::json!({
            "error": "CREDENTIALS_REQUIRED",
            "resolution": "routed_to_setup",
            "message": "Credentials are accepted only in Kuzushi Setup/Auth. No secret or freeform answer was collected."
        }),
        is_error: true,
    })
}

struct ObservedOperatorQuestion {
    contract_id: String,
    question_id: kuzushi_core::run_lifecycle::RunQuestionId,
    item_id: kuzushi_core::run_lifecycle::RunItemId,
    choice_ids: Vec<kuzushi_core::run_lifecycle::SafeText>,
}

fn persist_operator_questions(
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    request: &OperatorQuestionRequest,
) -> anyhow::Result<Vec<ObservedOperatorQuestion>> {
    let mut observed = Vec::with_capacity(request.questions.len());
    for (ordinal, question) in request.questions.iter().enumerate() {
        let item = observed_operator_question(request, question, ordinal);
        observation.emit(operator_question_record(question, &item))?;
        observed.push(item);
    }
    observation.flush()?;
    Ok(observed)
}

fn observed_operator_question(
    request: &OperatorQuestionRequest,
    question: &OperatorQuestion,
    question_ordinal: usize,
) -> ObservedOperatorQuestion {
    ObservedOperatorQuestion {
        contract_id: question.id.clone(),
        question_id: kuzushi_core::run_lifecycle::deterministic_question_id(
            &request.request_id,
            &question.id,
            question_ordinal,
        ),
        item_id: kuzushi_core::run_lifecycle::RunItemId::new(),
        choice_ids: question
            .options
            .iter()
            .enumerate()
            .map(|(choice_ordinal, _)| {
                kuzushi_core::run_lifecycle::deterministic_choice_id(
                    &request.request_id,
                    &question.id,
                    question_ordinal,
                    choice_ordinal,
                )
            })
            .collect(),
    }
}

fn operator_question_record(
    question: &OperatorQuestion,
    item: &ObservedOperatorQuestion,
) -> kuzushi_core::run_lifecycle::RunItemRecord {
    let choices = question
        .options
        .iter()
        .zip(&item.choice_ids)
        .map(
            |(option, choice_id)| kuzushi_core::run_lifecycle::OperatorChoice {
                id: choice_id.clone(),
                label: kuzushi_core::run_lifecycle::SafeText::operator_visible(&option.label),
            },
        )
        .collect();
    kuzushi_core::run_lifecycle::RunItemRecord::new(
        item.item_id,
        kuzushi_core::run_lifecycle::RunItemSource::Runtime,
        kuzushi_core::run_lifecycle::RunItemV1::OperatorQuestion {
            question_id: item.question_id,
            prompt: kuzushi_core::run_lifecycle::SafeText::operator_visible(format!(
                "{}: {}",
                question.header, question.prompt
            )),
            choices,
            authorization_scope: operator_input_scope(),
        },
    )
}

fn persist_operator_decisions(
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    observed: &[ObservedOperatorQuestion],
    resolution: &OperatorQuestionResolution,
) -> anyhow::Result<()> {
    for question in observed {
        let answer = resolution
            .answers
            .iter()
            .find(|answer| answer.question_id() == question.contract_id);
        let decision = operator_decision_value(question, answer, resolution.kind)?;
        emit_operator_decision(observation, question, decision)?;
    }
    observation.flush()
}

fn persist_operator_cancellation(
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    observed: &[ObservedOperatorQuestion],
) -> anyhow::Result<()> {
    for question in observed {
        emit_operator_decision(
            observation,
            question,
            kuzushi_core::run_lifecycle::OperatorDecisionValue::Denied,
        )?;
    }
    observation.flush()
}

fn emit_operator_decision(
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    question: &ObservedOperatorQuestion,
    decision: kuzushi_core::run_lifecycle::OperatorDecisionValue,
) -> anyhow::Result<()> {
    observation.emit(kuzushi_core::run_lifecycle::RunItemRecord::new(
        question.item_id,
        kuzushi_core::run_lifecycle::RunItemSource::Operator,
        kuzushi_core::run_lifecycle::RunItemV1::OperatorDecision {
            question_id: question.question_id,
            decision,
            authorization_scope: operator_input_scope(),
        },
    ))
}

fn operator_decision_value(
    question: &ObservedOperatorQuestion,
    answer: Option<&OperatorQuestionAnswer>,
    kind: OperatorQuestionResolutionKind,
) -> anyhow::Result<kuzushi_core::run_lifecycle::OperatorDecisionValue> {
    match answer {
        Some(OperatorQuestionAnswer::Predefined { choice_id, .. }) => {
            anyhow::ensure!(
                question
                    .choice_ids
                    .iter()
                    .any(|candidate| candidate.as_str() == choice_id),
                "operator answer references an unknown choice identity"
            );
            Ok(
                kuzushi_core::run_lifecycle::OperatorDecisionValue::Selected {
                    choice_id: kuzushi_core::run_lifecycle::SafeText::operator_visible(choice_id),
                },
            )
        }
        Some(OperatorQuestionAnswer::Freeform { text, .. }) if !text.trim().is_empty() => {
            Ok(kuzushi_core::run_lifecycle::OperatorDecisionValue::ProvidedFreeform)
        }
        _ if kind == OperatorQuestionResolutionKind::Canceled => {
            Ok(kuzushi_core::run_lifecycle::OperatorDecisionValue::Denied)
        }
        _ => Ok(kuzushi_core::run_lifecycle::OperatorDecisionValue::Deferred),
    }
}

fn operator_input_scope() -> kuzushi_core::run_lifecycle::SafeText {
    kuzushi_core::run_lifecycle::SafeText::operator_visible("operator_input_for_current_run")
}

fn wait_for_operator_resolution(
    request: &OperatorQuestionRequest,
    sink: &JobEventSink,
    cancel: &ScanCancellation,
) -> anyhow::Result<OperatorQuestionResolution> {
    use std::sync::mpsc::sync_channel;
    let (control, receiver) = sync_channel(8);
    let generation = sink.generation();
    deliver_operator_question(request, sink, generation, control)?;
    let mut deadline = request
        .auto_resolution_ms
        .map(|millis| std::time::Instant::now() + std::time::Duration::from_millis(millis));
    loop {
        anyhow::ensure!(
            !cancel.is_cancelled(),
            "operator question canceled with the run"
        );
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Ok(request.recommended_resolution());
        }
        match receive_question_signal(&receiver, request, generation)? {
            QuestionSignal::Wait => {}
            QuestionSignal::Snooze => deadline = None,
            QuestionSignal::Resolve(resolution) => return Ok(resolution),
        }
    }
}

fn deliver_operator_question(
    request: &OperatorQuestionRequest,
    sink: &JobEventSink,
    generation: WorkerGeneration,
    control: std::sync::mpsc::SyncSender<OperatorQuestionControl>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        sink.send(ShellEvent::OperatorQuestion(OperatorQuestionEnvelope {
            request: request.clone(),
            generation,
            control,
        })),
        "operator question could not be delivered reliably"
    );
    Ok(())
}

enum QuestionSignal {
    Wait,
    Snooze,
    Resolve(OperatorQuestionResolution),
}

fn receive_question_signal(
    receiver: &std::sync::mpsc::Receiver<OperatorQuestionControl>,
    request: &OperatorQuestionRequest,
    generation: WorkerGeneration,
) -> anyhow::Result<QuestionSignal> {
    use std::sync::mpsc::RecvTimeoutError;
    let control = match receiver.recv_timeout(std::time::Duration::from_millis(50)) {
        Ok(control) => control,
        Err(RecvTimeoutError::Timeout) => return Ok(QuestionSignal::Wait),
        Err(RecvTimeoutError::Disconnected) => {
            anyhow::bail!("operator question response channel disconnected")
        }
    };
    Ok(question_signal(control, request, generation))
}

fn question_signal(
    control: OperatorQuestionControl,
    request: &OperatorQuestionRequest,
    generation: WorkerGeneration,
) -> QuestionSignal {
    match control {
        OperatorQuestionControl::SnoozeAutoResolution {
            request_id,
            run_id,
            generation: answer,
        } if question_control_matches(request, generation, &request_id, &run_id, answer) => {
            QuestionSignal::Snooze
        }
        OperatorQuestionControl::Resolve {
            resolution,
            run_id,
            generation: answer,
        } if question_control_matches(
            request,
            generation,
            &resolution.request_id,
            &run_id,
            answer,
        ) =>
        {
            QuestionSignal::Resolve(resolution)
        }
        OperatorQuestionControl::Cancel {
            request_id,
            run_id,
            generation: answer,
        } if question_control_matches(request, generation, &request_id, &run_id, answer) => {
            QuestionSignal::Resolve(OperatorQuestionResolution::canceled(request_id))
        }
        _ => QuestionSignal::Wait,
    }
}

fn question_control_matches(
    request: &OperatorQuestionRequest,
    generation: WorkerGeneration,
    request_id: &str,
    run_id: &str,
    answer_generation: WorkerGeneration,
) -> bool {
    request.request_id == request_id && request.run_id == run_id && generation == answer_generation
}

fn question_tool_error(
    call: &kuzushi_core::runtime::ToolCall,
    message: &str,
) -> kuzushi_core::runtime::ToolResult {
    kuzushi_core::runtime::ToolResult {
        call_id: call.call_id.clone(),
        output: serde_json::json!({ "error": message }),
        is_error: true,
    }
}

fn agent_loop_cost_report(
    outcome: &kuzushi_core::runtime::AgentLoopOutcome,
) -> anyhow::Result<kuzushi_core::runtime::RuntimeCostReport> {
    let cost = kuzushi_core::runtime::RuntimeCost::from_usd(
        outcome.cost_usd,
        "root-shell agent loop cost",
    )?;
    Ok(if outcome.cost_usd_exact {
        kuzushi_core::runtime::RuntimeCostReport::known(cost)
    } else {
        kuzushi_core::runtime::RuntimeCostReport::incomplete(cost)
    })
}

fn checked_agent_loop_text(
    outcome: kuzushi_core::runtime::AgentLoopOutcome,
    cost: kuzushi_core::runtime::RuntimeCostReport,
) -> CostedWorkerResult<String> {
    if outcome.truncated {
        return Err(CostedWorkerError::observed(
            anyhow::anyhow!("agent stopped after the eight-step interaction limit"),
            cost,
        ));
    }
    let text = outcome.text.trim();
    if text.is_empty() {
        return Err(CostedWorkerError::observed(
            anyhow::anyhow!("agent returned an empty answer after interactive work"),
            cost,
        ));
    }
    Ok((text.to_string(), cost))
}

pub(crate) const PLAN_SYSTEM_PROMPT: &str = r#"You are Kuzushi's planning assistant.
Translate the operator's natural-language goal into a strict JSON proposal.
Output ONLY JSON, starting with '{'. No prose, no code fences.
Schema:
{
  "summary": "one-sentence restatement of the goal",
  "changes": [
    {"kind": "run_tool", "tool": "<descriptor tool name>", "input": {}},
    {"kind": "set_option", "tool": "<tool name or null>", "global": false, "name": "<key>", "value": "<value>"},
    {"kind": "note", "text": "<short operator-facing note>"}

  ],
  "unsupported": ["<natural-language reason something cannot be encoded>"]
}

Rules:
- Emit run_tool only when the prompt explicitly marks itself as a PHASE INTENT
  and only from that prompt's allowed descriptor list.
- If required operator choices are missing, call request_user_input and then
  continue this same planning turn. Do not emit an ask change.
- Never ask for credentials; direct credential work to Setup/Auth.
- Only emit set_option changes you are confident map to existing tool options.
- Otherwise add a string to "unsupported" instead.
- Prefer at most 6 changes."#;

pub(crate) fn planner_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    goal: String,
    phase_intent: Option<WorkflowPhase>,
    metadata: ProposalRunMetadata,
    sink: JobEventSink,
    cancel: ScanCancellation,
) {
    PlannerWorkerJob {
        config,
        model,
        thinking_level,
        cwd,
        goal,
        phase_intent,
        metadata,
        cancel,
    }
    .run(sink);
}

fn settle_planner_result(
    run: &ProposalRun<'_>,
    lifecycle: ProposalRunLifecycle,
    result: CostedWorkerResult<PlanProposal>,
    audit: AgentCallAudit,
    cancellation: Option<kuzushi_core::scan::CancellationDisposition>,
) -> PlanEvent {
    match result {
        Ok((plan, cost)) => persisted_plan_event(run, lifecycle, plan, cost, audit),
        Err(error) => failed_plan_event(run, lifecycle, error, audit, cancellation),
    }
}

fn start_planner_lifecycle(
    run: &ProposalRun<'_>,
    input: &serde_json::Value,
    model: String,
    config: &V2Config,
    loaded_modules: Vec<String>,
    sink: &JobEventSink,
) -> anyhow::Result<ProposalRunLifecycle> {
    let observation = proposal_run_observation(
        run.target,
        run.run_id,
        sink,
        "Draft the requested workflow plan",
    )?;
    run.start_observed(input, model, config, loaded_modules, observation)
}

fn send_plan_start_failure(sink: &JobEventSink, error: anyhow::Error, audit: AgentCallAudit) {
    sink.send(ShellEvent::Plan(PlanEvent::Failed {
        error: error.to_string(),
        audit,
    }));
}

fn persisted_plan_event(
    run: &ProposalRun<'_>,
    lifecycle: ProposalRunLifecycle,
    plan: PlanProposal,
    cost: kuzushi_core::runtime::RuntimeCostReport,
    audit: AgentCallAudit,
) -> PlanEvent {
    match run.complete_observed(
        "planner proposal ready",
        planner_proposal_value(&plan),
        cost,
        lifecycle,
    ) {
        Ok(()) => PlanEvent::Proposed {
            plan,
            audit: audit.with_cost(cost),
        },
        Err(error) => PlanEvent::Failed {
            error: terminal_persistence_error(run, error),
            audit: audit.with_cost(cost),
        },
    }
}

fn failed_plan_event(
    run: &ProposalRun<'_>,
    lifecycle: ProposalRunLifecycle,
    error: CostedWorkerError,
    audit: AgentCallAudit,
    cancellation: Option<kuzushi_core::scan::CancellationDisposition>,
) -> PlanEvent {
    let message = error.error.to_string();
    let safe_message = kuzushi_core::runtime::safe_model_failure_message(&message);
    let persisted = run.fail_observed(&safe_message, cancellation, error.cost, lifecycle);
    PlanEvent::Failed {
        error: persistence_aware_failure(safe_message, persisted),
        audit: audit.with_outcome(error.cost, error.call_attempted),
    }
}

fn terminal_persistence_error(run: &ProposalRun<'_>, error: anyhow::Error) -> String {
    let _ = run;
    format!("planner result unavailable because persistence failed: {error:#}")
}

fn persistence_aware_failure(message: String, persisted: anyhow::Result<()>) -> String {
    match persisted {
        Ok(()) => message,
        Err(_error) => format!("{message}; additionally, terminal run persistence failed"),
    }
}

pub(crate) fn run_planner_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    goal: &str,
    phase_intent: Option<WorkflowPhase>,
    observation: kuzushi_core::run_lifecycle::RunObservationHandle,
    run_id: String,
    sink: JobEventSink,
    cancel: ScanCancellation,
) -> CostedWorkerResult<PlanProposal> {
    let system_prompt = format!(
        "{PLAN_SYSTEM_PROMPT}\n\nYou may call request_user_input when 1-3 concise operator choices materially affect the proposal. Ask at most three times."
    );
    let (body, cost) = run_root_shell_tool_loop(
        config,
        model,
        thinking_level,
        cwd,
        system_prompt,
        goal.to_string(),
        Some(observation),
        RootRunIntent::planner_proposal(),
        run_id,
        sink,
        cancel,
    )?;
    let plan = parse_plan_json_for_phase(goal, &body, phase_intent)
        .map_err(|error| CostedWorkerError::observed(error, cost))?;
    Ok((plan, cost))
}
