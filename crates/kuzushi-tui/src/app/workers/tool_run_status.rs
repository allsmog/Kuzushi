use super::*;

#[cfg(test)]
mod tests;

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
    run_id: String,
    sink: JobEventSink,
    cancel: ScanCancellation,
) -> CostedWorkerResult<String> {
    let runtime = LangGraphRuntime::from_config(&config, &cwd)
        .map_err(CostedWorkerError::before_call)?
        .with_thinking_level(thinking_level)
        .with_cancellation(cancel.clone());
    let request = root_shell_agent_request(model, cwd.clone(), system_prompt, prompt);
    runtime
        .preflight_tool_loop_blocking(&request)
        .map_err(CostedWorkerError::before_call)?;
    let mut question_calls = 0usize;
    let mut handler = |call: &kuzushi_core::runtime::ToolCall| {
        handle_operator_question_call(call, &run_id, &cwd, &sink, &cancel, &mut question_calls)
    };
    let outcome = kuzushi_core::runtime::run_tool_loop(&runtime, &request, &mut handler)
        .map_err(CostedWorkerError::unresolved)?;
    let cost = agent_loop_cost_report(&outcome).map_err(CostedWorkerError::unresolved)?;
    checked_agent_loop_text(outcome, cost)
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
    target: &std::path::Path,
    sink: &JobEventSink,
    cancel: &ScanCancellation,
    question_calls: &mut usize,
) -> anyhow::Result<kuzushi_core::runtime::ToolResult> {
    if let Some(error) = question_call_preflight(call, question_calls)? {
        return Ok(error);
    }
    let request = OperatorQuestionRequest::from_tool_input(run_id, call.input.clone())?;
    if request.requires_credential_route() {
        return route_credential_question(call, target, sink, &request);
    }
    complete_operator_question(call, target, run_id, sink, cancel, &request)
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
    target: &std::path::Path,
    run_id: &str,
    sink: &JobEventSink,
    cancel: &ScanCancellation,
    request: &OperatorQuestionRequest,
) -> anyhow::Result<kuzushi_core::runtime::ToolResult> {
    let resolution = wait_for_operator_resolution(request, sink, cancel).inspect_err(|_| {
        sink.send(ShellEvent::OperatorQuestionCompleted(
            OperatorQuestionCompleted::failed(request),
        ));
    })?;
    if let Err(error) = persist_operator_resolution(target, run_id, request, &resolution) {
        sink.send(ShellEvent::OperatorQuestionCompleted(
            OperatorQuestionCompleted::failed(request),
        ));
        return Err(error);
    }
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
    target: &std::path::Path,
    sink: &JobEventSink,
    request: &OperatorQuestionRequest,
) -> anyhow::Result<kuzushi_core::runtime::ToolResult> {
    let resolution = OperatorQuestionResolution::routed_to_setup(request.request_id.clone());
    persist_operator_resolution(target, &request.run_id, request, &resolution)?;
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

fn persist_operator_resolution(
    target: &std::path::Path,
    run_id: &str,
    request: &OperatorQuestionRequest,
    resolution: &OperatorQuestionResolution,
) -> anyhow::Result<()> {
    let resolution_label = operator_resolution_label(resolution.kind);
    for question in &request.questions {
        let answer = resolution
            .answers
            .iter()
            .find(|answer| answer.question_id() == question.id);
        let audit = operator_interaction_audit(request, question, answer, resolution_label);
        let event = kuzushi_core::run_artifacts::RunEvent::new(
            0,
            "interaction",
            resolution_label,
            "operator question resolved",
        )
        .with_tool(REQUEST_USER_INPUT_TOOL)
        .with_interaction(audit);
        kuzushi_core::run_artifacts::append_run_event(target, run_id, &event)?;
    }
    Ok(())
}

fn operator_resolution_label(kind: OperatorQuestionResolutionKind) -> &'static str {
    match kind {
        OperatorQuestionResolutionKind::Submitted => "submitted",
        OperatorQuestionResolutionKind::Canceled => "canceled",
        OperatorQuestionResolutionKind::AutoResolved => "auto_resolved",
        OperatorQuestionResolutionKind::RoutedToSetup => "routed_to_setup",
    }
}

fn operator_interaction_audit(
    request: &OperatorQuestionRequest,
    question: &OperatorQuestion,
    answer: Option<&OperatorQuestionAnswer>,
    resolution: &str,
) -> kuzushi_core::run_artifacts::RunInteractionAudit {
    kuzushi_core::run_artifacts::RunInteractionAudit {
        request_id: request.request_id.clone(),
        question_id: question.id.clone(),
        predefined_label: answer
            .and_then(OperatorQuestionAnswer::predefined_label)
            .map(str::to_string),
        resolution: resolution.to_string(),
        freeform_supplied: answer.is_some_and(non_empty_freeform_answer),
    }
}

fn non_empty_freeform_answer(answer: &OperatorQuestionAnswer) -> bool {
    answer.is_freeform()
        && matches!(answer, OperatorQuestionAnswer::Freeform { text, .. } if !text.trim().is_empty())
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
    let audit = AgentCallAudit::for_prompt(&model, PLAN_SYSTEM_PROMPT, &goal);
    let run = ProposalRun {
        target: &cwd,
        run_id: &metadata.run_id,
        kind: "plan",
        tool: "planner:propose",
    };
    let input = planner_input(&goal, phase_intent);
    let start = run.start(&input, model.clone(), &config, metadata.loaded_modules);
    if let Err(error) = start {
        send_plan_start_failure(&sink, error, audit);
        return;
    }
    let event = match run_planner_worker(
        config,
        model,
        thinking_level,
        cwd.clone(),
        &goal,
        phase_intent,
        metadata.run_id.clone(),
        sink.clone(),
        cancel.clone(),
    ) {
        Ok((plan, cost)) => persisted_plan_event(&run, plan, cost, audit),
        Err(error) => failed_plan_event(&run, error, audit, cancel.is_cancelled()),
    };
    sink.send(ShellEvent::Plan(event));
}

fn send_plan_start_failure(sink: &JobEventSink, error: anyhow::Error, audit: AgentCallAudit) {
    sink.send(ShellEvent::Plan(PlanEvent::Failed {
        error: error.to_string(),
        audit,
    }));
}

fn persisted_plan_event(
    run: &ProposalRun<'_>,
    plan: PlanProposal,
    cost: kuzushi_core::runtime::RuntimeCostReport,
    audit: AgentCallAudit,
) -> PlanEvent {
    match run.complete(
        "planner proposal ready",
        planner_proposal_value(&plan),
        cost,
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
    error: CostedWorkerError,
    audit: AgentCallAudit,
    canceled: bool,
) -> PlanEvent {
    let message = error.error.to_string();
    let persisted = run.fail(&message, canceled);
    PlanEvent::Failed {
        error: persistence_aware_failure(message, persisted),
        audit: audit.with_outcome(error.cost, error.call_attempted),
    }
}

fn terminal_persistence_error(run: &ProposalRun<'_>, error: anyhow::Error) -> String {
    let message = format!("planner result unavailable because persistence failed: {error:#}");
    persistence_aware_failure(message.clone(), run.fail(&message, false))
}

fn persistence_aware_failure(message: String, persisted: anyhow::Result<()>) -> String {
    match persisted {
        Ok(()) => message,
        Err(error) => {
            format!("{message}; additionally, terminal run persistence failed: {error:#}")
        }
    }
}

pub(crate) fn run_planner_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    goal: &str,
    phase_intent: Option<WorkflowPhase>,
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
        run_id,
        sink,
        cancel,
    )?;
    let plan = parse_plan_json_for_phase(goal, &body, phase_intent)
        .map_err(|error| CostedWorkerError::observed(error, cost))?;
    Ok((plan, cost))
}
