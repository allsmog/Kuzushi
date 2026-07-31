use super::*;

struct VerifyGateOutcome {
    cost: RuntimeCostReport,
    response: Option<Value>,
}

struct VerifyExecution<'a> {
    runtime: &'a dyn AgentRuntime,
    model: String,
    workspace_root: &'a Path,
    prompt: String,
    finding: &'a crate::findings::Finding,
    source_identity: crate::workflow_attempts::TargetContentIdentity,
    input: VerifyFindingInput,
    trace: Option<&'a crate::run_artifacts::TraceHandle>,
}

pub(super) fn run(request: VerifyFindingToolRequest<'_>) -> Result<Value> {
    let input = VerifyFindingInput::from_tool_input(&request.input, request.workspace_root)?;
    let Some(finding) = request
        .store
        .get_finding_by_operator_reference(&input.fingerprint)?
    else {
        return Ok(missing_finding_response(&input.fingerprint));
    };
    if finding.triage.is_none() {
        return Ok(untriaged_finding_response(&finding.fingerprint));
    }

    let source_identity = capture_source_identity(request.workspace_root);
    let runtime = require_verify_finding_runtime(request.runtime)?;
    let model = verify_finding_model(&request.input, request.configured_model)?;
    require_distinct_gate_model(input.gate_model.as_deref(), &model)?;
    let prompt = bind_prompt_to_source_identity(
        build_verify_prompt(&finding, input.prompt_template.as_deref())?,
        &source_identity,
    )?;
    let execution = VerifyExecution {
        runtime,
        model,
        workspace_root: request.workspace_root,
        prompt,
        finding: &finding,
        source_identity,
        input,
        trace: request.trace,
    };
    let gate = run_verify_gate(&execution)?;
    if let Some(response) = gate.response {
        return Ok(response);
    }
    run_verify_panel(&execution, gate.cost)
}

/// Open a labelled Run Focus phase over the LLM calls a stage makes. The
/// `TracedRuntime` wrapper auto-emits per-call steps; this groups them under one
/// operator-readable header. A `None` trace is a no-op.
fn stage_scope(
    trace: Option<&crate::run_artifacts::TraceHandle>,
    label: String,
) -> Option<crate::run_artifacts::ParentScope> {
    let trace = trace?;
    let phase = trace.step("reasoning", "finding", label).emit();
    Some(trace.parent_scope(phase))
}

fn capture_source_identity(
    workspace_root: &Path,
) -> crate::workflow_attempts::TargetContentIdentity {
    match crate::verification::capture_verification_source_identity(workspace_root) {
        Ok(identity) => identity,
        Err(error) => crate::verification::unavailable_verification_source_identity(error),
    }
}

fn run_verify_gate(execution: &VerifyExecution<'_>) -> Result<VerifyGateOutcome> {
    let zero_cost = RuntimeCostReport::known(RuntimeCost::ZERO);
    let Some(gate_model) = execution.input.gate_model.as_deref() else {
        return Ok(VerifyGateOutcome {
            cost: zero_cost,
            response: None,
        });
    };
    let _scope = stage_scope(
        execution.trace,
        format!("gate · plausibility ({gate_model}) · rejection only"),
    );
    let gate_pass = run_one_verify_pass(
        execution.runtime,
        gate_model,
        execution.workspace_root,
        &execution.prompt,
        &execution.finding.fingerprint,
        &execution.input,
    )?;
    let cost = zero_cost.checked_add(gate_pass.cost_report()?, "verification gate cost")?;
    if gate_pass_is_exploitable(&gate_pass.value) {
        return Ok(VerifyGateOutcome {
            cost,
            response: None,
        });
    }
    let mut result = gate_pass.value;
    annotate_gate_stage(&mut result, gate_model, false);
    let response =
        bind_verification_result(result, execution.finding, &execution.source_identity)
        .and_then(|result| verify_finding_response(result, cost))?;
    Ok(VerifyGateOutcome {
        cost,
        response: Some(response),
    })
}

fn gate_pass_is_exploitable(result: &Value) -> bool {
    result
        .get("exploitable")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn run_verify_panel(
    execution: &VerifyExecution<'_>,
    gate_cost: RuntimeCostReport,
) -> Result<Value> {
    let passes = {
        let _scope = stage_scope(
            execution.trace,
            format!(
                "panel · {} pass(es) ({})",
                execution.input.passes, execution.model
            ),
        );
        run_verify_passes(
            execution.runtime,
            &execution.model,
            execution.workspace_root,
            &execution.prompt,
            &execution.finding.fingerprint,
            &execution.input,
        )?
    };
    let cost = passes.iter().try_fold(gate_cost, |total, pass| {
        total.checked_add(pass.cost_report()?, "verification consensus cost")
    })?;
    let mut result = super::super::verify_consensus::combine_verify_passes(
        passes.into_iter().map(|pass| pass.value).collect(),
    )?;
    if let Some(gate_model) = execution.input.gate_model.as_deref() {
        annotate_gate_stage(&mut result, gate_model, true);
    }
    let cost = resolve_split_verdict(execution, &mut result, cost)?;
    bind_verification_result(result, execution.finding, &execution.source_identity)
        .and_then(|result| verify_finding_response(result, cost))
}

/// When the panel splits evenly, an operator-named DIFFERENT model may break the
/// tie. Absence is the default; a same-model or invalid escalation is refused
/// and disclosed. The escalation runs one extra pass and adopts its verdict
/// without ever forging unanimity.
fn resolve_split_verdict(
    execution: &VerifyExecution<'_>,
    result: &mut Value,
    cost: RuntimeCostReport,
) -> Result<RuntimeCostReport> {
    if !super::super::verify_consensus::panel_verdict_is_split(result) {
        return Ok(cost);
    }
    match crate::runtime::decide_tie_break(
        &execution.model,
        execution.input.escalation_model.as_deref(),
    ) {
        crate::runtime::TieBreakEscalation::NotRequested => Ok(cost),
        crate::runtime::TieBreakEscalation::Refused(reason) => {
            annotate_escalation_refused(result, reason);
            emit_escalation_refusal(execution.trace, reason);
            Ok(cost)
        }
        crate::runtime::TieBreakEscalation::Escalate(escalation_model) => run_escalation_pass(
            execution.runtime,
            &escalation_model,
            execution.workspace_root,
            &execution.prompt,
            execution.finding,
            &execution.input,
            result,
            cost,
            execution.trace,
        ),
    }
}

fn emit_escalation_refusal(
    trace: Option<&crate::run_artifacts::TraceHandle>,
    reason: crate::runtime::TieBreakRefusal,
) {
    if let Some(trace) = trace {
        let _ = trace
            .step("refused", "finding", reason.operator_message())
            .with_severity("danger")
            .emit();
    }
}

#[allow(clippy::too_many_arguments)]
fn run_escalation_pass(
    runtime: &dyn AgentRuntime,
    escalation_model: &str,
    workspace_root: &Path,
    prompt: &str,
    finding: &crate::findings::Finding,
    input: &VerifyFindingInput,
    result: &mut Value,
    cost: RuntimeCostReport,
    trace: Option<&crate::run_artifacts::TraceHandle>,
) -> Result<RuntimeCostReport> {
    let _scope = stage_scope(trace, format!("escalation · tie-break ({escalation_model})"));
    // A best-effort tie-breaker's failure must never destroy the already-paid
    // split verdict: on error we keep the split, disclose the failure, and the
    // cost stays at the panel subtotal (no escalation pass was billed).
    match attempt_escalation_pass(runtime, escalation_model, workspace_root, prompt, finding, input, cost) {
        Ok((pass_value, escalated_cost)) => {
            apply_escalation_verdict(result, &pass_value, escalation_model);
            Ok(escalated_cost)
        }
        Err(error) => {
            annotate_escalation_failed(result, escalation_model, &error);
            emit_escalation_failure(trace, &error);
            Ok(cost)
        }
    }
}

fn attempt_escalation_pass(
    runtime: &dyn AgentRuntime,
    escalation_model: &str,
    workspace_root: &Path,
    prompt: &str,
    finding: &crate::findings::Finding,
    input: &VerifyFindingInput,
    cost: RuntimeCostReport,
) -> Result<(Value, RuntimeCostReport)> {
    let pass = run_one_verify_pass(
        runtime,
        escalation_model,
        workspace_root,
        prompt,
        &finding.fingerprint,
        input,
    )?;
    let escalated_cost =
        cost.checked_add(pass.cost_report()?, "verification tie-break escalation cost")?;
    Ok((pass.value, escalated_cost))
}

fn emit_escalation_failure(trace: Option<&crate::run_artifacts::TraceHandle>, error: &anyhow::Error) {
    if let Some(trace) = trace {
        let _ = trace
            .step(
                "refused",
                "finding",
                format!("tie-break escalation attempt failed: {error}; split verdict unchanged"),
            )
            .with_severity("danger")
            .emit();
    }
}

fn run_verify_passes(
    runtime: &dyn AgentRuntime,
    model: &str,
    workspace_root: &Path,
    prompt: &str,
    fingerprint: &str,
    input: &VerifyFindingInput,
) -> Result<Vec<CostedStructuredJson<Value>>> {
    let mut passes = Vec::with_capacity(input.passes as usize);
    for _ in 0..input.passes {
        passes.push(run_one_verify_pass(
            runtime,
            model,
            workspace_root,
            prompt,
            fingerprint,
            input,
        )?);
    }
    Ok(passes)
}
