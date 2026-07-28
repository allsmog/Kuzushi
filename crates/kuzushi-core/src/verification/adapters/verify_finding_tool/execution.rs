use super::*;

struct VerifyGateOutcome {
    cost: RuntimeCostReport,
    response: Option<Value>,
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
    let prompt = bind_prompt_to_source_identity(
        build_verify_prompt(&finding, input.prompt_template.as_deref())?,
        &source_identity,
    )?;
    let gate = run_verify_gate(
        runtime,
        request.workspace_root,
        &prompt,
        &finding,
        &source_identity,
        &input,
    )?;
    if let Some(response) = gate.response {
        return Ok(response);
    }
    run_verify_panel(
        runtime,
        &model,
        request.workspace_root,
        &prompt,
        &finding,
        &source_identity,
        &input,
        gate.cost,
    )
}

fn capture_source_identity(
    workspace_root: &Path,
) -> crate::workflow_attempts::TargetContentIdentity {
    match crate::verification::capture_verification_source_identity(workspace_root) {
        Ok(identity) => identity,
        Err(error) => crate::verification::unavailable_verification_source_identity(error),
    }
}

fn run_verify_gate(
    runtime: &dyn AgentRuntime,
    workspace_root: &Path,
    prompt: &str,
    finding: &crate::findings::Finding,
    source_identity: &crate::workflow_attempts::TargetContentIdentity,
    input: &VerifyFindingInput,
) -> Result<VerifyGateOutcome> {
    let zero_cost = RuntimeCostReport::known(RuntimeCost::ZERO);
    let Some(gate_model) = input.gate_model.as_deref() else {
        return Ok(VerifyGateOutcome {
            cost: zero_cost,
            response: None,
        });
    };
    let gate_pass = run_one_verify_pass(
        runtime,
        gate_model,
        workspace_root,
        prompt,
        &finding.fingerprint,
        input,
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
    let response = bind_verification_result(result, finding, source_identity)
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
    runtime: &dyn AgentRuntime,
    model: &str,
    workspace_root: &Path,
    prompt: &str,
    finding: &crate::findings::Finding,
    source_identity: &crate::workflow_attempts::TargetContentIdentity,
    input: &VerifyFindingInput,
    gate_cost: RuntimeCostReport,
) -> Result<Value> {
    let passes = run_verify_passes(
        runtime,
        model,
        workspace_root,
        prompt,
        &finding.fingerprint,
        input,
    )?;
    let cost = passes.iter().try_fold(gate_cost, |total, pass| {
        total.checked_add(pass.cost_report()?, "verification consensus cost")
    })?;
    let mut result = super::super::verify_consensus::combine_verify_passes(
        passes.into_iter().map(|pass| pass.value).collect(),
    )?;
    if let Some(gate_model) = input.gate_model.as_deref() {
        annotate_gate_stage(&mut result, gate_model, true);
    }
    bind_verification_result(result, finding, source_identity)
        .and_then(|result| verify_finding_response(result, cost))
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
