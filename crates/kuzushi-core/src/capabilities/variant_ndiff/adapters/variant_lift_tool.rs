use super::*;
use crate::findings::ReviewConfirmation;
use crate::WorkspaceTarget;

#[cfg(test)]
mod review_gate_tests;

pub fn run_variant_lift_pattern(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let fingerprint = match variant_lift_fingerprint(&input) {
        Some(fingerprint) => fingerprint,
        None => return Ok(missing_variant_lift_fingerprint_response()),
    };
    emit_variant_lift_step(
        ctx,
        "tool",
        format!("variant:lift-pattern start · fp={fingerprint}"),
    );
    let (workspace, finding, confirmation) = match variant_lift_subject(ctx, &fingerprint)? {
        VariantLiftSubject::Ready(subject) => subject,
        VariantLiftSubject::Rejected(response) => return Ok(response),
    };
    let signature =
        query_variant_lift_signature(&input, ctx, runtime, workspace, &finding, &confirmation)?;
    ctx.ensure_active()?;
    let object = signature
        .value
        .as_object()
        .context("variant:lift-pattern output parse failed: expected a JSON object")?;
    let output = variant_lift_output(&finding, object);
    emit_variant_lift_step(ctx, "done", "variant:lift-pattern complete");
    let cost = signature.cost_report()?;
    Ok(variant_lift_response(
        fingerprint,
        signature.value,
        finding,
        output,
        cost,
    ))
}

fn variant_lift_fingerprint(input: &Value) -> Option<String> {
    match input.get("fingerprint").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}

fn missing_variant_lift_fingerprint_response() -> Value {
    crate::module_result::failed_output_result(
        "variant:lift-pattern rejected input",
        "variant:lift-pattern requires a fingerprint.",
        json!({ "reason": "missing-fingerprint" }),
    )
}

enum VariantLiftSubject<'a> {
    Ready((&'a WorkspaceTarget, Finding, ReviewConfirmation)),
    Rejected(Value),
}

fn variant_lift_subject<'a>(
    ctx: &'a ToolExecutionContext<'_>,
    fingerprint: &str,
) -> Result<VariantLiftSubject<'a>> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "variant:lift-pattern",
        ))?;
    let store = ctx
        .findings_store
        .context("variant:lift-pattern requires the active workspace findings store")?;
    let Some(finding) = store.get_finding_by_operator_reference(fingerprint)? else {
        return Ok(VariantLiftSubject::Rejected(
            missing_variant_lift_finding_response(workspace, fingerprint),
        ));
    };
    let gate = crate::findings::load_finding_review_gate(store, &finding)?;
    Ok(
        match variant_confirmation("variant:lift-pattern", fingerprint, gate) {
            Ok(confirmation) => VariantLiftSubject::Ready((workspace, finding, confirmation)),
            Err(response) => VariantLiftSubject::Rejected(response),
        },
    )
}

fn missing_variant_lift_finding_response(workspace: &WorkspaceTarget, fingerprint: &str) -> Value {
    let output = format!(
        "No finding with fingerprint \"{}\" in {}.",
        fingerprint,
        workspace.findings_db_path().display()
    );
    crate::module_result::failed_output_result(
        "variant:lift-pattern finding not found",
        output,
        json!({ "fingerprint": fingerprint, "reason": "finding-not-found" }),
    )
}

fn query_variant_lift_signature(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    workspace: &WorkspaceTarget,
    finding: &Finding,
    confirmation: &ReviewConfirmation,
) -> Result<CostedStructuredJson<Value>> {
    let runtime = require_runtime("variant:lift-pattern", runtime)?;
    let model = require_model("variant:lift-pattern", input, ctx)?;
    let thinking_level = optional_variant_reasoning(input);
    let prompt = build_variant_lift_prompt(finding, confirmation);
    let _llm_scope = begin_variant_lift_scope(ctx);
    query_required_structured_json_with_cost(
        runtime,
        variant_lift_request(model, workspace, prompt, thinking_level.as_deref())?,
        StructuredJsonContract::new(
            "variant:lift-pattern",
            "VariantSignature",
            variant_signature_schema(),
        ),
        validate_variant_signature,
    )
}

fn variant_lift_request(
    model: String,
    workspace: &WorkspaceTarget,
    prompt: String,
    thinking_level: Option<&str>,
) -> Result<AgentQueryRequest> {
    let request = AgentQueryRequest::new(
        model,
        workspace.root().to_path_buf(),
        VARIANT_SIGNATURE_SYSTEM_PROMPT.to_string(),
        prompt,
    )
    .with_tool_policy(try_whitebox_static_policy_for_target(workspace.root())?);
    Ok(match thinking_level {
        Some(level) => request.with_thinking_level(level),
        None => request,
    })
}

fn begin_variant_lift_scope(
    ctx: &ToolExecutionContext<'_>,
) -> Option<crate::run_artifacts::ParentScope> {
    ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", "lift-pattern", "lift-pattern")
            .emit();
        trace.parent_scope(phase)
    })
}

fn variant_lift_output(finding: &Finding, object: &Map<String, Value>) -> String {
    [
        "Unaccepted source-pattern draft. Inspect the signature before using reviewed lesson generation or approving separate discovery work.".to_string(),
        format!(
            "Variant signature for {} ({}:{}):",
            finding.rule_id, finding.file_path, finding.start_line
        ),
        variant_lift_field("Source", read_object_string(object, &["source"])),
        variant_lift_field("Sink", read_object_string(object, &["sink"])),
        variant_lift_field(
            "Missing guard",
            read_object_string(object, &["missingGuard", "missing_guard"]),
        ),
        format!(
            "  Languages:     {}",
            read_object_string_array(object, &["languages"]).join(", ")
        ),
        format!(
            "  Keywords:      {}",
            read_object_string_array(object, &["keywords"]).join(", ")
        ),
        String::new(),
        read_object_string(object, &["description"]).unwrap_or_default(),
    ]
    .join("\n")
}

fn variant_lift_field(label: &str, value: Option<String>) -> String {
    let label = format!("{label}:");
    format!("  {label:<15}{}", value.unwrap_or_default())
}

fn variant_lift_response(
    fingerprint: String,
    signature: Value,
    finding: Finding,
    output: String,
    cost: crate::runtime::RuntimeCostReport,
) -> Value {
    let data = json!({
        "fingerprint": fingerprint,
        "signature": signature,
        "finding": finding,
        "draft": true,
        "accepted": false,
        "contextActivated": false,
    });
    let mut result = crate::module_result::completed_output_result(
        "Unaccepted source-pattern draft",
        output,
        data,
    );
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    result
}

fn emit_variant_lift_step(ctx: &ToolExecutionContext<'_>, kind: &str, label: impl Into<String>) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, "lift-pattern", label.into()).emit();
    }
}
