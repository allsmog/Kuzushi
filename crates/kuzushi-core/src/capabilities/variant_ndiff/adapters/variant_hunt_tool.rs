use super::*;
use crate::findings::{FindingReviewGate, ReviewConfirmation, ReviewDecision};

#[cfg(test)]
mod review_gate_tests;

pub fn run_variant_hunt(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let Some(fingerprint) = variant_hunt_fingerprint(&input) else {
        return Ok(missing_variant_hunt_fingerprint_response());
    };
    emit_variant_hunt_start(ctx, &fingerprint);
    let run = match prepare_variant_hunt_run(input, ctx, runtime, fingerprint)? {
        VariantHuntPreparation::Run(run) => run,
        VariantHuntPreparation::Response(response) => return Ok(response),
    };
    let findings = query_variant_hunt_findings(&run, ctx)?;
    let persisted = persist_findings(&run.target, &findings.value, ctx)?;
    emit_variant_hunt_done(ctx, findings.value.len());
    let cost = findings.cost_report()?;
    Ok(variant_hunt_response(
        &run,
        findings.value,
        persisted,
        cost,
    ))
}

fn variant_hunt_fingerprint(input: &Value) -> Option<String> {
    input
        .get("fingerprint")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn missing_variant_hunt_fingerprint_response() -> Value {
    crate::module_result::failed_output_result(
        "variant:hunt rejected input",
        "variant:hunt requires a fingerprint.",
        json!({ "reason": "missing-fingerprint" }),
    )
}

struct VariantHuntRun<'a> {
    fingerprint: String,
    target: PathBuf,
    finding: Finding,
    confirmation: ReviewConfirmation,
    runtime: &'a dyn AgentRuntime,
    model: String,
    max_findings: usize,
    thinking_level: String,
    include_vendored: bool,
    vendor_paths: Vec<String>,
}

enum VariantHuntPreparation<'a> {
    Run(VariantHuntRun<'a>),
    Response(Value),
}

fn prepare_variant_hunt_run<'a>(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
    fingerprint: String,
) -> Result<VariantHuntPreparation<'a>> {
    let subject = match resolve_variant_hunt_subject(&input, ctx, &fingerprint)? {
        VariantHuntSubjectResolution::Found(subject) => subject,
        VariantHuntSubjectResolution::Response(response) => {
            return Ok(VariantHuntPreparation::Response(response));
        }
    };
    let execution = resolve_variant_hunt_execution(&input, ctx, runtime)?;
    Ok(VariantHuntPreparation::Run(VariantHuntRun {
        fingerprint,
        target: subject.target,
        finding: subject.finding,
        confirmation: subject.confirmation,
        runtime: execution.runtime,
        model: execution.model,
        max_findings: execution.max_findings,
        thinking_level: execution.thinking_level,
        include_vendored: execution.include_vendored,
        vendor_paths: execution.vendor_paths,
    }))
}

struct VariantHuntSubject {
    target: PathBuf,
    finding: Finding,
    confirmation: ReviewConfirmation,
}

enum VariantHuntSubjectResolution {
    Found(VariantHuntSubject),
    Response(Value),
}

fn resolve_variant_hunt_subject(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    fingerprint: &str,
) -> Result<VariantHuntSubjectResolution> {
    let target = resolve_tool_target(input, ctx)?;
    let workspace = require_variant_hunt_workspace(ctx)?;
    let store = variant_hunt_store(ctx)?;
    let Some(finding) = store.get_finding_by_reference(fingerprint)? else {
        return Ok(VariantHuntSubjectResolution::Response(
            missing_variant_hunt_finding_response(workspace, fingerprint),
        ));
    };
    let gate = crate::findings::load_finding_review_gate(store, &finding)?;
    Ok(match variant_hunt_confirmation(fingerprint, gate) {
        Ok(confirmation) => VariantHuntSubjectResolution::Found(VariantHuntSubject {
            target,
            finding,
            confirmation,
        }),
        Err(response) => VariantHuntSubjectResolution::Response(response),
    })
}

fn variant_hunt_store<'a>(
    ctx: &'a ToolExecutionContext<'_>,
) -> Result<&'a crate::findings::FindingStore> {
    ctx.findings_store
        .context("variant:hunt requires the active workspace findings store")
}

fn missing_variant_hunt_finding_response(
    workspace: &crate::workspace::WorkspaceTarget,
    fingerprint: &str,
) -> Value {
    let output = format!(
        "No finding with fingerprint \"{}\" in {}.",
        fingerprint,
        workspace.findings_db_path().display()
    );
    crate::module_result::failed_output_result(
        "variant:hunt finding not found",
        output,
        json!({ "fingerprint": fingerprint, "reason": "finding-not-found" }),
    )
}

fn require_variant_hunt_workspace<'a>(
    ctx: &'a ToolExecutionContext<'_>,
) -> Result<&'a crate::workspace::WorkspaceTarget> {
    ctx.workspace
        .context(crate::workspace::active_workspace_required_message("variant:hunt"))
}

struct VariantHuntExecution<'a> {
    runtime: &'a dyn AgentRuntime,
    model: String,
    max_findings: usize,
    thinking_level: String,
    include_vendored: bool,
    vendor_paths: Vec<String>,
}

fn resolve_variant_hunt_execution<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<VariantHuntExecution<'a>> {
    let runtime = require_runtime("variant:hunt", runtime)?;
    let model = require_model("variant:hunt", input, ctx)?;
    Ok(VariantHuntExecution {
        runtime,
        model,
        max_findings: positive_usize_input(input, "maxFindings", 10, 50),
        thinking_level: agentic_hunter_thinking_level(input),
        include_vendored: include_vendored_variants(input),
        vendor_paths: vendor_paths_from_input(input),
    })
}

fn include_vendored_variants(input: &Value) -> bool {
    input
        .get("includeVendored")
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

fn query_variant_hunt_findings(
    run: &VariantHuntRun<'_>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<CostedStructuredJson<Vec<Finding>>> {
    let raw = query_variant_hunt_json(run, ctx)?;
    let repo_name = repo_name(&run.target);
    Ok(CostedStructuredJson {
        value: normalize_variant_findings(
            raw.value,
            &run.target,
            &repo_name,
            &run.finding,
            run.max_findings,
        )?,
        cost_usd: raw.cost_usd,
        cost_usd_exact: raw.cost_usd_exact,
    })
}

fn query_variant_hunt_json(
    run: &VariantHuntRun<'_>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<CostedStructuredJson<Value>> {
    let prompt = build_variant_hunt_prompt(
        &run.finding,
        &run.confirmation,
        run.include_vendored,
        &run.vendor_paths,
    );
    let _llm_scope = begin_variant_hunt_scope(ctx);
    let raw = query_required_structured_json_with_cost(
        run.runtime,
        AgentQueryRequest::new(
            run.model.clone(),
            run.target.clone(),
            VARIANT_HUNT_SYSTEM_PROMPT.to_string(),
            prompt,
        )
        .with_tool_policy(try_whitebox_static_policy_for_target(&run.target)?)
        .with_thinking_level(run.thinking_level.clone()),
        StructuredJsonContract::new("variant:hunt", "VariantFindings", findings_schema()),
        require_json_object,
    )?;
    drop(_llm_scope);
    Ok(raw)
}

fn begin_variant_hunt_scope(
    ctx: &ToolExecutionContext<'_>,
) -> Option<crate::run_artifacts::ParentScope> {
    ctx.trace.map(|trace| {
        let phase = trace.step("reasoning", "hunt", "hunt-variants").emit();
        trace.parent_scope(phase)
    })
}

fn emit_variant_hunt_start(ctx: &ToolExecutionContext<'_>, fingerprint: &str) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "hunt",
                format!("variant:hunt start · fp={fingerprint}"),
            )
            .emit();
    }
}

fn emit_variant_hunt_done(ctx: &ToolExecutionContext<'_>, variant_count: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "hunt",
                format!("variant:hunt complete · {variant_count} variants"),
            )
            .emit();
    }
}

fn variant_hunt_response(
    run: &VariantHuntRun<'_>,
    findings: Vec<Finding>,
    persisted: Option<PersistedRun>,
    cost: crate::runtime::RuntimeCostReport,
) -> Value {
    let output = render_variant_hunt_output(
        &run.finding,
        findings.len(),
        run.include_vendored,
        findings.as_slice(),
    );
    let summary = format!(
        "variant:hunt completed with {} variant{}",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" }
    );
    let data = json!({
        "fingerprint": run.fingerprint,
        "originalFinding": run.finding,
        "variants": findings,
        "scope": {
            "includeVendored": run.include_vendored,
            "vendorPaths": visible_vendor_paths(run),
        },
        "persisted": persisted,
    });
    let mut result = crate::module_result::completed_output_result(summary, output, data);
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    result
}

fn visible_vendor_paths(run: &VariantHuntRun<'_>) -> Vec<String> {
    if run.include_vendored {
        run.vendor_paths.clone()
    } else {
        Vec::new()
    }
}

/// Variant hunting generalizes a confirmed vulnerability, so only a finding
/// whose review decision in force confirms it qualifies; a human verdict
/// outranks cached automated triage either way.
fn variant_hunt_confirmation(
    fingerprint: &str,
    gate: FindingReviewGate,
) -> std::result::Result<ReviewConfirmation, Value> {
    match gate {
        FindingReviewGate::Confirmed(confirmation) => Ok(confirmation),
        FindingReviewGate::Unreviewed => Err(unreviewed_variant_subject_response(fingerprint)),
        FindingReviewGate::ReviewerDismissed(decision)
        | FindingReviewGate::Unconfirmed(decision) => {
            Err(unconfirmed_variant_subject_response(fingerprint, &decision))
        }
    }
}

fn unreviewed_variant_subject_response(fingerprint: &str) -> Value {
    let output = format!(
        "variant:hunt expects a confirmed TP; finding \"{fingerprint}\" has no triage verdict and no confirming review decision. {}",
        crate::findings::MISSING_CONFIRMATION_GUIDANCE
    );
    crate::module_result::failed_output_result(
        "variant:hunt finding is not confirmed",
        output,
        json!({ "fingerprint": fingerprint, "reason": "missing-triage" }),
    )
}

fn unconfirmed_variant_subject_response(fingerprint: &str, decision: &ReviewDecision) -> Value {
    let output = format!(
        "variant:hunt expects a confirmed TP; finding \"{fingerprint}\" has review decision \"{}\" by {}.",
        decision.verdict.as_str(),
        decision.author.as_str(),
    );
    let verdict = decision
        .verdict
        .to_triage_verdict()
        .map_or(decision.verdict.as_str(), TriageVerdict::as_str);
    crate::module_result::failed_output_result(
        "variant:hunt finding is not confirmed",
        output,
        json!({
            "fingerprint": fingerprint,
            "reason": "non-true-positive",
            "verdict": verdict,
            "reviewDecision": decision.verdict.as_str(),
            "reviewAuthor": decision.author.as_str(),
        }),
    )
}
