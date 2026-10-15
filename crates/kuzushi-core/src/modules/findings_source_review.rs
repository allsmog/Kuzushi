//! Shared descriptor-driven source capture and explicit human decisions.
use super::*;
use crate::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
use crate::workspace::{
    capture_review_source_with_limit, decide_on_review_source, read_review_source_capture,
};

pub(crate) fn tool() -> ToolDescriptor {
    let mut tool = tool_with_options("findings:review-source", "Capture, inspect and explicitly decide against the current source. No scan or model calls.", vec![
        opt("op", OptionType::Enum, "Source review action.").choices(&["capture", "read", "decide"]).default(json!("capture")),
        opt("finding", OptionType::String, "Exact recorded finding reference.").required(),
        opt("sourceRef", OptionType::String, "Immutable reference returned by capture; required for read and decide."),
        opt("maxCitedSourceBytes", OptionType::Int, "Maximum complete cited-file bytes captured for code reading; larger files are explicitly omitted.").integer_range(1,262144).default(json!(262144)),
        opt("verdict", OptionType::Enum, "Explicit human decision for the captured source; required for decide.").choices(&["confirmed", "rejected_false_positive", "accepted_risk", "deferred", "needs_review"]),
        opt("reason", OptionType::String, "Required explanation of the source review for decide."),
    ]).with_policy(workspace_policy(ToolPhase::Review, RuntimeRequirement::Never, FindingStoreRequirement::Required))
        .without_phase_result();
    tool.approval = ApprovalPolicy::Explicit;
    tool
}

pub(crate) fn execute(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let store = ctx
        .findings_store
        .context("Source review requires a findings store")?;
    let workspace = ctx
        .workspace
        .context("Source review requires an active target")?;
    let finding = store
        .get_finding_by_operator_reference(required(input, "finding")?)?
        .context("Source review finding was not found")?;
    let capture = match required(input, "op")? {
        "capture" => capture_review_source_with_limit(
            ctx,
            &finding,
            input["maxCitedSourceBytes"]
                .as_u64()
                .context("Source review requires maxCitedSourceBytes")? as usize,
        )?,
        "read" | "decide" => {
            read_review_source_capture(workspace, &finding, required(input, "sourceRef")?)?
        }
        _ => anyhow::bail!("Unsupported source review action"),
    };
    finish(input, ctx, &finding, capture)
}

fn finish(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    finding: &crate::Finding,
    capture: crate::workspace::WorkspaceReviewSourceCapture,
) -> Result<Value> {
    let code = crate::workspace::read_captured_review_code(
        ctx.workspace
            .context("Source review requires an active target")?,
        &capture.source,
    )?;
    let id = if required(input, "op")? == "decide" {
        Some(decide_on_review_source(
            ctx,
            finding,
            &human_decision(input)?,
            &capture.source_ref,
        )?)
    } else {
        None
    };
    let output = source_output(&capture, id)?;
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "schemaVersion":1, "sourceRef":capture.source_ref, "reviewedSource":capture.source,
            "decisionId":id, "providerRequests":0, "createsObservation":false,
            "currentCheckoutApplicability":if id.is_some() { "matched_before_save" } else { "not_assessed" },
            "fixStatus":"not_assessed",
            "captureCoverage":"bounded_source_identity_walk",
            "citedSourceCode": code,
        }),
    ))
}

fn required<'a>(input: &'a Value, key: &str) -> Result<&'a str> {
    input
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("Source review requires {key}"))
}

fn human_decision(input: &Value) -> Result<ReviewDecision> {
    let verdict = ReviewDecisionVerdict::from_str(required(input, "verdict")?)
        .context("Unknown source review verdict")?;
    Ok(ReviewDecision {
        verdict,
        author: TriageAuthor::Human,
        confidence: 1.0,
        rationale: required(input, "reason")?.into(),
        dismiss_reason: None,
        actor: Some("operator".into()),
    })
}

fn source_output(
    capture: &crate::workspace::WorkspaceReviewSourceCapture,
    id: Option<i64>,
) -> Result<String> {
    let label = id.map_or_else(
        || "Source identity captured; inspect the current code before deciding.".into(),
        |id| format!("Decision #{id} saved against this captured source."),
    );
    Ok(format!("{label}\nSource reference: {}\nSnapshot: {}\nContent: {}\nGit: {}\nIdentity follows indexed source exclusions. Ignored and symlink material is not covered; this is not a complete source copy.\nThis does not record a scan observation or establish a fix.\nRun findings:review-source with op=decide, the same finding and sourceRef, an explicit verdict and a reason.",
        capture.source_ref, capture.source.snapshot_hash, capture.source.tree_hash,
        serde_json::to_string(&capture.source.source_git)?))
}

#[cfg(test)]
mod tests;
