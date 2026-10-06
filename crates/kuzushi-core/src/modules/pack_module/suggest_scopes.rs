use super::*;

pub(super) fn descriptor() -> ToolDescriptor {
    tool_with_options("pack:suggest-scopes",
        "Suggest at most eight primary scan scopes from an existing bounded inventory and immutable context. One proposal request, no tools, delegation, repair or jobs. A valid result creates an unaccepted scope revision. An approved investigation allowance is required.",
        vec![
            opt("proposalRef", OptionType::Json, "Current source-bound scope revision whose inventory will be reused.").required(),
            opt("threatModelRef", OptionType::Json, "Immutable architecture/context revision, or null to explicitly omit context. The global active pointer is never read.").default(Value::Null),
            opt("priorities", OptionType::String, "Operator priorities for boundaries, at most 2048 bytes. Priorities never determine finding verdicts.").default(json!("")),
            opt("model", OptionType::String, "Explicit model; otherwise use the operator's selected model with no fallback."),
            opt("thinkingLevel", OptionType::Enum, "Reasoning effort. Omit to inherit the selected runtime effort.").choices(&["low","medium","high","xhigh"]),
            opt("maxOutputTokens", OptionType::Int, "Requested output tokens. Subscription OAuth may not enforce this ceiling; shared provider-request limits still apply.").integer_range(1024,8192).default(json!(4096)),
            opt("allowanceRef", OptionType::Json, "Approved investigation revision and work item. Every provider attempt, including transport retries, must reserve from this allowance.").required(),
        ]).without_phase_result()
}

pub(in crate::modules) fn execute(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let runtime = runtime.context("scope suggestions require the selected model runtime")?;
    let model = resolve_tool_model("pack:suggest-scopes", input, ctx)?;
    let review = crate::workspace::suggest_scan_scope_proposal(ctx, input, &model, runtime)?;
    Ok(json!({"ok":true, "status":"completed",
        "summary":format!("Suggested scope revision {}: {} primary boundaries, {} uncovered files and {} overlapping files. Review coverage and accept boundaries explicitly. No scan jobs started.",
            review.reference.revision, review.record.draft.scopes.len(), review.coverage.uncovered_files.total, review.coverage.overlaps.total),
        "data":review}))
}
