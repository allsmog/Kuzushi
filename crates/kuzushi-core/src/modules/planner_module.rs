use super::*;

pub(super) fn module() -> BuiltinModule {
    builtin_module(
        "planner", "Workflow Planner", ModuleKind::Catalog,
        "Draft bounded workflow proposals for operator review. No proposal executes tools or changes settings.",
        tools_with_policy(
            workspace_policy(ToolPhase::Map, RuntimeRequirement::Always, FindingStoreRequirement::Optional),
            vec![tool_with_options("planner:propose",
                "Experimental, single-request workflow proposal under an approved investigation allowance. No tools, delegation, output repair or action execution. New work requires separate approval.",
                vec![
                    target_option(),
                    opt("goal", OptionType::String, "Operator goal, from one to 4096 bytes. Goals guide priorities, never finding verdicts.").required(),
                    opt("proposalConfigSha256", OptionType::String, "Frozen prompt, schema and supplied capability metadata fingerprint, prepared by the workflow study.").required().advanced(),
                    opt("phase", OptionType::Enum, "Optional selected investigation phase. Omission permits option proposals and notes only.").choices(&["map", "scan", "review"]),
                    opt("model", OptionType::String, "Selected model, with no provider or model fallback."),
                    opt("thinkingLevel", OptionType::Enum, "Reasoning effort; omission inherits the selected runtime.").choices(&["low", "medium", "high", "xhigh"]),
                    opt("maxOutputTokens", OptionType::Int, "Requested output tokens. Subscription adapters may not enforce this; provider-attempt limits remain mandatory.").integer_range(1024,8192).default(json!(4096)),
                    opt("allowanceRef", OptionType::Json, "Approved investigation revision and fixed work item. Every potentially billable attempt reserves from it.").required(),
                ]).without_phase_result().with_allowance_category(AllowanceCategory::Scope)],
        ), vec![],
    ).labs()
}

pub(super) fn execute(
    registry: &ModuleRegistry,
    _name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let runtime = runtime.context("workflow planning requires the selected runtime")?;
    let model = resolve_tool_model("planner:propose", input, ctx)?;
    crate::capabilities::planner::propose(registry, input, ctx, &model, runtime)
}
