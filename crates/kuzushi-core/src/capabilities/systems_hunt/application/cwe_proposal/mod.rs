use super::*;
use crate::workspace::source_snapshot::run_source_bound_tool;

mod context;
mod input;
mod render;
mod response;
pub(crate) use input::cwe_proposal_option_supported;
pub(super) use response::validate_classes;
#[cfg(test)]
mod tests;

const TOOL: &str = "systems-hunt:deep-semantic-cwe-select";

pub(crate) fn execute_cwe_proposal(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let input = input::canonical(input)?;
    let target = resolve_target(&input, ctx)?;
    let runtime = runtime.context("CWE proposals require the selected agent runtime")?;
    run_source_bound_tool(ctx, TOOL, &target, || select(&target, &input, ctx, runtime))
}

fn select(
    root: &Path,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
) -> Result<Value> {
    let model = crate::runtime::resolve_explicit_model(
        TOOL,
        optional_nonempty_string(input, "model")?,
        ctx.config.model.as_deref(),
    )?;
    let prepared = context::prepare(root, input, ctx)?;
    let system = SystemsHuntInput::from_tool_input(input)?.deep_semantic_cwe_system_prompt;
    anyhow::ensure!(
        system.len() <= 16 * 1024,
        "CWE system prompt exceeds 16 KiB; no request started"
    );
    anyhow::ensure!(!ctx.is_cancelled(), "CWE proposal canceled before request");
    let response = crate::runtime::query_blocking_checked(
        runtime,
        request(root, &model, &system, &prepared.prompt, input),
    )?;
    render::result(
        prepared,
        system,
        model,
        response,
        input::Limits::parse(input)?.max_classes,
        ctx.is_cancelled(),
    )
}

fn request(
    root: &Path,
    model: &str,
    system: &str,
    prompt: &str,
    input: &Value,
) -> AgentQueryRequest {
    let mut request = AgentQueryRequest::new(model, root.to_path_buf(), system, prompt)
        .with_stage("deep-semantic-cwe-select")
        .with_tool_policy(AgentToolPolicy::new(
            "cwe-proposal",
            std::iter::empty::<&str>(),
        ))
        .with_max_model_turns(Some(1))
        .with_max_output_tokens(4096);
    if let Some(level) = input["thinkingLevel"].as_str() {
        request = request.with_thinking_level(level);
    }
    request
}

#[cfg(test)]
pub(super) fn legacy_select(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<DeepSemanticCweOutput> {
    let result = execute_cwe_proposal(&input::legacy_input(input)?, ctx, runtime)?;
    anyhow::ensure!(
        result["status"] != "failed",
        "{}",
        result["output"].as_str().unwrap_or("CWE proposal failed")
    );
    Ok(DeepSemanticCweOutput {
        cwes: serde_json::from_value(result["data"]["cwes"].clone())
            .context("CWE proposal result is malformed")?,
        cost_usd: result["data"]["observedCostUsd"]
            .as_f64()
            .context("Observed CWE cost missing")?,
        cost_usd_exact: result["data"]["costUsdExact"]
            .as_bool()
            .context("CWE cost state missing")?,
    })
}
