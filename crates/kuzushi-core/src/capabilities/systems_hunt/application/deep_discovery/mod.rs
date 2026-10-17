use super::*;
use crate::runtime::{AgentQueryResponse, RuntimeCostReport};
use crate::workspace::source_snapshot::SourceSnapshot;

mod context;
mod evidence;
mod input;
mod publication;
mod render;
mod response;
#[cfg(test)]
mod tests;
pub(crate) use input::deep_discovery_option_supported;

const TOOL: &str = "systems-hunt:deep-semantic-hunt";

pub(crate) fn execute_deep_discovery(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let input = input::canonical(input)?;
    let root = resolve_target(&input, ctx)?;
    require_active_ledger(&root, ctx)?;
    let runtime = runtime.context("Deep discovery requires the selected agent runtime")?;
    let snapshot = SourceSnapshot::capture(ctx, TOOL, &root)?;
    let store = ctx
        .findings_store
        .context("Active findings ledger is missing")?;
    let ready = snapshot.bind_result(store.prepare_finding_source_snapshot(
        &root,
        snapshot.hashes().0,
        snapshot.hashes().1,
    ))?;
    let output = snapshot.bind_result(select(&root, &input, ctx, runtime))?;
    let mut result = snapshot.finish(ctx, TOOL, &root, output);
    publication::finalize(&root, &input, ctx, &ready, &mut result)?;
    Ok(result)
}

fn require_active_ledger(root: &Path, ctx: &ToolExecutionContext<'_>) -> Result<()> {
    ctx.findings_store
        .context("Deep discovery requires the active findings ledger before model work")?
        .require_workspace_target(root)?;
    let workspace = ctx
        .workspace
        .context("Deep discovery requires an active repository")?;
    anyhow::ensure!(root.canonicalize()? == workspace.root().canonicalize()?,
        "Deep discovery target must match the active repository; switch target before approving work");
    Ok(())
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
    let system = SystemsHuntInput::from_tool_input(input)?.deep_semantic_hunt_system_prompt;
    anyhow::ensure!(
        system.len() <= 16 * 1024,
        "Discovery system prompt exceeds 16 KiB; no request started"
    );
    artifact_root(
        root,
        input["artifactDir"]
            .as_str()
            .unwrap_or(".kuzushi/systems-hunt"),
    )?;
    anyhow::ensure!(
        !ctx.is_cancelled(),
        "Deep discovery canceled before request"
    );
    let query = request(root, &model, &system, &prepared.prompt, input);
    let supplied = render::prepare_input(&prepared, &query)?;
    crate::run_artifacts::retain_prepared_model_input(
        root,
        &ctx.finding_run_id(),
        TOOL,
        &supplied,
    )?;
    ctx.ensure_active()?;
    let response = crate::runtime::query_blocking_checked(runtime, query)?;
    render::result(prepared, supplied, response, input, ctx, root)
}

fn request(
    root: &Path,
    model: &str,
    system: &str,
    prompt: &str,
    input: &Value,
) -> AgentQueryRequest {
    let mut request = AgentQueryRequest::new(model, root.to_path_buf(), system, prompt)
        .with_stage("deep-semantic-hunt")
        .with_tool_policy(AgentToolPolicy::new(
            "deep-discovery",
            std::iter::empty::<&str>(),
        ))
        .with_max_model_turns(Some(1))
        .with_max_output_tokens(4096);
    if let Some(reasoning) = input["thinkingLevel"].as_str() {
        request = request.with_thinking_level(reasoning);
    }
    request
}

#[cfg(test)]
pub(super) fn explicit_classes(input: &Value) -> Result<Vec<DeepSemanticCweSelection>> {
    input::classes(input)
}
