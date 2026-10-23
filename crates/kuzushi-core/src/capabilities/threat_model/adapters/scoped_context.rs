//! One inactive context draft over exact accepted discovery and shared files.
use super::*;
use crate::workspace::{source_snapshot::SourceSnapshot, AcceptedScanScopeSelection, ScanScopeRef};

mod contract;
mod publication;
mod selection;
mod synthesis;
use selection::ContextSource;
#[cfg(test)]
mod tests;

pub(super) fn collect_recorded_evidence_source(
    build: &BuildInput,
    paths: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<(CodeSource, Value)> {
    let paths = selection::files::checked_paths(paths)?;
    let inventory = selection::files::require_inventory_membership(&paths, ctx)?;
    let source = collect_context_files(
        build,
        &paths,
        "selected-evidence",
        "selected-evidence-source-code-v1",
        ctx,
    )?;
    Ok((source, inventory))
}

pub(crate) fn validate_scoped_context_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<Value>> {
    Ok(resolve_validated_context_source(input, ctx)?.inventory)
}

fn resolve_validated_context_source(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ContextSource> {
    contract::validate(input)?;
    context_edit::require_selected_context_target(
        ctx.workspace
            .context("File-group context requires a repository")?
            .root(),
        input,
        ctx,
    )?;
    let scope = ContextSource::resolve(input, ctx)?;
    inherited_document(input, ctx)?;
    Ok(scope)
}

pub(crate) fn build_scoped_context(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    flavor: BuildFlavor,
) -> Result<Value> {
    anyhow::ensure!(
        flavor.tool_name() == "threat-model:build",
        "Accepted file-group context is supported by threat-model:build only"
    );
    let scope = resolve_validated_context_source(&input, ctx)?;
    let runtime =
        runtime.context("File-group context requires the explicitly selected model runtime")?;
    let build = parse_build_input(&input, ctx, flavor)?;
    let snapshot = SourceSnapshot::capture(ctx, "threat-model:build", build.workspace_root())?;
    anyhow::ensure!(
        scope.source["treeHash"] == snapshot.hashes().1,
        "Accepted group source changed before context collection"
    );
    let output = snapshot.bind_result(generate_bound(
        &input, &build, &scope, &snapshot, ctx, runtime,
    ))?;
    Ok(snapshot.finish(ctx, "threat-model:build", build.workspace_root(), output))
}

fn generate_bound(
    input: &Value,
    build: &BuildInput,
    scope: &ContextSource,
    snapshot: &SourceSnapshot,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
) -> Result<Value> {
    let source = scope.collect(build, ctx)?;
    let inherited = inherited_document(input, ctx)?;
    snapshot.ensure_current(ctx, "threat-model:build", build.workspace_root())?;
    let generated = synthesis::request(
        input,
        build,
        scope,
        &source,
        inherited.as_ref(),
        ctx,
        runtime,
    )?;
    publication::publish(input, build, scope, snapshot, generated, ctx)
}

fn inherited_document(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Option<Value>> {
    let Some(value) = input
        .get("inheritedContextRef")
        .filter(|value| !value.is_null())
    else {
        return Ok(None);
    };
    let reference: ThreatModelRef =
        serde_json::from_value(value.clone()).context("Invalid inheritedContextRef")?;
    let root = ctx
        .workspace
        .context("File-group context needs a repository")?
        .root();
    load_exact_threat_model(root, &reference).map(Some)
}
