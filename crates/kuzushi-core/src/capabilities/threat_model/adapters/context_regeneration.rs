use super::*;
use crate::workspace::source_snapshot::SourceSnapshot;
mod synthesis;
#[cfg(test)]
mod tests;

pub(crate) fn regenerate_context_adapter(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let runtime = runtime.context("Context regeneration requires the selected model runtime")?;
    let root = workspace_root(ctx, "threat-model:regenerate")?;
    context_edit::require_selected_context_target(root, &input, ctx)?;
    anyhow::ensure!(
        ctx.run_id().is_some(),
        "Context regeneration requires a durable run identity"
    );
    let base = prepare_regeneration(root, &input, ctx)?;
    let snapshot = SourceSnapshot::capture(ctx, "threat-model:regenerate", root)?;
    exact_verification::require_recorded_source(
        &base.document,
        &base.commit.scope,
        root,
        snapshot.hashes().1,
    )?;
    let scope = base.commit.scope.clone();
    let result = snapshot.bind_result(regenerate_bound_context(
        root, &input, base, ctx, runtime, &snapshot,
    ))?;
    let mut result = exact_verification::finish_revision_output(
        snapshot,
        ctx,
        root,
        result,
        &scope,
        "threat-model:regenerate",
    );
    result["data"]["sourceCurrent"] = json!(result["status"] != "partial");
    Ok(result)
}

struct RegenerationBase {
    reference: ThreatModelRef,
    document: Value,
    fields: Vec<ContextTextField>,
    commit: ThreatModelCommit,
}

pub(crate) fn validate_context_regeneration_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let root = workspace_root(ctx, "threat-model:regenerate")?;
    context_edit::require_selected_context_target(root, input, ctx)?;
    let base = prepare_regeneration(root, input, ctx)?;
    let current = crate::workspace::source_snapshot::inspect_current_source_hash(
        ctx,
        "threat-model:regenerate",
        root,
    )?;
    exact_verification::require_recorded_source(&base.document, &base.commit.scope, root, &current)
}

fn prepare_regeneration(
    root: &Path,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<RegenerationBase> {
    let reference = exact_verification::exact_reference(input)?;
    let document = load_exact_threat_model(root, &reference)?;
    let selected: Vec<String> = serde_json::from_value(input["fields"].clone())
        .context("fields must be selected context pointers")?;
    let fields = regeneration_fields(&document, &selected)?;
    anyhow::ensure!(
        input["guidance"].as_str().unwrap_or("").len() <= 2048,
        "Context guidance exceeds 2048 bytes"
    );
    let mut commit = exact_verification::checked_revision_request(root, &reference, ctx.run_id())?;
    commit.model_id = None;
    commit.new_model = true;
    commit.label = format!("{} · regeneration draft", commit.label);
    commit.source = ThreatModelRevisionSource::Build;
    commit.actor = "tool:threat-model:regenerate".into();
    Ok(RegenerationBase {
        reference,
        document,
        fields,
        commit,
    })
}

fn regenerate_bound_context(
    root: &Path,
    input: &Value,
    base: RegenerationBase,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    snapshot: &SourceSnapshot,
) -> Result<Value> {
    let generated = synthesis::request(input, &base, ctx, runtime)?;
    let selected = base
        .fields
        .iter()
        .map(|field| field.pointer.clone())
        .collect::<Vec<_>>();
    let mut revised = validate_regenerated_text(&base.document, &selected, &generated.response)?;
    stamp_regeneration(&mut revised, &base.reference, &generated.receipt)?;
    let scope = base.commit.scope.clone();
    let committed = ctx.with_cancellation(|cancel| {
        commit_checked_threat_model_revision(
            root,
            &revised,
            base.commit,
            &|| cancel.is_cancelled(),
            &|| {
                snapshot.ensure_current(ctx, "threat-model:regenerate", root)?;
                exact_verification::require_recorded_source(
                    &revised,
                    &scope,
                    root,
                    snapshot.hashes().1,
                )
            },
        )
    })?;
    Ok(crate::module_result::completed_output_result(
        "Saved an inactive regeneration draft. Compare proposed text with its exact parent before selecting it for work.",
        "Saved an inactive regeneration draft. Compare proposed text with its exact parent before selecting it for work.",
        json!({"target":root,"sourceModelRef":base.reference,"modelRef":committed.model_ref,"document":revised,"activated":false,"regeneration":generated.receipt,"edits":generated.response.edits}),
    ))
}

fn stamp_regeneration(
    document: &mut Value,
    reference: &ThreatModelRef,
    receipt: &Value,
) -> Result<()> {
    let object = document
        .as_object_mut()
        .context("Context document is not an object")?;
    object.remove("verification");
    let provenance = object
        .entry("provenance")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("Context provenance is not an object")?;
    provenance.insert(
        "regeneration".into(),
        json!({"schemaVersion":1,"sourceModelRef":reference,"receipt":receipt,"accepted":false}),
    );
    Ok(())
}
