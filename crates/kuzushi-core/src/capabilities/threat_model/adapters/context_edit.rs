use super::*;

pub(crate) fn revise_context_adapter(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let root = workspace_root(ctx, "threat-model:revise")?;
    require_selected_context_target(root, &input, ctx)?;
    let reference = edit_reference(&input)?;
    let document = load_exact_threat_model(root, &reference)?;
    let edits: Vec<ContextTextEdit> = serde_json::from_value(input["edits"].clone())
        .context("edits must be context text edits")?;
    let mut revised = apply_context_operator_edits(&document, &edits)?;
    stamp_operator_context(&mut revised, &reference, &edits)?;
    let request = edit_commit_request(root, &reference, input.get("label"))?;
    let committed = ctx.with_cancellation(|cancel| {
        commit_threat_model_revision_cancellable(root, &revised, request, &|| cancel.is_cancelled())
    })?;
    Ok(crate::module_result::completed_output_result(
        "Saved an immutable edited copy. Inspect it before selecting it for work.",
        "Saved an immutable edited copy. Inspect it before selecting it for work.",
        json!({"target":root,"sourceModelRef":reference,"modelRef":committed.model_ref,"document":revised,"activated":false,"editCount":edits.len()}),
    ))
}

pub(super) fn require_selected_context_target(
    root: &Path,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let target = resolve_target(input, ctx)?
        .canonicalize()
        .context("Context target is unavailable")?;
    anyhow::ensure!(
        target == root.canonicalize()?,
        "Context actions use the selected workspace; select the requested target first"
    );
    Ok(())
}

pub(super) fn edit_reference(input: &Value) -> Result<ThreatModelRef> {
    match ThreatModelSelection::from_input(input)? {
        ThreatModelSelection::Revision(reference) => Ok(reference),
        _ => anyhow::bail!("Select an exact threatModelRef before editing context"),
    }
}

fn stamp_operator_context(
    document: &mut Value,
    reference: &ThreatModelRef,
    edits: &[ContextTextEdit],
) -> Result<()> {
    let object = document
        .as_object_mut()
        .context("Context document is not an object")?;
    object.remove("verification");
    object.insert("userEdited".into(), json!(true));
    let provenance = object
        .entry("provenance")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("Context provenance is not an object")?;
    provenance.insert("operatorEdit".into(), json!({"sourceModelRef":reference,"fields":edits.iter().map(|edit| &edit.pointer).collect::<Vec<_>>(),"actor":"operator"}));
    Ok(())
}

pub(super) fn edit_commit_request(
    root: &Path,
    reference: &ThreatModelRef,
    label: Option<&Value>,
) -> Result<ThreatModelCommit> {
    let manifest = load_threat_model_manifest(root)?.context("Context catalog is missing")?;
    let model = manifest
        .models
        .iter()
        .find(|model| model.model_id == reference.model_id)
        .context("Context lineage is missing")?;
    let revision = model
        .revisions
        .iter()
        .find(|revision| revision.revision_id == reference.revision_id)
        .context("Context revision is missing")?;
    let label = edited_copy_label(label, &model.label)?;
    Ok(ThreatModelCommit {
        model_id: None,
        new_model: true,
        label,
        scope: revision.scope.as_ref().unwrap_or(&model.scope).clone(),
        methodology: model.methodology.clone(),
        source: ThreatModelRevisionSource::OperatorEdit,
        source_revision_id: Some(reference.revision_id.clone()),
        run_id: None,
        activate: Some(false),
        actor: "tool:threat-model:revise".into(),
    })
}

fn edited_copy_label(value: Option<&Value>, original: &str) -> Result<String> {
    let label = value
        .map(|value| value.as_str().context("label must be text"))
        .transpose()?
        .map(str::trim)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{original} · edited"));
    anyhow::ensure!(
        !label.is_empty() && label.len() <= 2048,
        "Edited context label must contain 1 to 2048 bytes"
    );
    Ok(label)
}

#[cfg(test)]
mod tests;
