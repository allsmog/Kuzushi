use super::*;

pub(crate) fn list_threat_models_adapter(ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = workspace_root(ctx, "threat-model:models")?;
    let manifest = load_threat_model_manifest(root)?;
    let legacy_mirror = persistent_threat_model_path(root).is_file() && manifest.is_none();
    let (generation, active, models) = match manifest {
        Some(manifest) => (manifest.generation, manifest.active, manifest.models),
        None => (0, None, Vec::new()),
    };
    completed_command(
        format!("{} threat-model lineage(s)", models.len()),
        json!({
            "generation": generation,
            "active": active,
            "models": models,
            "legacyMirrorRequiresWritableMigration": legacy_mirror,
        }),
    )
}

pub(crate) fn activate_threat_model_adapter(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let root = workspace_root(ctx, "threat-model:activate")?;
    let model_id = required_model_id(&input)?;
    let revision_id = optional_revision_id(&input)?;
    let mirror_action = if input.get("force").and_then(Value::as_bool).unwrap_or(false) {
        MirrorAction::Discard
    } else {
        MirrorAction::Refuse
    };
    let model_ref = activate_threat_model(
        root,
        &model_id,
        revision_id.as_ref(),
        "tool:threat-model:activate",
        mirror_action,
    )?;
    let summary = format!(
        "activated {}@{}",
        model_ref.model_id, model_ref.revision_id
    );
    completed_command(summary, json!({"modelRef": model_ref}))
}

pub(crate) fn list_threat_model_revisions_adapter(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let root = workspace_root(ctx, "threat-model:revisions")?;
    let model_id = required_model_id(&input)?;
    let revisions = list_model_revisions(root, &model_id)?;
    completed_command(
        format!("{} revision(s) for {model_id}", revisions.len()),
        json!({"modelId": model_id, "revisions": revisions}),
    )
}

pub(crate) fn restore_threat_model_revision_adapter(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let root = workspace_root(ctx, "threat-model:restore")?;
    let revision_id = required_revision_id(&input)?;
    let committed = restore_threat_model_revision(
        root,
        &revision_id,
        "tool:threat-model:restore",
    )?;
    completed_command(
        format!("restored {revision_id} as {}", committed.model_ref.revision_id),
        json!({"modelRef": committed.model_ref, "sourceRevisionId": revision_id}),
    )
}

pub(crate) fn adopt_threat_model_mirror_adapter(
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let root = workspace_root(ctx, "threat-model:adopt")?;
    if load_threat_model_manifest(root)?.is_none() {
        let manifest = open_writable_threat_model_store(root)?;
        let model_ref = manifest.active.context("compatibility mirror is missing")?;
        return completed_command(
            "imported legacy compatibility mirror".to_string(),
            json!({"modelRef": model_ref, "source": "legacy-import"}),
        );
    }
    let committed = adopt_threat_model_mirror_edits(root, "tool:threat-model:adopt")?;
    completed_command(
        format!("adopted mirror edits as {}", committed.model_ref.revision_id),
        json!({"modelRef": committed.model_ref, "source": "adopt"}),
    )
}

pub(super) fn workspace_root<'a>(
    ctx: &'a ToolExecutionContext<'_>,
    tool: &str,
) -> Result<&'a Path> {
    ctx.workspace
        .map(|workspace| workspace.root())
        .context(crate::workspace::active_workspace_required_message(tool))
}

fn required_model_id(input: &Value) -> Result<ThreatModelId> {
    let value = input
        .get("modelId")
        .and_then(Value::as_str)
        .context("modelId is required")?;
    ThreatModelId::parse(value)
}

fn optional_revision_id(input: &Value) -> Result<Option<ThreatModelRevisionId>> {
    input
        .get("revisionId")
        .and_then(Value::as_str)
        .map(ThreatModelRevisionId::parse)
        .transpose()
}

fn required_revision_id(input: &Value) -> Result<ThreatModelRevisionId> {
    optional_revision_id(input)?.context("revisionId is required")
}

fn completed_command(summary: String, data: Value) -> Result<Value> {
    Ok(crate::module_result::completed_output_result(
        summary.clone(),
        summary,
        data,
    ))
}
