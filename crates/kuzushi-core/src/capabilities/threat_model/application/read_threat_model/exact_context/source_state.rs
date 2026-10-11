use super::*;

pub(super) fn inspect_source_state(
    root: &Path,
    reference: &ThreatModelRef,
    document: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Value {
    match compare_source(root, reference, document, ctx) {
        Ok((status, message)) => json!({"schemaVersion":1,"status":status,"message":message}),
        Err(error) => {
            json!({"schemaVersion":1,"status":"unknown","message":format!("Source identity unavailable at inspection: {error}. Treat the recorded check as historical.")})
        }
    }
}

fn compare_source(
    root: &Path,
    reference: &ThreatModelRef,
    document: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<(&'static str, String)> {
    let recorded = recorded_revision(root, reference)?;
    let metadata = crate::workspace::target_git_metadata(root);
    anyhow::ensure!(
        recorded == "unavailable" || metadata.is_some(),
        "repository revision is unavailable"
    );
    let current = metadata
        .as_ref()
        .map(|git| git.sha.as_str())
        .unwrap_or("unavailable");
    if recorded != current {
        return Ok(("drifted", format!("Source drift at inspection: SHA changed. Recorded {recorded}; current {current}. This context is historical.")));
    }
    let hash = document
        .pointer("/provenance/treeHash")
        .and_then(Value::as_str)
        .context("this context has no recorded content hash")?;
    let current_hash = crate::workspace::source_snapshot::inspect_current_source_hash(
        ctx,
        "threat-model:read",
        root,
    )?;
    Ok(inspected_tree_state(
        document,
        metadata.as_ref().map(|git| git.dirty),
        hash == current_hash,
    ))
}

fn inspected_tree_state(
    document: &Value,
    dirty: Option<bool>,
    matches: bool,
) -> (&'static str, String) {
    if !matches {
        return content_state(false);
    }
    if dirty_state_changed(document, dirty) {
        return ("drifted", "Source drift at inspection: repository dirty state changed. Treat this context as historical.".into());
    }
    content_state(true)
}

fn dirty_state_changed(document: &Value, current: Option<bool>) -> bool {
    document
        .pointer("/provenance/revisionDirty")
        .and_then(Value::as_bool)
        .is_some_and(|recorded| Some(recorded) != current)
}

fn recorded_revision(root: &Path, reference: &ThreatModelRef) -> Result<String> {
    let manifest = load_threat_model_manifest(root)?.context("Context catalog is unavailable")?;
    let model = manifest
        .models
        .iter()
        .find(|model| model.model_id == reference.model_id)
        .context("Context lineage is absent")?;
    let revision = model
        .revisions
        .iter()
        .find(|revision| revision.revision_id == reference.revision_id)
        .context("Context revision is absent")?;
    Ok(revision
        .scope
        .as_ref()
        .unwrap_or(&model.scope)
        .target_revision
        .clone())
}

fn content_state(matches: bool) -> (&'static str, String) {
    if matches {
        ("matches", "Source identity matched at inspection. This does not validate the context's claims or finding verdicts.".into())
    } else {
        ("drifted", "Source drift at inspection: content changed. This context is historical, even if its SHA is unchanged.".into())
    }
}
