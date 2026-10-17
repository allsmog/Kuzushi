use super::*;
use crate::workspace::source_snapshot::SourceSnapshot;

pub(super) fn verify_exact_context(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = workspace_root(ctx, "threat-model:verify")?;
    context_edit::require_selected_context_target(root, &input, ctx)?;
    anyhow::ensure!(
        input.get("scope").is_none_or(Value::is_null),
        "Exact context checks inherit the revision scope; omit scope"
    );
    let reference = exact_reference(&input)?;
    let document = load_exact_threat_model(root, &reference)?;
    let request = checked_revision_request(root, &reference, ctx.run_id())?;
    let source_scope = request.scope.clone();
    let snapshot = SourceSnapshot::capture(ctx, "threat-model:verify", root)?;
    let output = snapshot.bind_result(check_and_save(
        &input, ctx, root, &reference, document, request, &snapshot,
    ))?;
    Ok(finish_exact_check(
        snapshot,
        ctx,
        root,
        output,
        &source_scope,
    ))
}

fn finish_exact_check(
    snapshot: SourceSnapshot,
    ctx: &ToolExecutionContext<'_>,
    root: &Path,
    output: Value,
    source_scope: &ScopeRef,
) -> Value {
    finish_revision_output(
        snapshot,
        ctx,
        root,
        output,
        source_scope,
        "threat-model:verify",
    )
}

pub(super) fn finish_revision_output(
    snapshot: SourceSnapshot,
    ctx: &ToolExecutionContext<'_>,
    root: &Path,
    output: Value,
    source_scope: &ScopeRef,
    tool: &str,
) -> Value {
    let recorded_tree = snapshot.hashes().1.to_owned();
    let mut output = snapshot.finish(ctx, tool, root, output);
    if let Err(error) = require_recorded_source(
        &output["data"]["document"],
        source_scope,
        root,
        &recorded_tree,
    ) {
        crate::workspace::source_snapshot::mark_source_unverified(&mut output, &error);
    }
    output
}

pub(super) fn exact_reference(input: &Value) -> Result<ThreatModelRef> {
    match ThreatModelSelection::from_input(input)? {
        ThreatModelSelection::Revision(reference) => Ok(reference),
        _ => anyhow::bail!("Select a non-null exact threatModelRef before checking context"),
    }
}

fn check_and_save(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    root: &Path,
    reference: &ThreatModelRef,
    document: Value,
    request: ThreatModelCommit,
    snapshot: &SourceSnapshot,
) -> Result<Value> {
    require_recorded_source(&document, &request.scope, root, snapshot.hashes().1)?;
    let roots = recorded_roots(root, &request.scope)?;
    let verification = verify_threat_model_document_with_roots(&document, &roots)?;
    let mut checked = document;
    stamp_verification(&mut checked, &verification);
    snapshot.ensure_current(ctx, "threat-model:verify", root)?;
    let write = input.get("write").and_then(Value::as_bool).unwrap_or(true);
    let written = save_checked_revision(root, &checked, request, write, ctx, snapshot)?;
    Ok(checked_result(
        root,
        reference,
        written,
        checked,
        verification,
    ))
}

pub(super) fn require_recorded_source(
    document: &Value,
    scope: &ScopeRef,
    root: &Path,
    current_tree: &str,
) -> Result<()> {
    let recorded_tree = document.pointer("/provenance/treeHash").and_then(Value::as_str)
        .context("Exact context check needs recorded provenance treeHash; this historical context cannot be authenticated")?;
    anyhow::ensure!(recorded_tree == current_tree, "Context source content changed. Keep this historical revision or generate context for the current source.");
    let current = crate::workspace::target_git_metadata(root);
    let revision = current
        .as_ref()
        .map(|git| git.sha.as_str())
        .unwrap_or("unavailable");
    anyhow::ensure!(scope.target_revision == revision, "Context source revision changed. This check cannot rebind historical context to the current SHA.");
    require_document_git_identity(document, current.as_ref())
}

fn require_document_git_identity(
    document: &Value,
    current: Option<&crate::run_artifacts::RunTargetGitMetadata>,
) -> Result<()> {
    let revision = document
        .pointer("/provenance/revision")
        .and_then(Value::as_str);
    let dirty = document
        .pointer("/provenance/revisionDirty")
        .and_then(Value::as_bool);
    if let Some(revision) = revision {
        anyhow::ensure!(
            Some(revision) == current.map(|git| git.sha.as_str()),
            "Context documented SHA changed"
        );
    }
    if let Some(dirty) = dirty {
        anyhow::ensure!(
            Some(dirty) == current.map(|git| git.dirty),
            "Context source dirty state changed"
        );
    }
    Ok(())
}

pub(super) fn recorded_roots(root: &Path, scope: &ScopeRef) -> Result<ThreatModelBuildRoots> {
    let analysis_root = canonical_analysis_root(root, &scope.rel_path)?;
    Ok(ThreatModelBuildRoots {
        workspace_root: root.into(),
        analysis_root,
        scope: (scope.rel_path != Path::new(".")).then(|| scope.clone()),
    })
}

pub(super) fn checked_revision_request(
    root: &Path,
    reference: &ThreatModelRef,
    run_id: Option<String>,
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
    Ok(ThreatModelCommit {
        model_id: Some(model.model_id.clone()),
        new_model: false,
        label: model.label.clone(),
        scope: revision.scope.as_ref().unwrap_or(&model.scope).clone(),
        methodology: model.methodology.clone(),
        source: ThreatModelRevisionSource::Verify,
        source_revision_id: Some(reference.revision_id.clone()),
        run_id,
        activate: Some(false),
        actor: "tool:threat-model:verify".into(),
    })
}

fn save_checked_revision(
    root: &Path,
    document: &Value,
    request: ThreatModelCommit,
    write: bool,
    ctx: &ToolExecutionContext<'_>,
    snapshot: &SourceSnapshot,
) -> Result<Option<ThreatModelRef>> {
    if !write {
        return Ok(None);
    }
    let scope = request.scope.clone();
    ctx.with_cancellation(|cancel| {
        commit_checked_threat_model_revision(
            root,
            document,
            request,
            &|| cancel.is_cancelled(),
            &|| {
                snapshot.ensure_current(ctx, "threat-model:verify", root)?;
                require_recorded_source(document, &scope, root, snapshot.hashes().1)
            },
        )
    })
    .map(|committed| Some(committed.model_ref))
}

fn checked_result(
    root: &Path,
    source: &ThreatModelRef,
    written: Option<ThreatModelRef>,
    document: Value,
    verification: ThreatModelVerification,
) -> Value {
    let summary = format!("Context source check: {}. Citations, links and bounded coverage checked; review the details before using this revision.", verification.verdict);
    crate::module_result::completed_output_result(
        summary.clone(),
        summary,
        json!({
            "resolvedFrom":"exact-verification", "target":root, "sourceModelRef":source,
            "written":written.is_some(), "modelRef":written, "document":document,
            "verification":verification, "activated":false,
        }),
    )
}

#[cfg(test)]
mod tests;
