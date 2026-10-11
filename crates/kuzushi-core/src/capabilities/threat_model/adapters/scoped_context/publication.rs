use super::*;
use synthesis::Generated;

pub(super) fn publish(
    input: &Value,
    build: &BuildInput,
    scope: &AcceptedScanScopeSelection,
    snapshot: &SourceSnapshot,
    mut generated: Generated,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    stamp_document(&mut generated.document, &generated.receipt, build, snapshot)?;
    stamp_operator_intent(&mut generated.document, build)?;
    let root = build.workspace_root();
    let commit = commit_request(build, scope, ctx);
    let committed = ctx.with_cancellation(|cancel| {
        commit_checked_threat_model_revision(
            root,
            &generated.document,
            commit,
            &|| cancel.is_cancelled(),
            &|| snapshot.ensure_current(ctx, "threat-model:build", root),
        )
    })?;
    Ok(crate::module_result::completed_output_result(
        "Saved an inactive file-group context draft. Inspect its source, omissions and inherited architecture before selecting it for a boundary.",
        "Saved an inactive file-group context draft. No discovery jobs or global context changes were made.",
        json!({"target":root,"modelRef":committed.model_ref,"document":generated.document,"activated":false,
            "scopeContext":generated.receipt,"inheritedContextRef":input["inheritedContextRef"],
            "costUsd":generated.cost.is_complete().then(||generated.cost.observed_usd()),"costUsdExact":generated.cost.is_complete()}),
    ))
}

fn stamp_document(
    document: &mut Value,
    receipt: &Value,
    build: &BuildInput,
    snapshot: &SourceSnapshot,
) -> Result<()> {
    let root = document
        .as_object_mut()
        .context("Generated context must be an object")?;
    root.insert("treeHash".into(), json!(snapshot.hashes().1));
    root.insert(
        "targetGit".into(),
        json!(crate::workspace::target_git_metadata(
            build.workspace_root()
        )),
    );
    root.remove("verification");
    let provenance = root.entry("provenance").or_insert_with(|| json!({}));
    let provenance = provenance
        .as_object_mut()
        .context("Generated context provenance must be an object")?;
    provenance.insert("treeHash".into(), json!(snapshot.hashes().1));
    provenance.insert(
        "targetGit".into(),
        json!(crate::workspace::target_git_metadata(
            build.workspace_root()
        )),
    );
    provenance.insert("scopeContext".into(), json!({"receipt":receipt}));
    Ok(())
}

fn commit_request(
    build: &BuildInput,
    scope: &AcceptedScanScopeSelection,
    ctx: &ToolExecutionContext<'_>,
) -> ThreatModelCommit {
    ThreatModelCommit {
        model_id: None,
        new_model: true,
        label: format!("{} · context draft", scope.name),
        scope: ScopeRef {
            scope_id: format!("scan-group:{}", scope.reference.scope_id),
            rel_path: PathBuf::from("."),
            project_model_sha256: scope.reference.proposal.record_hash.clone(),
            target_revision: scope
                .source
                .git_revision
                .clone()
                .unwrap_or_else(|| "unavailable".into()),
        },
        methodology: build.methodology.clone(),
        source: ThreatModelRevisionSource::Build,
        source_revision_id: None,
        run_id: ctx.run_id(),
        activate: Some(false),
        actor: "tool:threat-model:build".into(),
    }
}
