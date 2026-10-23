use super::*;
use synthesis::Generated;

pub(super) fn publish(
    input: &Value,
    build: &BuildInput,
    scope: &ContextSource,
    snapshot: &SourceSnapshot,
    mut generated: Generated,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    stamp_document(
        &mut generated.document,
        &generated.receipt,
        build,
        snapshot,
        scope.provenance_key(),
    )?;
    stamp_operator_intent(&mut generated.document, build)?;
    let root = build.workspace_root();
    let mut commit = scope.commit.clone();
    commit.methodology = build.methodology.clone();
    let committed = ctx.with_cancellation(|cancel| {
        commit_checked_threat_model_revision(
            root,
            &generated.document,
            commit,
            &|| cancel.is_cancelled(),
            &|| snapshot.ensure_current(ctx, "threat-model:build", root),
        )
    })?;
    Ok(output(input, build, scope, generated, committed.model_ref))
}

fn output(
    input: &Value,
    build: &BuildInput,
    scope: &ContextSource,
    generated: Generated,
    model_ref: ThreatModelRef,
) -> Value {
    let mut data = json!({"target":build.workspace_root(),"modelRef":model_ref,"document":generated.document,"activated":false,
        "inheritedContextRef":input["inheritedContextRef"],
        "costUsd":generated.cost.is_complete().then(||generated.cost.observed_usd()),"costUsdExact":generated.cost.is_complete()});
    data[scope.provenance_key()] = generated.receipt;
    crate::module_result::completed_output_result(
        "Saved an inactive file-group context draft. Inspect its source, omissions and inherited architecture before selecting it for a boundary.",
        "Saved an inactive file-group context draft. No discovery jobs or global context changes were made.",
        data,
    )
}

fn stamp_document(
    document: &mut Value,
    receipt: &Value,
    build: &BuildInput,
    snapshot: &SourceSnapshot,
    provenance_key: &str,
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
    provenance.remove("scopeContext");
    provenance.remove("fileContext");
    provenance.insert(provenance_key.into(), json!({"receipt":receipt}));
    Ok(())
}
