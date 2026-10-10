use super::*;

pub(super) fn adopt_mirror_locked(
    root: &Path,
    manifest: &mut ThreatModelManifest,
    actor: &str,
) -> Result<ThreatModelCommitResult> {
    let active = manifest
        .active
        .clone()
        .context("no active threat model to adopt into")?;
    let document = super::super::store::try_load_legacy_threat_model(root)?
        .context("compatibility mirror is missing; there are no edits to adopt")?;
    let model = manifest
        .models
        .iter()
        .find(|model| model.model_id == active.model_id)
        .context("active threat-model lineage is absent from manifest")?;
    validate_persisted_threat_model(&document, &model.methodology)?;
    let observed_mirror_sha256 = document_sha256(&document)?;
    let document = reviewed_adoption_document(document, &active.sha256)?;
    let object = write_object(root, &document)?;
    append_adopted_revision(
        manifest,
        &active,
        &object.sha256,
        &document,
        actor,
        root,
        &observed_mirror_sha256,
    )
}

fn reviewed_adoption_document(mut document: Value, active_sha256: &str) -> Result<Value> {
    anyhow::ensure!(
        document_sha256(&document)? != active_sha256,
        "compatibility mirror already matches the active threat model"
    );
    let object = document
        .as_object_mut()
        .context("adopted context is not an object")?;
    object.remove("verification");
    object.insert("userEdited".into(), serde_json::json!(true));
    Ok(document)
}

fn append_adopted_revision(
    manifest: &mut ThreatModelManifest,
    active: &ThreatModelRef,
    sha256: &str,
    document: &Value,
    actor: &str,
    root: &Path,
    observed_mirror_sha256: &str,
) -> Result<ThreatModelCommitResult> {
    let model_ref = append_adopted_model_revision(manifest, active, sha256, document, actor)?;
    commit_manifest_update_with_observed(
        root,
        manifest.clone(),
        Some(model_ref.clone()),
        actor,
        ActivationSource::Adopt,
        None,
        Some(observed_mirror_sha256),
    )?;
    Ok(ThreatModelCommitResult {
        model_ref,
        activated: true,
    })
}

fn append_adopted_model_revision(
    manifest: &mut ThreatModelManifest,
    active: &ThreatModelRef,
    sha256: &str,
    document: &Value,
    actor: &str,
) -> Result<ThreatModelRef> {
    let model = manifest
        .models
        .iter_mut()
        .find(|model| model.model_id == active.model_id)
        .context("active threat-model lineage is absent from manifest")?;
    let revision_id = ThreatModelRevisionId::new();
    let request = adopt_commit_request(model, active, actor);
    let parent = Some(model.head_revision.clone());
    let revision = revision_metadata(document, revision_id.clone(), sha256, parent, &request);
    model.revisions.push(revision);
    model.head_revision = revision_id.clone();
    Ok(ThreatModelRef {
        model_id: model.model_id.clone(),
        revision_id,
        sha256: sha256.to_string(),
    })
}

fn adopt_commit_request(
    model: &ThreatModelMetadata,
    active: &ThreatModelRef,
    actor: &str,
) -> ThreatModelCommit {
    ThreatModelCommit {
        model_id: Some(model.model_id.clone()),
        new_model: false,
        label: model.label.clone(),
        scope: model.scope.clone(),
        methodology: model.methodology.clone(),
        source: ThreatModelRevisionSource::Adopt,
        source_revision_id: Some(active.revision_id.clone()),
        run_id: None,
        activate: Some(true),
        actor: actor.to_string(),
    }
}
