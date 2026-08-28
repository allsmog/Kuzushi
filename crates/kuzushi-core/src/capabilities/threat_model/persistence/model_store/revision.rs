use super::*;

pub(super) fn select_commit_model(
    manifest: &mut ThreatModelManifest,
    request: &ThreatModelCommit,
) -> Result<(usize, ThreatModelId)> {
    anyhow::ensure!(
        !(request.new_model && request.model_id.is_some()),
        "modelId and newModel=true are mutually exclusive"
    );
    if let Some(model_id) = &request.model_id {
        let index = manifest
            .models
            .iter()
            .position(|model| &model.model_id == model_id)
            .with_context(|| format!("threat model {} was not found", model_id.as_str()))?;
        ensure_lineage_category(&manifest.models[index], request)?;
        return Ok((index, model_id.clone()));
    }
    let matches = matching_models(manifest, request);
    anyhow::ensure!(
        request.new_model || matches.is_empty(),
        "a threat-model lineage already exists for this scope and methodology; select modelId or set newModel=true"
    );
    let model_id = ThreatModelId::new();
    manifest.models.push(ThreatModelMetadata {
        model_id: model_id.clone(),
        label: normalized_label(&request.label, &request.methodology),
        scope: request.scope.clone(),
        methodology: request.methodology.clone(),
        created_at: now_string(),
        head_revision: ThreatModelRevisionId::new(),
        revisions: Vec::new(),
    });
    Ok((manifest.models.len() - 1, model_id))
}

pub(super) fn ensure_lineage_category(
    model: &ThreatModelMetadata,
    request: &ThreatModelCommit,
) -> Result<()> {
    anyhow::ensure!(
        model.methodology == request.methodology
            && model.scope.same_lineage_category(&request.scope),
        "selected threat-model lineage does not match the requested scope and methodology"
    );
    Ok(())
}

pub(super) fn matching_models(
    manifest: &ThreatModelManifest,
    request: &ThreatModelCommit,
) -> Vec<usize> {
    manifest
        .models
        .iter()
        .enumerate()
        .filter(|(_, model)| {
            model.methodology == request.methodology
                && model.scope.same_lineage_category(&request.scope)
        })
        .map(|(index, _)| index)
        .collect()
}

pub(super) fn normalized_label(label: &str, methodology: &str) -> String {
    let label = label.trim();
    if label.is_empty() {
        format!("{} threat model", methodology.to_ascii_uppercase())
    } else {
        label.to_string()
    }
}

pub(super) fn revision_metadata(
    document: &Value,
    revision_id: ThreatModelRevisionId,
    sha256: &str,
    parent_revision_id: Option<ThreatModelRevisionId>,
    request: &ThreatModelCommit,
) -> ThreatModelRevisionMetadata {
    ThreatModelRevisionMetadata {
        revision_id,
        sha256: sha256.to_string(),
        created_at: now_string(),
        parent_revision_id,
        source_revision_id: request.source_revision_id.clone(),
        source: request.source.clone(),
        run_id: request.run_id.clone(),
        verification: verification_cache(document, sha256),
        scope: Some(request.scope.clone()),
    }
}

pub(super) fn append_requested_revision(
    manifest: &mut ThreatModelManifest,
    document: &Value,
    sha256: &str,
    request: &ThreatModelCommit,
) -> Result<ThreatModelRef> {
    let (model_index, model_id) = select_commit_model(manifest, request)?;
    let revision_id = ThreatModelRevisionId::new();
    let parent = manifest.models[model_index]
        .revisions
        .last()
        .map(|row| row.revision_id.clone());
    let revision = revision_metadata(document, revision_id.clone(), sha256, parent, request);
    manifest.models[model_index].revisions.push(revision);
    manifest.models[model_index].head_revision = revision_id.clone();
    manifest.models[model_index].scope.target_revision = request.scope.target_revision.clone();
    Ok(ThreatModelRef {
        model_id,
        revision_id,
        sha256: sha256.to_string(),
    })
}

pub(super) fn verification_cache(
    document: &Value,
    sha256: &str,
) -> Option<ThreatModelVerificationCache> {
    document
        .pointer("/verification/verdict")
        .and_then(Value::as_str)
        .map(|verdict| ThreatModelVerificationCache {
            verdict: verdict.to_string(),
            document_sha256: sha256.to_string(),
        })
}

pub(super) fn should_activate_revision(
    manifest: &ThreatModelManifest,
    model_ref: &ThreatModelRef,
    requested: Option<bool>,
) -> bool {
    requested.unwrap_or_else(|| {
        manifest.active.is_none()
            || manifest
                .active
                .as_ref()
                .is_some_and(|active| active.model_id == model_ref.model_id)
    })
}

pub(super) fn activation_source(source: &ThreatModelRevisionSource) -> ActivationSource {
    match source {
        ThreatModelRevisionSource::Build => ActivationSource::Build,
        ThreatModelRevisionSource::Refine => ActivationSource::Refine,
        ThreatModelRevisionSource::Verify => ActivationSource::Verify,
        ThreatModelRevisionSource::Import => ActivationSource::Import,
        ThreatModelRevisionSource::Restore => ActivationSource::Restore,
        ThreatModelRevisionSource::Adopt => ActivationSource::Adopt,
        ThreatModelRevisionSource::OperatorEdit => ActivationSource::OperatorEdit,
        ThreatModelRevisionSource::LegacyImport => ActivationSource::LegacyImport,
    }
}

pub(super) fn resolve_manifest_ref(
    manifest: &ThreatModelManifest,
    model_id: &ThreatModelId,
    revision_id: Option<&ThreatModelRevisionId>,
) -> Result<ThreatModelRef> {
    let model = manifest
        .models
        .iter()
        .find(|model| &model.model_id == model_id)
        .with_context(|| format!("threat model {} was not found", model_id.as_str()))?;
    ref_for_revision(model, revision_id.unwrap_or(&model.head_revision))
}

pub(super) fn find_revision_owner<'a>(
    manifest: &'a ThreatModelManifest,
    revision_id: &ThreatModelRevisionId,
) -> Result<(&'a ThreatModelMetadata, &'a ThreatModelRevisionMetadata)> {
    manifest
        .models
        .iter()
        .find_map(|model| {
            model
                .revisions
                .iter()
                .find(|revision| &revision.revision_id == revision_id)
                .map(|revision| (model, revision))
        })
        .with_context(|| format!("threat-model revision {revision_id} was not found"))
}

pub(super) fn commit_request_for_restore(
    model: &ThreatModelMetadata,
    revision_id: &ThreatModelRevisionId,
    actor: &str,
) -> ThreatModelCommit {
    ThreatModelCommit {
        model_id: Some(model.model_id.clone()),
        new_model: false,
        label: model.label.clone(),
        scope: model.scope.clone(),
        methodology: model.methodology.clone(),
        source: ThreatModelRevisionSource::Restore,
        source_revision_id: Some(revision_id.clone()),
        run_id: None,
        activate: Some(true),
        actor: actor.to_string(),
    }
}

pub(super) fn ref_for_revision(
    model: &ThreatModelMetadata,
    revision_id: &ThreatModelRevisionId,
) -> Result<ThreatModelRef> {
    let revision = model
        .revisions
        .iter()
        .find(|revision| &revision.revision_id == revision_id)
        .with_context(|| {
            format!(
                "threat-model revision {} was not found",
                revision_id.as_str()
            )
        })?;
    Ok(ThreatModelRef {
        model_id: model.model_id.clone(),
        revision_id: revision.revision_id.clone(),
        sha256: revision.sha256.clone(),
    })
}

pub(super) fn document_sha256(document: &Value) -> Result<String> {
    let bytes = crate::review_yield::domain::canonical_json_bytes(document)?;
    Ok(crate::run_lifecycle::sha256_content_digest(&bytes))
}

pub(super) fn now_string() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}
