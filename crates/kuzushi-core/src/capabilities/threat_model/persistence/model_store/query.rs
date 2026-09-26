use super::*;

pub fn load_threat_model_manifest(root: &Path) -> Result<Option<ThreatModelManifest>> {
    let Some(manifest) = read_manifest(root)? else {
        return Ok(None);
    };
    validate_manifest(root, &manifest)?;
    Ok(Some(manifest))
}

pub fn load_active_threat_model(root: &Path) -> Result<Option<ActiveThreatModel>> {
    let Some(manifest) = load_threat_model_manifest(root)? else {
        return Ok(None);
    };
    let Some(model_ref) = manifest.active else {
        return Ok(None);
    };
    active_document(root, model_ref).map(Some)
}

fn active_document(root: &Path, model_ref: ThreatModelRef) -> Result<ActiveThreatModel> {
    let document = read_object(root, &model_ref.sha256)?;
    Ok(ActiveThreatModel {
        model_ref,
        document,
    })
}

pub fn load_threat_model_revision(
    root: &Path,
    model_id: &ThreatModelId,
    revision_id: Option<&ThreatModelRevisionId>,
) -> Result<ActiveThreatModel> {
    let manifest = load_threat_model_manifest(root)?.context("threat-model manifest is missing")?;
    let model_ref = resolve_manifest_ref(&manifest, model_id, revision_id)?;
    active_document(root, model_ref)
}

/// Resolves an operator selector to one immutable revision: `tmr_…` names an
/// exact revision and `tm_…` names a lineage, which selects its head revision.
/// Anything else, or an id absent from the manifest, is an explicit error.
pub fn load_threat_model_by_selector(root: &Path, selector: &str) -> Result<ActiveThreatModel> {
    let manifest = load_threat_model_manifest(root)?.context("threat-model manifest is missing")?;
    let model_ref = resolve_selector_ref(&manifest, selector.trim())?;
    active_document(root, model_ref)
}

fn resolve_selector_ref(manifest: &ThreatModelManifest, selector: &str) -> Result<ThreatModelRef> {
    if selector.starts_with("tmr_") {
        return resolve_revision_selector(manifest, selector);
    }
    if selector.starts_with("tm_") {
        return resolve_lineage_selector(manifest, selector);
    }
    anyhow::bail!(
        "{selector:?} is neither a threat-model lineage id (tm_…) nor a revision id (tmr_…)"
    )
}

fn resolve_revision_selector(
    manifest: &ThreatModelManifest,
    selector: &str,
) -> Result<ThreatModelRef> {
    let revision_id = ThreatModelRevisionId::parse(selector)?;
    let (model, _) = find_revision_owner(manifest, &revision_id).with_context(|| {
        format!(
            "looked up as a revision id across {} lineage(s)",
            manifest.models.len()
        )
    })?;
    ref_for_revision(model, &revision_id)
}

fn resolve_lineage_selector(
    manifest: &ThreatModelManifest,
    selector: &str,
) -> Result<ThreatModelRef> {
    let model_id = ThreatModelId::parse(selector)?;
    resolve_manifest_ref(manifest, &model_id, None).with_context(|| {
        format!(
            "looked up as a lineage id (head revision) among {} lineage(s)",
            manifest.models.len()
        )
    })
}

pub fn load_scope_threat_model(root: &Path, scope: &ScopeRef) -> Result<Option<ActiveThreatModel>> {
    let Some(manifest) = load_threat_model_manifest(root)? else {
        return Ok(None);
    };
    let matches = matching_scope_models(&manifest, scope)?;
    if matches.is_empty() {
        return Ok(None);
    }
    let model = select_scope_model(&manifest, matches)?;
    let model_ref = active_ref_for_model(&manifest, model)
        .cloned()
        .unwrap_or(ref_for_revision(model, &model.head_revision)?);
    active_document(root, model_ref).map(Some)
}

fn active_ref_for_model<'a>(
    manifest: &'a ThreatModelManifest,
    model: &ThreatModelMetadata,
) -> Option<&'a ThreatModelRef> {
    manifest
        .active
        .as_ref()
        .filter(|active| active.model_id == model.model_id)
}

/// Resolves the exact lineage a build/refine operation may consume. Ambiguous
/// variants are refused unless the active pointer selects one.
pub fn load_build_threat_model(
    root: &Path,
    scope: &ScopeRef,
    methodology: &str,
    model_id: Option<&ThreatModelId>,
) -> Result<Option<ActiveThreatModel>> {
    let Some(manifest) = load_threat_model_manifest(root)? else {
        return Ok(None);
    };
    let Some(model) = select_build_model(&manifest, scope, methodology, model_id)? else {
        return Ok(None);
    };
    let model_ref = active_ref_for_model(&manifest, model)
        .cloned()
        .unwrap_or(ref_for_revision(model, &model.head_revision)?);
    active_document(root, model_ref).map(Some)
}

/// Selects the one exact lineage an expanded multi-scope rerun may refine.
/// Missing and stale decomposition bindings deliberately resolve to `None`,
/// while same-category variants remain an operator choice and are refused.
pub fn resolve_unique_build_lineage(
    root: &Path,
    scope: &ScopeRef,
    methodology: &str,
) -> Result<Option<ThreatModelId>> {
    let Some(manifest) = load_threat_model_manifest(root)? else {
        return Ok(None);
    };
    unique_build_lineage(&manifest, scope, methodology)
        .map(|model| model.map(|model| model.model_id.clone()))
}

fn unique_build_lineage<'a>(
    manifest: &'a ThreatModelManifest,
    scope: &ScopeRef,
    methodology: &str,
) -> Result<Option<&'a ThreatModelMetadata>> {
    let matches = manifest
        .models
        .iter()
        .filter(|model| {
            model.scope.same_lineage_category(scope) && model.methodology == methodology
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        matches.len() <= 1,
        "multiple threat-model variants match scope {:?} ({}) and methodology {:?}; select modelId explicitly before refining",
        scope.scope_id,
        scope.rel_path.display(),
        methodology,
    );
    Ok(matches.first().copied())
}

fn select_build_model<'a>(
    manifest: &'a ThreatModelManifest,
    scope: &ScopeRef,
    methodology: &str,
    model_id: Option<&ThreatModelId>,
) -> Result<Option<&'a ThreatModelMetadata>> {
    if let Some(model_id) = model_id {
        return explicit_build_model(manifest, scope, methodology, model_id).map(Some);
    }
    let matches = matching_category_models(manifest, scope, methodology)?;
    if matches.is_empty() {
        return Ok(None);
    }
    select_scope_model(manifest, matches).map(Some)
}

fn explicit_build_model<'a>(
    manifest: &'a ThreatModelManifest,
    scope: &ScopeRef,
    methodology: &str,
    model_id: &ThreatModelId,
) -> Result<&'a ThreatModelMetadata> {
    let model = manifest
        .models
        .iter()
        .find(|model| &model.model_id == model_id)
        .with_context(|| format!("threat model {} was not found", model_id.as_str()))?;
    ensure_requested_category(model, scope, methodology)?;
    Ok(model)
}

fn matching_category_models<'a>(
    manifest: &'a ThreatModelManifest,
    scope: &ScopeRef,
    methodology: &str,
) -> Result<Vec<&'a ThreatModelMetadata>> {
    Ok(matching_scope_models(manifest, scope)?
        .into_iter()
        .filter(|model| model.methodology == methodology)
        .collect())
}

fn ensure_requested_category(
    model: &ThreatModelMetadata,
    scope: &ScopeRef,
    methodology: &str,
) -> Result<()> {
    anyhow::ensure!(
        model.scope.same_lineage_category(scope) && model.methodology == methodology,
        "selected threat-model lineage does not match the requested scope and methodology"
    );
    Ok(())
}

fn matching_scope_models<'a>(
    manifest: &'a ThreatModelManifest,
    scope: &ScopeRef,
) -> Result<Vec<&'a ThreatModelMetadata>> {
    let same_identity = manifest
        .models
        .iter()
        .filter(|model| {
            model.scope.scope_id == scope.scope_id && model.scope.rel_path == scope.rel_path
        })
        .collect::<Vec<_>>();
    let exact = same_identity
        .iter()
        .filter(|model| model.scope.same_lineage_category(scope))
        .copied()
        .collect::<Vec<_>>();
    anyhow::ensure!(
        !exact.is_empty() || same_identity.is_empty(),
        "threat-model scope binding is stale; run mode=build with seedMode=fresh to mint a lineage for the current decomposition"
    );
    Ok(exact)
}

fn select_scope_model<'a>(
    manifest: &ThreatModelManifest,
    matches: Vec<&'a ThreatModelMetadata>,
) -> Result<&'a ThreatModelMetadata> {
    if let Some(model) = active_match(manifest, &matches) {
        return Ok(model);
    }
    anyhow::ensure!(
        matches.len() == 1,
        "multiple threat-model variants match this scope; activate one explicitly"
    );
    Ok(matches[0])
}

fn active_match<'a>(
    manifest: &ThreatModelManifest,
    matches: &[&'a ThreatModelMetadata],
) -> Option<&'a ThreatModelMetadata> {
    let active = manifest.active.as_ref()?;
    matches
        .iter()
        .find(|model| model.model_id == active.model_id)
        .copied()
}

#[cfg(test)]
mod unique_lineage_tests {
    use super::*;

    #[test]
    fn unique_lineage_requires_exact_scope_binding_and_methodology() {
        let exact = model(scope("tree-current"), "stride");
        let exact_id = exact.model_id.clone();
        let manifest = ThreatModelManifest {
            models: vec![
                exact,
                model(scope("tree-current"), "pasta"),
                model(scope("tree-stale"), "stride"),
            ],
            ..ThreatModelManifest::default()
        };

        assert_eq!(
            unique_build_lineage(&manifest, &scope("tree-current"), "stride")
                .unwrap()
                .map(|model| model.model_id.clone()),
            Some(exact_id)
        );
        assert!(
            unique_build_lineage(&manifest, &scope("tree-next"), "stride")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn unique_lineage_refuses_variants_even_when_one_is_active() {
        let first = model(scope("tree-current"), "stride");
        let second = model(scope("tree-current"), "stride");
        let manifest = ThreatModelManifest {
            active: Some(ThreatModelRef {
                model_id: first.model_id.clone(),
                revision_id: first.head_revision.clone(),
                sha256: format!("sha256:{}", "1".repeat(64)),
            }),
            models: vec![first, second],
            ..ThreatModelManifest::default()
        };

        let error = unique_build_lineage(&manifest, &scope("tree-current"), "stride")
            .unwrap_err()
            .to_string();

        assert!(error.contains("multiple threat-model variants"), "{error}");
        assert!(error.contains("select modelId explicitly"), "{error}");
    }

    fn scope(project_model_sha256: &str) -> ScopeRef {
        ScopeRef {
            scope_id: "api".to_string(),
            rel_path: PathBuf::from("services/api"),
            project_model_sha256: project_model_sha256.to_string(),
            target_revision: "revision".to_string(),
        }
    }

    fn model(scope: ScopeRef, methodology: &str) -> ThreatModelMetadata {
        ThreatModelMetadata {
            model_id: ThreatModelId::new(),
            label: "API".to_string(),
            scope,
            methodology: methodology.to_string(),
            created_at: "2026-08-27T00:00:00Z".to_string(),
            head_revision: ThreatModelRevisionId::new(),
            revisions: Vec::new(),
        }
    }
}

#[cfg(test)]
mod selector_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn selector_resolves_revision_ids_and_lineage_heads() {
        let root = tempfile::tempdir().unwrap();
        let first = commit(root.path(), "a", None);
        let head = commit(root.path(), "b", Some(first.model_id.clone()));

        let exact = load_threat_model_by_selector(root.path(), first.revision_id.as_str()).unwrap();
        let lineage = load_threat_model_by_selector(root.path(), first.model_id.as_str()).unwrap();

        assert_eq!(exact.model_ref, first);
        assert_eq!(lineage.model_ref, head);
        assert_eq!(lineage.document["threats"][0]["id"], json!("b"));
    }

    #[test]
    fn selector_errors_name_what_was_tried() {
        let root = tempfile::tempdir().unwrap();
        commit(root.path(), "a", None);
        let missing_revision = ThreatModelRevisionId::new();
        let missing_model = ThreatModelId::new();

        let revision_error = error(root.path(), missing_revision.as_str());
        let lineage_error = error(root.path(), missing_model.as_str());
        let malformed_error = error(root.path(), "latest");

        assert!(revision_error.contains("as a revision id across 1 lineage"), "{revision_error}");
        assert!(revision_error.contains(missing_revision.as_str()), "{revision_error}");
        assert!(lineage_error.contains("as a lineage id (head revision)"), "{lineage_error}");
        assert!(malformed_error.contains("neither a threat-model lineage id"), "{malformed_error}");
    }

    fn commit(root: &Path, threat: &str, model_id: Option<ThreatModelId>) -> ThreatModelRef {
        commit_threat_model_revision(root, &document(threat), request(model_id))
            .unwrap()
            .model_ref
    }

    fn error(root: &Path, selector: &str) -> String {
        format!("{:#}", load_threat_model_by_selector(root, selector).unwrap_err())
    }

    fn document(threat: &str) -> Value {
        json!({
            "version": "2.0",
            "methodology": "stride",
            "dfd": {"nodes": [{"id": "app"}], "flows": [], "trustBoundaries": []},
            "threats": [{"id": threat, "targetElementIds": ["app"]}],
            "summary": {"text": threat}
        })
    }

    fn request(model_id: Option<ThreatModelId>) -> ThreatModelCommit {
        ThreatModelCommit {
            model_id,
            new_model: false,
            label: "Root".to_string(),
            scope: ScopeRef {
                scope_id: "root".to_string(),
                rel_path: PathBuf::from("."),
                project_model_sha256: format!("sha256:{}", "1".repeat(64)),
                target_revision: "test".to_string(),
            },
            methodology: "stride".to_string(),
            source: ThreatModelRevisionSource::Build,
            source_revision_id: None,
            run_id: None,
            activate: Some(true),
            actor: "test".to_string(),
        }
    }
}
