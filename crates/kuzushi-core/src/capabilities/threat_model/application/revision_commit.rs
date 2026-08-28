use super::*;

#[derive(Debug, Clone)]
pub(crate) struct BuildRevisionSelection {
    pub(crate) workspace_root: PathBuf,
    pub(crate) scope: ScopeRef,
    pub(crate) methodology: String,
    pub(crate) label: String,
    pub(crate) model_id: Option<ThreatModelId>,
    pub(crate) new_model: bool,
    pub(crate) fresh: bool,
    pub(crate) activate: Option<bool>,
    pub(crate) source: ThreatModelRevisionSource,
    pub(crate) run_id: Option<String>,
    pub(crate) actor: String,
}

#[derive(Debug, Clone)]
pub struct ThreatModelPatchCommit {
    pub model_ref: ThreatModelRef,
    pub ledger_warning: Option<String>,
}

pub fn apply_threat_model_patch_revision(
    workspace_root: &Path,
    patch: &Value,
    actor: &str,
) -> Result<ThreatModelPatchCommit> {
    let (committed, document) = apply_threat_model_patch_to_active(workspace_root, patch, actor)?;
    let ledger_warning = record_threat_model_version_with_ref(
        workspace_root,
        &document,
        "operator-edit",
        None,
        &committed.model_ref,
    )
    .err()
    .map(|error| {
        format!("immutable revision committed, but version ledger append failed: {error:#}")
    });
    Ok(ThreatModelPatchCommit {
        model_ref: committed.model_ref,
        ledger_warning,
    })
}

pub(crate) fn commit_generated_threat_model_revision(
    document: &Value,
    selection: BuildRevisionSelection,
) -> Result<ThreatModelRef> {
    let model_id = selected_lineage_id(&selection)?;
    let request = ThreatModelCommit {
        model_id,
        new_model: selection.new_model,
        label: selection.label,
        scope: selection.scope,
        methodology: selection.methodology,
        source: selection.source,
        source_revision_id: None,
        run_id: selection.run_id,
        activate: selection.activate,
        actor: selection.actor,
    };
    Ok(commit_threat_model_revision(&selection.workspace_root, document, request)?.model_ref)
}

pub(crate) fn load_selected_build_threat_model(
    input: &BuildInput,
) -> Result<Option<ActiveThreatModel>> {
    let scope = effective_build_scope(input)?;
    load_build_threat_model(
        input.workspace_root(),
        &scope,
        &input.methodology,
        input.model_id.as_ref(),
    )
}

pub(crate) fn should_preserve_selected_user_edited_model(
    selection: &BuildRevisionSelection,
    preserve_user_edits: bool,
) -> Result<bool> {
    if selection.new_model || !preserve_user_edits {
        return Ok(false);
    }
    Ok(load_build_threat_model(
        &selection.workspace_root,
        &selection.scope,
        &selection.methodology,
        selection.model_id.as_ref(),
    )?
    .is_some_and(|selected| {
        selected
            .document
            .get("userEdited")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }))
}

pub(crate) fn effective_build_scope(input: &BuildInput) -> Result<ScopeRef> {
    input
        .roots
        .scope
        .clone()
        .map(Ok)
        .unwrap_or_else(|| root_scope_ref(input.workspace_root()))
}

fn selected_lineage_id(selection: &BuildRevisionSelection) -> Result<Option<ThreatModelId>> {
    resolve_build_lineage_selection(
        &selection.workspace_root,
        &selection.scope,
        &selection.methodology,
        selection.model_id.as_ref(),
        selection.new_model,
        selection.source == ThreatModelRevisionSource::Refine,
        selection.fresh,
    )
}

pub(crate) fn resolve_build_lineage_selection(
    root: &Path,
    scope: &ScopeRef,
    methodology: &str,
    model_id: Option<&ThreatModelId>,
    new_model: bool,
    require_existing: bool,
    fresh_build: bool,
) -> Result<Option<ThreatModelId>> {
    anyhow::ensure!(
        !(new_model && model_id.is_some()),
        "modelId and newModel=true are mutually exclusive"
    );
    anyhow::ensure!(
        !(require_existing && fresh_build),
        "mode=refine derives from the persisted model and cannot use a fresh lineage"
    );
    if new_model {
        return Ok(None);
    }
    open_writable_threat_model_store(root)?;
    let selected = selected_build_lineage(root, scope, methodology, model_id, fresh_build)?;
    anyhow::ensure!(
        model_id.is_none() || selected.is_some(),
        "selected threat-model lineage was not found"
    );
    anyhow::ensure!(
        !require_existing || selected.is_some(),
        "mode=refine requires a threat-model lineage matching the selected scope and methodology; run a full build first"
    );
    Ok(selected)
}

fn selected_build_lineage(
    root: &Path,
    scope: &ScopeRef,
    methodology: &str,
    model_id: Option<&ThreatModelId>,
    fresh_build: bool,
) -> Result<Option<ThreatModelId>> {
    if fresh_build && model_id.is_none() {
        return resolve_unique_build_lineage(root, scope, methodology);
    }
    load_build_threat_model(root, scope, methodology, model_id)
        .map(|selected| selected.map(|model| model.model_ref.model_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(binding: &str) -> ScopeRef {
        ScopeRef {
            scope_id: "root".to_string(),
            rel_path: PathBuf::from("."),
            project_model_sha256: binding.to_string(),
            target_revision: "revision-a".to_string(),
        }
    }

    fn model_document() -> Value {
        json!({
            "version": "2.0",
            "methodology": "stride",
            "dfd": {
                "nodes": [{"id": "app"}],
                "flows": [],
                "trustBoundaries": []
            },
            "threats": [],
            "summary": {}
        })
    }

    fn commit_lineage(root: &Path, scope: ScopeRef) -> ThreatModelRef {
        commit_threat_model_revision(
            root,
            &model_document(),
            ThreatModelCommit {
                model_id: None,
                new_model: false,
                label: "fixture".to_string(),
                scope,
                methodology: "stride".to_string(),
                source: ThreatModelRevisionSource::Build,
                source_revision_id: None,
                run_id: None,
                activate: Some(false),
                actor: "test".to_string(),
            },
        )
        .unwrap()
        .model_ref
    }

    #[test]
    fn implicit_selection_uses_a_unique_inactive_scope_lineage() {
        let root = tempfile::tempdir().unwrap();
        let active = commit_threat_model_revision(
            root.path(),
            &model_document(),
            ThreatModelCommit {
                model_id: None,
                new_model: false,
                label: "root".to_string(),
                scope: scope("tree-a"),
                methodology: "stride".to_string(),
                source: ThreatModelRevisionSource::Build,
                source_revision_id: None,
                run_id: None,
                activate: Some(true),
                actor: "test".to_string(),
            },
        )
        .unwrap();
        let inactive_scope = ScopeRef {
            scope_id: "api".to_string(),
            rel_path: PathBuf::from("apps/api"),
            ..scope("tree-a")
        };
        let inactive = commit_threat_model_revision(
            root.path(),
            &model_document(),
            ThreatModelCommit {
                model_id: None,
                new_model: false,
                label: "api".to_string(),
                scope: inactive_scope.clone(),
                methodology: "stride".to_string(),
                source: ThreatModelRevisionSource::Build,
                source_revision_id: None,
                run_id: None,
                activate: Some(false),
                actor: "test".to_string(),
            },
        )
        .unwrap();

        let selected = resolve_build_lineage_selection(
            root.path(),
            &inactive_scope,
            "stride",
            None,
            false,
            true,
            false,
        )
        .unwrap();
        assert_eq!(selected, Some(inactive.model_ref.model_id));
        assert_ne!(selected, Some(active.model_ref.model_id));
    }

    #[test]
    fn fresh_build_accepts_a_stale_decomposition_without_reusing_it() {
        let root = tempfile::tempdir().unwrap();
        commit_lineage(root.path(), scope("tree-a"));

        let selected = resolve_build_lineage_selection(
            root.path(),
            &scope("tree-b"),
            "stride",
            None,
            false,
            false,
            true,
        )
        .unwrap();

        assert_eq!(selected, None);
        let seeded_error = resolve_build_lineage_selection(
            root.path(),
            &scope("tree-b"),
            "stride",
            None,
            false,
            false,
            false,
        )
        .unwrap_err();
        assert!(seeded_error.to_string().contains("scope binding is stale"));
    }

    #[test]
    fn fresh_build_still_requires_an_explicit_lineage_to_match_exactly() {
        let root = tempfile::tempdir().unwrap();
        let stored = commit_lineage(root.path(), scope("tree-a"));

        let error = resolve_build_lineage_selection(
            root.path(),
            &scope("tree-b"),
            "stride",
            Some(&stored.model_id),
            false,
            false,
            true,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("does not match the requested scope and methodology"));
    }
}
