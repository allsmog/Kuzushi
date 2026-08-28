use super::*;

pub(crate) fn bind_scope_ref(
    workspace_root: &Path,
    tree: Option<&crate::workspace::NestedProjectScopeTree>,
    scope: &crate::workspace::NestedProjectScope,
) -> Result<ScopeRef> {
    Ok(ScopeRef {
        scope_id: scope.id.clone(),
        rel_path: PathBuf::from(&scope.rel_path),
        project_model_sha256: scope_tree_sha256(tree)?,
        target_revision: target_revision(workspace_root),
    })
}

pub fn current_scope_ref_for_path(
    workspace_root: &Path,
    rel_path: &str,
) -> Result<Option<ScopeRef>> {
    let tree = crate::workspace::load_nested_project_scopes(workspace_root)?;
    let scope = current_scope(tree.as_ref(), rel_path);
    scope
        .as_ref()
        .map(|scope| bind_scope_ref(workspace_root, tree.as_ref(), scope))
        .transpose()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeBindingStatus {
    Exact,
    StaleDecomposition,
    Missing,
}

/// Compare persisted model scope identity with one already-hydrated current
/// decomposition. Target revision is intentionally not part of lineage
/// identity; content revisions record it separately.
pub fn classify_scope_binding(
    stored: &ScopeRef,
    tree: Option<&crate::workspace::NestedProjectScopeTree>,
) -> Result<ScopeBindingStatus> {
    let rel_path = stored.rel_path.to_string_lossy().replace('\\', "/");
    let Some(current) = current_scope(tree, &rel_path) else {
        return Ok(ScopeBindingStatus::Missing);
    };
    if current.id != stored.scope_id {
        return Ok(ScopeBindingStatus::Missing);
    }
    if scope_tree_sha256(tree)? != stored.project_model_sha256 {
        return Ok(ScopeBindingStatus::StaleDecomposition);
    }
    Ok(ScopeBindingStatus::Exact)
}

fn current_scope(
    tree: Option<&crate::workspace::NestedProjectScopeTree>,
    rel_path: &str,
) -> Option<crate::workspace::NestedProjectScope> {
    if rel_path == "." {
        return tree
            .and_then(|tree| tree.root_scope().cloned())
            .or_else(|| Some(root_scope()));
    }
    tree.and_then(|tree| {
        tree.scopes
            .iter()
            .find(|scope| scope.rel_path == rel_path)
            .cloned()
    })
}

pub(crate) fn root_scope() -> crate::workspace::NestedProjectScope {
    crate::workspace::NestedProjectScope {
        id: crate::workspace::ROOT_SCOPE_ID.to_string(),
        parent: None,
        kind: crate::workspace::NestedProjectKind::Root,
        rel_path: ".".to_string(),
        inherited_sections: Vec::new(),
    }
}

fn scope_tree_sha256(
    tree: Option<&crate::workspace::NestedProjectScopeTree>,
) -> Result<String> {
    let fallback;
    let tree = match tree {
        Some(tree) => tree,
        None => {
            fallback = crate::workspace::NestedProjectScopeTree {
                schema_version: 2,
                root: crate::workspace::ROOT_SCOPE_ID.to_string(),
                scopes: vec![root_scope()],
            };
            &fallback
        }
    };
    let bytes = crate::review_yield::domain::canonical_json_bytes(tree)?;
    Ok(crate::run_lifecycle::sha256_content_digest(&bytes))
}

fn target_revision(workspace_root: &Path) -> String {
    crate::workspace::target_git_metadata(workspace_root)
        .map(|metadata| metadata.sha)
        .unwrap_or_else(|| "unavailable".to_string())
}
