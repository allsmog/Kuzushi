use anyhow::{Context, Result};
use kuzushi_core::{NestedProjectScope, ScopeRef, ThreatModelManifest, ThreatModelMetadata};
use serde_json::{json, Value};
use std::path::Path;

pub(crate) fn scoped_regeneration_input(
    root: &Path,
    scope: &NestedProjectScope,
    default_methodology: &str,
) -> Result<Value> {
    let current = kuzushi_core::capabilities::current_scope_ref_for_path(root, &scope.rel_path)?
        .context("selected regeneration scope is absent from the current decomposition")?;
    let manifest = kuzushi_core::capabilities::load_threat_model_manifest(root)?;
    let model = manifest
        .as_ref()
        .map(|manifest| selected_scope_model(manifest, &current))
        .transpose()?
        .flatten();
    Ok(match model {
        Some(model) => json!({
            "scope": format!("id:{}", scope.id),
            "methodology": model.methodology,
            "mode": "refine",
            "modelId": model.model_id.as_str(),
        }),
        None => json!({
            "scope": format!("id:{}", scope.id),
            "methodology": default_methodology,
            "mode": "build",
        }),
    })
}

fn selected_scope_model<'a>(
    manifest: &'a ThreatModelManifest,
    scope: &ScopeRef,
) -> Result<Option<&'a ThreatModelMetadata>> {
    let matches = manifest
        .models
        .iter()
        .filter(|model| model.scope.same_lineage_category(scope))
        .collect::<Vec<_>>();
    if matches.len() <= 1 {
        return Ok(matches.first().copied());
    }
    let active = manifest.active.as_ref().and_then(|active| {
        matches
            .iter()
            .find(|model| model.model_id == active.model_id)
            .copied()
    });
    active
        .context("multiple model variants match this scope; activate one before refining")
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> NestedProjectScope {
        NestedProjectScope {
            id: "package-api".to_string(),
            parent: Some("root".to_string()),
            kind: kuzushi_core::NestedProjectKind::PackageRoot,
            rel_path: "packages/api".to_string(),
            inherited_sections: Vec::new(),
        }
    }

    fn scope_tree(extra: bool) -> kuzushi_core::NestedProjectScopeTree {
        let mut scopes = vec![
            NestedProjectScope {
                id: "root".to_string(),
                parent: None,
                kind: kuzushi_core::NestedProjectKind::Root,
                rel_path: ".".to_string(),
                inherited_sections: Vec::new(),
            },
            scope(),
        ];
        if extra {
            scopes.push(NestedProjectScope {
                id: "package-web".to_string(),
                parent: Some("root".to_string()),
                kind: kuzushi_core::NestedProjectKind::PackageRoot,
                rel_path: "packages/web".to_string(),
                inherited_sections: Vec::new(),
            });
        }
        kuzushi_core::NestedProjectScopeTree {
            schema_version: 2,
            root: "root".to_string(),
            scopes,
        }
    }

    #[test]
    fn scope_without_a_model_requests_a_build() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("packages/api")).unwrap();
        kuzushi_core::save_nested_project_scopes(root.path(), &scope_tree(false)).unwrap();

        let input = scoped_regeneration_input(root.path(), &scope(), "pasta").unwrap();

        assert_eq!(input["scope"], "id:package-api");
        assert_eq!(input["methodology"], "pasta");
        assert_eq!(input["mode"], "build");
        assert!(input.get("modelId").is_none());
    }

    #[test]
    fn changed_decomposition_builds_fresh_instead_of_refining_a_stale_lineage() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("packages/api")).unwrap();
        std::fs::create_dir_all(root.path().join("packages/web")).unwrap();
        kuzushi_core::save_nested_project_scopes(root.path(), &scope_tree(false)).unwrap();
        let old_scope =
            kuzushi_core::capabilities::current_scope_ref_for_path(root.path(), "packages/api")
                .unwrap()
                .unwrap();
        kuzushi_core::capabilities::commit_threat_model_revision(
            root.path(),
            &json!({
                "version": "2.0",
                "methodology": "stride",
                "dfd": {"nodes": [{"id": "api"}], "flows": [], "trustBoundaries": []},
                "threats": [],
                "summary": {}
            }),
            kuzushi_core::capabilities::ThreatModelCommit {
                model_id: None,
                new_model: false,
                label: "API".to_string(),
                scope: old_scope,
                methodology: "stride".to_string(),
                source: kuzushi_core::capabilities::ThreatModelRevisionSource::Build,
                source_revision_id: None,
                run_id: None,
                activate: Some(true),
                actor: "test".to_string(),
            },
        )
        .unwrap();
        kuzushi_core::save_nested_project_scopes(root.path(), &scope_tree(true)).unwrap();

        let input = scoped_regeneration_input(root.path(), &scope(), "pasta").unwrap();

        assert_eq!(input["mode"], "build");
        assert_eq!(input["methodology"], "pasta");
        assert!(input.get("modelId").is_none());
    }
}
