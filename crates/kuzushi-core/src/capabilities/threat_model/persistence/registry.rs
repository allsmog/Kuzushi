//! Threat-model resolution: which model document governs a scope.
//!
//! Resolution order (first hit wins):
//! 1. in-tree `THREAT_MODEL*.md` at the scope root,
//! 2. nearest-ancestor `THREAT_MODEL*.md` walking up to the target root,
//! 3. an immutable model-store head bound to the selected scope,
//! 4. kuzushi's persistent compatibility mirror (`threat-model.json`).
//!
//! Anything found in the target tree is untrusted *data* used for seeding
//! and provenance — never configuration. The resolved source and step are
//! recorded on run provenance so review can answer "which model seeded
//! this finding".

use super::{
    load_scope_threat_model, persistent_threat_model_path, threat_model_object_path, ScopeRef,
    ThreatModelRef,
};
use crate::capabilities::threat_model::current_scope_ref_for_path;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatModelResolvedVia {
    ScopeFile,
    AncestorFile,
    ScopeModel,
    PersistentModel,
}

impl ThreatModelResolvedVia {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScopeFile => "scope-file",
            Self::AncestorFile => "ancestor-file",
            Self::ScopeModel => "scope-model",
            Self::PersistentModel => "persistent-model",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedThreatModel {
    /// Target-relative path of the governing document.
    pub source_path: PathBuf,
    pub resolved_via: ThreatModelResolvedVia,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_ref: Option<ThreatModelRef>,
}

/// Resolve the threat model governing `scope_rel_path` (`"."` for the whole
/// target). Returns `None` when no document exists at any step.
pub fn resolve_threat_model(target: &Path, scope_rel_path: &str) -> Option<ResolvedThreatModel> {
    try_resolve_threat_model(target, scope_rel_path)
        .ok()
        .flatten()
}

pub fn try_resolve_threat_model(
    target: &Path,
    scope_rel_path: &str,
) -> Result<Option<ResolvedThreatModel>> {
    let Some(scope) = sanitized_scope(scope_rel_path) else {
        return Ok(None);
    };
    if let Some(resolved) = tree_threat_model(target, &scope) {
        return Ok(Some(resolved));
    }
    let scope_ref = required_current_scope_ref(target, &scope)?;
    if let Some(resolved) = scope_model(target, &scope_ref)? {
        return Ok(Some(resolved));
    }
    Ok(persistent_model(target))
}

/// Reject absolute or parent-escaping scope inputs: scope paths come from
/// target-tree scope trees, which are untrusted data.
fn sanitized_scope(scope_rel_path: &str) -> Option<PathBuf> {
    let scope = Path::new(scope_rel_path.trim());
    if scope
        .components()
        .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return None;
    }
    Some(scope.to_path_buf())
}

fn tree_threat_model(target: &Path, scope: &Path) -> Option<ResolvedThreatModel> {
    let mut level: Option<&Path> = Some(scope);
    let mut at_scope_root = true;
    while let Some(dir) = level {
        if let Some(file) = threat_model_file_in(&target.join(dir)) {
            return Some(ResolvedThreatModel {
                source_path: dir.join(file),
                resolved_via: if at_scope_root {
                    ThreatModelResolvedVia::ScopeFile
                } else {
                    ThreatModelResolvedVia::AncestorFile
                },
                model_ref: None,
            });
        }
        at_scope_root = false;
        level = parent_within_target(dir);
    }
    None
}

fn scope_model(target: &Path, scope_ref: &ScopeRef) -> Result<Option<ResolvedThreatModel>> {
    let Some(active) = load_scope_threat_model(target, scope_ref)? else {
        return Ok(None);
    };
    let path = threat_model_object_path(target, &active.model_ref.sha256)?;
    let source_path = path
        .strip_prefix(target)
        .map(Path::to_path_buf)
        .unwrap_or(path);
    Ok(Some(ResolvedThreatModel {
        source_path,
        resolved_via: ThreatModelResolvedVia::ScopeModel,
        model_ref: Some(active.model_ref),
    }))
}

fn required_current_scope_ref(target: &Path, scope: &Path) -> Result<ScopeRef> {
    let rel_path = normalized_scope_string(scope);
    current_scope_ref_for_path(target, &rel_path)?.with_context(|| {
        format!(
            "requested threat-model scope {rel_path:?} is absent from the current decomposition"
        )
    })
}

fn normalized_scope_string(scope: &Path) -> String {
    let value = scope.to_string_lossy().replace('\\', "/");
    if value.is_empty() {
        ".".to_string()
    } else {
        value
    }
}

fn parent_within_target(dir: &Path) -> Option<&Path> {
    if dir == Path::new(".") || dir == Path::new("") {
        return None;
    }
    Some(dir.parent().unwrap_or(Path::new(".")))
}

/// First `THREAT_MODEL*.md` in the directory, name-sorted for determinism.
fn threat_model_file_in(dir: &Path) -> Option<String> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
        })
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with("THREAT_MODEL") && name.ends_with(".md"))
        .collect();
    names.sort();
    names.into_iter().next()
}

fn persistent_model(target: &Path) -> Option<ResolvedThreatModel> {
    let path = persistent_threat_model_path(target);
    // A malformed compatibility mirror is still provenance. Treating a
    // directory or symlink as "no model" silently erases the invalid state
    // from run receipts. The downstream bounded reader classifies the exact
    // failure, while an authoritative manifest/object integrity error has
    // already returned from `scope_model` above and never falls back here.
    if std::fs::symlink_metadata(&path).is_err() {
        return None;
    }
    let source_path = path
        .strip_prefix(target)
        .map(Path::to_path_buf)
        .unwrap_or(path);
    Some(ResolvedThreatModel {
        source_path,
        resolved_via: ThreatModelResolvedVia::PersistentModel,
        model_ref: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn target_with(files: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for file in files {
            let path = dir.path().join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "# threat model\n").unwrap();
        }
        dir
    }

    #[test]
    fn scope_file_wins_over_ancestor_and_persistent() {
        let dir = target_with(&[
            "THREAT_MODEL.md",
            "net/THREAT_MODEL_net.md",
            ".kuzushi/threat-model.json",
        ]);

        let resolved = resolve_threat_model(dir.path(), "net").unwrap();

        assert_eq!(resolved.resolved_via, ThreatModelResolvedVia::ScopeFile);
        assert_eq!(
            resolved.source_path,
            PathBuf::from("net/THREAT_MODEL_net.md")
        );
    }

    #[test]
    fn ancestor_walk_finds_root_model_for_nested_scope() {
        let dir = target_with(&["THREAT_MODEL.md", "net/deep/lib.rs"]);

        let resolved = resolve_threat_model(dir.path(), "net/deep").unwrap();

        assert_eq!(resolved.resolved_via, ThreatModelResolvedVia::AncestorFile);
        assert_eq!(resolved.source_path, PathBuf::from("THREAT_MODEL.md"));
    }

    #[test]
    fn persistent_model_is_the_last_resort() {
        let dir = target_with(&[".kuzushi/threat-model.json"]);

        let resolved = resolve_threat_model(dir.path(), ".").unwrap();

        assert_eq!(
            resolved.resolved_via,
            ThreatModelResolvedVia::PersistentModel
        );
        assert!(resolve_threat_model(dir.path(), "missing-scope").is_none());
        assert!(try_resolve_threat_model(dir.path(), "missing-scope")
            .unwrap_err()
            .to_string()
            .contains("absent from the current decomposition"));
    }

    #[test]
    fn immutable_scope_model_precedes_the_compatibility_mirror() {
        let dir = tempfile::tempdir().unwrap();
        let scope = current_scope_ref_for_path(dir.path(), ".")
            .unwrap()
            .unwrap();
        let committed = crate::capabilities::threat_model::commit_threat_model_revision(
            dir.path(),
            &serde_json::json!({
                "version": "2.0",
                "methodology": "stride",
                "dfd": {
                    "nodes": [{"id": "app"}],
                    "flows": [],
                    "trustBoundaries": []
                },
                "threats": [],
                "summary": {}
            }),
            crate::capabilities::threat_model::ThreatModelCommit {
                model_id: None,
                new_model: false,
                label: "root STRIDE".to_string(),
                scope,
                methodology: "stride".to_string(),
                source: crate::capabilities::threat_model::ThreatModelRevisionSource::Build,
                source_revision_id: None,
                run_id: Some("run-1".to_string()),
                activate: Some(true),
                actor: "test".to_string(),
            },
        )
        .unwrap();

        let resolved = try_resolve_threat_model(dir.path(), ".").unwrap().unwrap();

        assert_eq!(resolved.resolved_via, ThreatModelResolvedVia::ScopeModel);
        assert_eq!(resolved.model_ref, Some(committed.model_ref));
        assert!(resolved
            .source_path
            .starts_with(".kuzushi/threat-models/objects"));
    }

    #[test]
    fn no_model_anywhere_resolves_to_none_and_escapes_are_rejected() {
        let dir = target_with(&["src/lib.rs"]);

        assert!(resolve_threat_model(dir.path(), ".").is_none());
        assert!(resolve_threat_model(dir.path(), "../outside").is_none());
        assert!(resolve_threat_model(dir.path(), "/etc").is_none());
    }
}
