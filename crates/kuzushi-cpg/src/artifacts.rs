//! Artifact conventions: where cpg-rs graphs live under a target and how the
//! engine shape version invalidates them.

use cpg_cli::workspace::GRAPH_SHAPE_VERSION;
use std::path::{Path, PathBuf};

/// Directory holding every per-language graph for a target.
pub fn artifact_dir(target: &Path) -> PathBuf {
    target.join(".kuzushi").join("cpg-rs")
}

/// The graph file for one language. The shape version is part of the name so
/// graphs built by an older engine are rebuilt instead of silently reused.
pub fn artifact_path(target: &Path, lang: &str) -> PathBuf {
    artifact_dir(target).join(format!("{lang}.v{GRAPH_SHAPE_VERSION}.cpg"))
}

/// The graph file for one build scope. Whole-workspace graphs keep the flat
/// per-language name; subtree-scoped graphs nest under `scoped/<key>/` — the
/// artifact ALWAYS lives under the workspace root's `.kuzushi`, never inside
/// the scanned subtree, so a scoped build leaves the target tree untouched.
pub fn scoped_artifact_path(root: &Path, subdir: Option<&Path>, lang: &str) -> PathBuf {
    match subdir {
        None => artifact_path(root, lang),
        Some(subdir) => artifact_dir(root)
            .join("scoped")
            .join(scope_key(subdir))
            .join(format!("{lang}.v{GRAPH_SHAPE_VERSION}.cpg")),
    }
}

/// Versioned, collision-resistant identity of the normalized relative scope.
fn scope_key(subdir: &Path) -> String {
    let normalized: PathBuf = subdir.components().collect();
    let digest = blake3::hash(normalized.as_os_str().as_encoded_bytes());
    let prefix: String = normalized
        .to_string_lossy()
        .chars()
        .take(48)
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    format!("v2-{prefix}-{digest}")
}

/// True when at least one current-shape-version graph exists for the target.
/// This is the MCP attachment / backend readiness probe.
pub fn has_artifacts(target: &Path) -> bool {
    !artifact_langs(target).is_empty()
}

/// Languages with a current-shape-version graph on disk, sorted.
pub fn artifact_langs(target: &Path) -> Vec<String> {
    let suffix = format!(".v{GRAPH_SHAPE_VERSION}.cpg");
    let mut langs: Vec<String> = std::fs::read_dir(artifact_dir(target))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| name.strip_suffix(&suffix).map(str::to_string))
        .filter(|lang| !lang.is_empty())
        .collect();
    langs.sort();
    langs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_path_carries_shape_version() {
        let path = artifact_path(Path::new("/repo"), "go");
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(name, format!("go.v{GRAPH_SHAPE_VERSION}.cpg"));
        assert!(path.starts_with("/repo/.kuzushi/cpg-rs"));
    }

    #[test]
    fn scoped_paths_stay_under_the_workspace_root() {
        let root = Path::new("/repo");
        assert_eq!(
            scoped_artifact_path(root, None, "go"),
            artifact_path(root, "go")
        );
        let scoped = scoped_artifact_path(root, Some(Path::new("platform/src/acme")), "go");
        assert_eq!(
            scoped,
            PathBuf::from(format!(
                "/repo/.kuzushi/cpg-rs/scoped/{}/go.v{GRAPH_SHAPE_VERSION}.cpg",
                scope_key(Path::new("platform/src/acme"))
            ))
        );
    }

    #[test]
    fn scoped_graphs_do_not_masquerade_as_root_languages() {
        let temp = tempfile::tempdir().unwrap();
        let scoped = scoped_artifact_path(temp.path(), Some(Path::new("svc")), "go");
        std::fs::create_dir_all(scoped.parent().unwrap()).unwrap();
        std::fs::write(&scoped, b"x").unwrap();
        // Root-level readiness must not report a subtree-scoped graph.
        assert!(artifact_langs(temp.path()).is_empty());
        assert!(!has_artifacts(temp.path()));
    }

    #[test]
    fn artifact_langs_ignores_stale_shape_versions() {
        let temp = tempfile::tempdir().unwrap();
        let dir = artifact_dir(temp.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("go.v{GRAPH_SHAPE_VERSION}.cpg")), b"x").unwrap();
        std::fs::write(dir.join("python.v1.cpg"), b"x").unwrap();
        assert_eq!(artifact_langs(temp.path()), vec!["go".to_string()]);
        assert!(has_artifacts(temp.path()));
    }

    #[test]
    fn missing_dir_reports_no_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        assert!(!has_artifacts(temp.path()));
        assert!(artifact_langs(temp.path()).is_empty());
    }
}

#[cfg(test)]
mod scope_identity_tests {
    use super::*;
    #[test]
    fn formerly_colliding_scopes_have_distinct_identities() {
        assert_ne!(
            scope_key(Path::new("api/auth")),
            scope_key(Path::new("api_auth"))
        );
        assert_eq!(
            scope_key(Path::new("api/./auth")),
            scope_key(Path::new("api/auth"))
        );
    }
}
