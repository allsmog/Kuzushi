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
