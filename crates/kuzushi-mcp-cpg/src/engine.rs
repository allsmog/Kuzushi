//! Target resolution and per-call engine access.
//!
//! The engine is fully in-process, so a "connection" is just loading (or
//! implicitly building) the target's per-language projects inside a blocking
//! task. `Project` is not `Send` (its frontends hold parser state), so each
//! call creates and drops its projects inside one `spawn_blocking` closure —
//! loads are sub-second thanks to the persisted graphs.

use anyhow::{Context, Result};
use kuzushi_cpg::Project;
use kuzushi_mcp_common::ReadRootCapability;
use std::path::{Path, PathBuf};

pub const ARTIFACT_ENV: &str = "KUZUSHI_MCP_CPG_ARTIFACT";

/// The repository the server answers questions about: derived from the
/// bridge-provided artifact directory (`<target>/.kuzushi/cpg-rs`), else the
/// first MCP read root.
pub fn target_root() -> Result<PathBuf> {
    if let Some(root) = target_root_from_artifact_env() {
        return Ok(root);
    }
    let capability = ReadRootCapability::from_environment()
        .context("cannot resolve target: set KUZUSHI_MCP_CPG_ARTIFACT or the MCP read roots")?;
    capability.resolve(Path::new("."))
}

fn target_root_from_artifact_env() -> Option<PathBuf> {
    let artifact = PathBuf::from(std::env::var_os(ARTIFACT_ENV)?);
    // <target>/.kuzushi/cpg-rs -> <target>
    let target = artifact.parent()?.parent()?;
    target.is_dir().then(|| target.to_path_buf())
}

/// Languages a query runs against: every persisted current-shape graph plus
/// every buildable language detected from source, which the implicit build
/// then materialises. A persisted graph must not hide the rest of the
/// repository: Juice Shop's persisted client-side JavaScript graph used to
/// shadow its entire TypeScript server.
pub fn query_languages(root: &Path) -> Vec<String> {
    let mut languages = kuzushi_cpg::artifact_langs(root);
    for detected in kuzushi_cpg::detect_buildable_languages(root) {
        if !languages.iter().any(|language| language == detected) {
            languages.push(detected.to_string());
        }
    }
    languages
}

/// Load-or-build every queryable language project for the target, then run
/// `f` over them on a blocking thread. The projects never leave the closure.
pub async fn with_language_projects<T, F>(f: F) -> Result<T>
where
    F: FnOnce(&Path, &[(String, Project)]) -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let root = target_root()?;
    tokio::task::spawn_blocking(move || {
        let languages = query_languages(&root);
        anyhow::ensure!(
            !languages.is_empty(),
            "no cpg-rs-supported source language under {} (supported: {})",
            root.display(),
            kuzushi_cpg::supported_languages().join(", ")
        );
        let projects = load_language_projects(&root, languages)?;
        f(&root, &projects)
    })
    .await
    .context("cpg engine task panicked")?
}

/// A missing language graph makes the query incomplete. Refuse the result
/// instead of presenting a partial empty answer as complete repository coverage.
fn load_language_projects(root: &Path, languages: Vec<String>) -> Result<Vec<(String, Project)>> {
    let mut projects = Vec::new();
    let mut failures = Vec::new();
    for lang in languages {
        match kuzushi_cpg::ensure_project(root, &lang) {
            Ok((project, _report)) => projects.push((lang, project)),
            Err(error) => failures.push(format!("{lang}: {error}")),
        }
    }
    report_skipped_languages(&projects, &failures)?;
    Ok(projects)
}

fn report_skipped_languages(projects: &[(String, Project)], failures: &[String]) -> Result<()> {
    anyhow::ensure!(
        failures.is_empty(),
        "cpg-rs query coverage incomplete: {}",
        failures.join("; ")
    );
    anyhow::ensure!(
        !projects.is_empty(),
        "cpg-rs graph unavailable: {}",
        failures.join("; ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_language_cannot_be_reported_as_a_complete_empty_query() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("main.go"),
            "package main\nfunc main() {}\n",
        )
        .unwrap();
        std::fs::write(temp.path().join("broken.py"), [0xff, 0xfe]).unwrap();
        let result = load_language_projects(temp.path(), vec!["go".into(), "python".into()]);
        let error = result.err().expect("partial language coverage must refuse");
        assert!(error.to_string().contains("coverage incomplete"));
        assert!(error.to_string().contains("python"));
    }

    #[test]
    fn query_languages_add_detected_languages_to_persisted_graphs() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("main.go"), "package main\n").unwrap();
        // No artifacts yet: detection reports go.
        assert_eq!(query_languages(temp.path()), vec!["go".to_string()]);
        // A persisted python graph joins detection; it does not hide go.
        let dir = kuzushi_cpg::artifact_dir(temp.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(format!("python.v{}.cpg", kuzushi_cpg::GRAPH_SHAPE_VERSION)),
            b"x",
        )
        .unwrap();
        assert_eq!(
            query_languages(temp.path()),
            vec!["python".to_string(), "go".to_string()]
        );
    }
}
