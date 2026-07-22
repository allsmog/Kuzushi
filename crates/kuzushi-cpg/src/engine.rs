//! Build-or-load of per-language cpg-rs projects — the implicit-build
//! primitive that makes a fresh checkout scannable with zero setup.

use crate::artifacts::artifact_path;
use crate::languages::{extensions_for, walk_sources};
use cpg_core::{Cpg, Query};
use cpg_incremental::Project;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// What one `ensure_project` call did, for run traces and build stats.
#[derive(Debug, Clone)]
pub struct CpgBuildReport {
    pub language: String,
    pub cpg_path: PathBuf,
    /// True when a fresh on-disk graph was reopened instead of rebuilt.
    pub reused_cache: bool,
    pub methods: usize,
    pub calls: usize,
    pub nodes: usize,
    pub duration_ms: u128,
}

/// Load the target's graph for `lang` when fresh, else build it from source
/// and persist it. Freshness = the artifact is newer than every in-scope
/// source file (same mtime policy as the engine's own workspace cache).
pub fn ensure_project(target: &Path, lang: &str) -> Result<(Project, CpgBuildReport), String> {
    let started = std::time::Instant::now();
    let cpg_path = artifact_path(target, lang);
    let (project, reused_cache) = match load_fresh(target, lang, &cpg_path) {
        Some(project) => (project, true),
        None => (build_and_save(target, lang, &cpg_path)?, false),
    };
    let report = build_report(lang, cpg_path, reused_cache, &project, started.elapsed());
    Ok((project, report))
}

fn build_report(
    lang: &str,
    cpg_path: PathBuf,
    reused_cache: bool,
    project: &Project,
    elapsed: std::time::Duration,
) -> CpgBuildReport {
    CpgBuildReport {
        language: lang.to_string(),
        cpg_path,
        reused_cache,
        methods: project.cpg.methods().len(),
        calls: project.cpg.calls().len(),
        nodes: project.cpg.live_count(),
        duration_ms: elapsed.as_millis(),
    }
}

fn load_fresh(target: &Path, lang: &str, cpg_path: &Path) -> Option<Project> {
    let artifact_mtime = std::fs::metadata(cpg_path).and_then(|m| m.modified()).ok()?;
    if newest_source_mtime(target, lang).is_some_and(|source| source > artifact_mtime) {
        return None;
    }
    let cpg = Cpg::load(&cpg_path.to_string_lossy()).ok()?;
    let (mut project, _) = cpg_cli::make_project(lang);
    project.reopen(cpg);
    Some(project)
}

fn build_and_save(target: &Path, lang: &str, cpg_path: &Path) -> Result<Project, String> {
    let excludes = cpg_cli::workspace::excludes_for(lang);
    let project = cpg_cli::build_project_filtered(&target.to_string_lossy(), lang, excludes);
    if let Some(parent) = cpg_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    project
        .cpg
        .save(&cpg_path.to_string_lossy())
        .map_err(|error| format!("cannot save {}: {error}", cpg_path.display()))?;
    Ok(project)
}

fn newest_source_mtime(target: &Path, lang: &str) -> Option<SystemTime> {
    let exts = extensions_for(lang);
    let excludes = cpg_cli::workspace::excludes_for(lang);
    let mut newest: Option<SystemTime> = None;
    walk_sources(target, exts, excludes, &mut |path| {
        if let Ok(mtime) = std::fs::metadata(path).and_then(|m| m.modified()) {
            if newest.is_none_or(|current| mtime > current) {
                newest = Some(mtime);
            }
        }
    });
    newest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_go_fixture(dir: &Path) {
        std::fs::write(
            dir.join("main.go"),
            "package main\n\nfunc handler(input string) {\n\trun(input)\n}\n\nfunc run(cmd string) {\n}\n",
        )
        .unwrap();
    }

    #[test]
    fn builds_then_reuses_the_persisted_graph() {
        let temp = tempfile::tempdir().unwrap();
        write_go_fixture(temp.path());

        let (_, first) = ensure_project(temp.path(), "go").unwrap();
        assert!(!first.reused_cache);
        assert!(first.cpg_path.exists());
        assert!(first.methods >= 2, "got {first:?}");

        let (_, second) = ensure_project(temp.path(), "go").unwrap();
        assert!(second.reused_cache);
        assert_eq!(second.methods, first.methods);
    }

    #[test]
    fn source_edit_invalidates_the_cache() {
        let temp = tempfile::tempdir().unwrap();
        write_go_fixture(temp.path());
        let (_, first) = ensure_project(temp.path(), "go").unwrap();

        // Push the source mtime past the artifact's.
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        let file = std::fs::File::options()
            .append(true)
            .open(temp.path().join("main.go"))
            .unwrap();
        file.set_modified(future).unwrap();
        drop(file);

        let (_, second) = ensure_project(temp.path(), "go").unwrap();
        assert!(!second.reused_cache, "edited source must rebuild");
        assert_eq!(second.methods, first.methods);
    }
}
