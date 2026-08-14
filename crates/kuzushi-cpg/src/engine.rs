//! Build-or-load of per-language cpg-rs projects — the implicit-build
//! primitive that makes a fresh checkout scannable with zero setup.

use crate::artifacts::scoped_artifact_path;
use crate::languages::{build_excludes, extensions_for, walk_sources};
use cpg_core::{Cpg, Query};
use cpg_incremental::Project;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

/// Build refusal threshold: one graph build may consume at most this many
/// source files before the engine refuses instead of grinding unbounded.
/// Whole-monorepo builds are pathological (superlinear passes, one thread);
/// scoped subtrees are the supported shape for very large targets.
pub const DEFAULT_MAX_SOURCE_FILES: usize = 25_000;

pub fn validate_graph_artifact(path: &Path) -> Result<(), String> {
    let path = path.to_string_lossy().into_owned();
    match std::panic::catch_unwind(|| Cpg::load(&path)) {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(format!("invalid cpg-rs graph: {error}")),
        Err(_) => Err("invalid cpg-rs graph: decoder panicked".to_string()),
    }
}

/// Resource ceilings for one graph build. Loads of fresh artifacts are
/// never limited — only fresh builds are.
#[derive(Debug, Clone, Copy)]
pub struct BuildLimits {
    pub max_source_files: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_source_files: DEFAULT_MAX_SOURCE_FILES,
        }
    }
}

/// Where a build reads sources from and where its artifact lives. The
/// artifact ALWAYS lands under the workspace root's `.kuzushi` — a
/// subtree-scoped build never writes inside the scanned subtree.
#[derive(Debug, Clone)]
pub struct BuildScope {
    root: PathBuf,
    subdir: Option<PathBuf>,
}

impl BuildScope {
    /// Whole-workspace scope: sources and artifacts both keyed on `root`.
    pub fn whole(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            subdir: None,
        }
    }

    /// Subtree scope: sources come from `root/subdir`, the artifact from
    /// `root/.kuzushi/cpg-rs/scoped/<key>/`. Rejects absolute or traversing
    /// subdirs so the scope can never escape the workspace.
    pub fn subtree(root: &Path, subdir: &Path) -> Result<Self, String> {
        let traverses = subdir
            .components()
            .any(|component| matches!(component, Component::ParentDir));
        if subdir.is_absolute() || traverses || subdir.as_os_str().is_empty() {
            return Err(format!(
                "scope subdir must be a non-empty relative path without '..', got {}",
                subdir.display()
            ));
        }
        Ok(Self {
            root: root.to_path_buf(),
            subdir: Some(subdir.to_path_buf()),
        })
    }

    /// The directory the source corpus is read from.
    pub fn scan_root(&self) -> PathBuf {
        match &self.subdir {
            Some(subdir) => self.root.join(subdir),
            None => self.root.clone(),
        }
    }

    /// The scope's persisted graph location for `lang`.
    pub fn artifact_path(&self, lang: &str) -> PathBuf {
        scoped_artifact_path(&self.root, self.subdir.as_deref(), lang)
    }
}

/// What one `ensure_project` call did, for run traces and build stats.
#[derive(Debug, Clone)]
pub struct CpgBuildReport {
    pub language: String,
    pub cpg_path: PathBuf,
    /// True when a fresh on-disk graph was reopened instead of rebuilt.
    pub reused_cache: bool,
    /// In-scope source files censused before the build/load decision.
    pub source_files: usize,
    pub methods: usize,
    pub calls: usize,
    pub nodes: usize,
    pub duration_ms: u128,
}

/// Whole-workspace `ensure_project_in` with default limits, kept for the
/// callers that scan a target root directly (MCP server, simple builds).
pub fn ensure_project(target: &Path, lang: &str) -> Result<(Project, CpgBuildReport), String> {
    ensure_project_in(&BuildScope::whole(target), lang, &BuildLimits::default())
}

/// Load the scope's persisted graph for `lang` WITHOUT building or rebuilding.
/// Returns `None` when no artifact is on disk (or it fails to decode).
///
/// Unlike [`ensure_project_in`], a STALE graph (sources newer than the
/// artifact) is still served as-is — staleness is the caller's policy
/// decision. Callers that must never trigger an implicit from-source build
/// during bulk work (e.g. the deep auditor's `Available` taint policy) use
/// this load-only path so serving an existing graph as a hint can never turn
/// into a whole-repo rebuild.
pub fn open_project_in(scope: &BuildScope, lang: &str) -> Option<Project> {
    load_project(&scope.artifact_path(lang), lang)
}

/// Decode a persisted graph and reopen it as a per-language project. Shared by
/// the freshness-gated [`load_fresh`] and the load-only [`open_project_in`].
///
/// `Cpg::load` can PANIC on a corrupt or truncated artifact, so the decode is
/// wrapped in the same panic guard [`validate_graph_artifact`] uses. A bad
/// graph degrades to `None` — the caller's `Failed`/`Missing` readiness — and
/// never aborts the (audit) thread. Both entry points share this guard, so the
/// `Available` policy's unvetted on-disk load is safe too.
fn load_project(cpg_path: &Path, lang: &str) -> Option<Project> {
    let path = cpg_path.to_string_lossy().into_owned();
    let cpg = std::panic::catch_unwind(|| Cpg::load(&path)).ok()?.ok()?;
    let (mut project, _) = cpg_cli::make_project(lang).ok()?;
    project.reopen(cpg);
    Some(project)
}

/// Load the scope's graph for `lang` when fresh, else build it from source
/// and persist it. Freshness = the artifact is newer than every in-scope
/// source file. A stale/missing graph whose corpus exceeds the limits is an
/// explicit refusal, never a silent multi-hour build.
pub fn ensure_project_in(
    scope: &BuildScope,
    lang: &str,
    limits: &BuildLimits,
) -> Result<(Project, CpgBuildReport), String> {
    let started = std::time::Instant::now();
    let scan_root = scope.scan_root();
    let cpg_path = scope.artifact_path(lang);
    let census = source_census(&scan_root, lang);
    let (project, reused_cache) = match load_fresh(&census, lang, &cpg_path) {
        Some(project) => (project, true),
        None => (
            build_and_save(&scan_root, lang, &cpg_path, &census, limits)?,
            false,
        ),
    };
    let report = build_report(
        lang,
        cpg_path,
        reused_cache,
        &census,
        &project,
        started.elapsed(),
    );
    Ok((project, report))
}

/// One walk feeding both decisions: corpus size (build guardrail) and
/// newest source mtime (artifact freshness).
struct SourceCensus {
    files: usize,
    newest_mtime: Option<SystemTime>,
}

fn source_census(scan_root: &Path, lang: &str) -> SourceCensus {
    let exts = extensions_for(lang);
    let excludes = build_excludes(lang);
    let mut census = SourceCensus {
        files: 0,
        newest_mtime: None,
    };
    walk_sources(scan_root, exts, &excludes, &mut |path| {
        census.files += 1;
        if let Ok(mtime) = std::fs::metadata(path).and_then(|m| m.modified()) {
            if census.newest_mtime.is_none_or(|current| mtime > current) {
                census.newest_mtime = Some(mtime);
            }
        }
    });
    census
}

fn build_report(
    lang: &str,
    cpg_path: PathBuf,
    reused_cache: bool,
    census: &SourceCensus,
    project: &Project,
    elapsed: std::time::Duration,
) -> CpgBuildReport {
    CpgBuildReport {
        language: lang.to_string(),
        cpg_path,
        reused_cache,
        source_files: census.files,
        methods: project.cpg.methods().len(),
        calls: project.cpg.calls().len(),
        nodes: project.cpg.live_count(),
        duration_ms: elapsed.as_millis(),
    }
}

fn load_fresh(census: &SourceCensus, lang: &str, cpg_path: &Path) -> Option<Project> {
    let artifact_mtime = std::fs::metadata(cpg_path)
        .and_then(|m| m.modified())
        .ok()?;
    if census
        .newest_mtime
        .is_some_and(|source| source > artifact_mtime)
    {
        return None;
    }
    load_project(cpg_path, lang)
}

fn build_and_save(
    scan_root: &Path,
    lang: &str,
    cpg_path: &Path,
    census: &SourceCensus,
    limits: &BuildLimits,
) -> Result<Project, String> {
    if census.files > limits.max_source_files {
        return Err(format!(
            "refusing to build the {lang} graph: {} source files under {} exceed the build \
             cap of {} — scope the build to a subtree (targetSubdir / subdir) or raise \
             maxSourceFiles explicitly",
            census.files,
            scan_root.display(),
            limits.max_source_files
        ));
    }
    let excludes = build_excludes(lang);
    let project = cpg_cli::build_project_filtered(&scan_root.to_string_lossy(), lang, &excludes)?;
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
        assert_eq!(first.source_files, 1);

        let (_, second) = ensure_project(temp.path(), "go").unwrap();
        assert!(second.reused_cache);
        assert_eq!(second.methods, first.methods);
    }

    #[test]
    fn open_project_in_loads_a_stale_graph_without_rebuilding() {
        let temp = tempfile::tempdir().unwrap();
        write_go_fixture(temp.path());
        let scope = BuildScope::whole(temp.path());
        let (_, built) = ensure_project_in(&scope, "go", &BuildLimits::default()).unwrap();
        assert!(!built.reused_cache);
        let mtime = std::fs::metadata(&built.cpg_path)
            .and_then(|m| m.modified())
            .unwrap();

        // Make the source newer than the artifact.
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        let file = std::fs::File::options()
            .append(true)
            .open(temp.path().join("main.go"))
            .unwrap();
        file.set_modified(future).unwrap();
        drop(file);

        // Load-only: the stale graph is served as-is; the artifact is not
        // rebuilt (mtime unchanged), unlike `ensure_project_in`.
        let project = open_project_in(&scope, "go").expect("stale graph must still load");
        assert!(project.cpg.methods().len() >= 2);
        let mtime2 = std::fs::metadata(&built.cpg_path)
            .and_then(|m| m.modified())
            .unwrap();
        assert_eq!(mtime, mtime2, "open_project_in must not rebuild");
    }

    #[test]
    fn open_project_in_returns_none_without_an_artifact() {
        let temp = tempfile::tempdir().unwrap();
        write_go_fixture(temp.path());
        assert!(open_project_in(&BuildScope::whole(temp.path()), "go").is_none());
    }

    #[test]
    fn open_project_in_returns_none_on_a_corrupt_artifact_without_panicking() {
        // A truncated/garbage graph must degrade to `None` (the caller's Failed
        // readiness), never PANIC and abort the audit thread. `Cpg::load` can
        // panic on a malformed artifact; the decode guard turns that into `None`.
        let temp = tempfile::tempdir().unwrap();
        write_go_fixture(temp.path());
        let scope = BuildScope::whole(temp.path());
        let artifact = scope.artifact_path("go");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        std::fs::write(&artifact, b"not a real cpg-rs graph \x00\x01\x02 truncated").unwrap();

        // Silence the caught-panic backtrace noise this deliberately triggers.
        let prior = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let loaded = open_project_in(&scope, "go");
        std::panic::set_hook(prior);

        assert!(
            loaded.is_none(),
            "a corrupt artifact must not load a project"
        );
        // `validate_graph_artifact` (the reference guard) agrees it is invalid.
        assert!(validate_graph_artifact(&artifact).is_err());
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

    #[test]
    fn oversized_corpus_is_refused_with_an_actionable_error() {
        let temp = tempfile::tempdir().unwrap();
        write_go_fixture(temp.path());
        std::fs::write(temp.path().join("second.go"), "package main\n").unwrap();

        let limits = BuildLimits {
            max_source_files: 1,
        };
        let error = ensure_project_in(&BuildScope::whole(temp.path()), "go", &limits)
            .err()
            .expect("2 files over a 1-file cap must refuse");
        assert!(error.contains("build cap"), "{error}");
        assert!(error.contains("targetSubdir"), "{error}");
        // The refusal must not leave a partial artifact behind.
        assert!(!BuildScope::whole(temp.path()).artifact_path("go").exists());
    }

    #[test]
    fn fresh_artifacts_load_even_when_the_corpus_exceeds_the_cap() {
        let temp = tempfile::tempdir().unwrap();
        write_go_fixture(temp.path());
        ensure_project(temp.path(), "go").unwrap();

        let limits = BuildLimits {
            max_source_files: 0,
        };
        let (_, report) =
            ensure_project_in(&BuildScope::whole(temp.path()), "go", &limits).unwrap();
        assert!(
            report.reused_cache,
            "loading a fresh graph is never limited"
        );
    }

    #[test]
    fn subtree_scope_keeps_artifacts_under_the_workspace_root() {
        let temp = tempfile::tempdir().unwrap();
        let subtree = temp.path().join("svc");
        std::fs::create_dir_all(&subtree).unwrap();
        write_go_fixture(&subtree);

        let scope = BuildScope::subtree(temp.path(), Path::new("svc")).unwrap();
        let (_, report) = ensure_project_in(&scope, "go", &BuildLimits::default()).unwrap();

        assert!(report.cpg_path.exists());
        assert!(
            report
                .cpg_path
                .starts_with(temp.path().join(".kuzushi/cpg-rs/scoped/svc")),
            "got {}",
            report.cpg_path.display()
        );
        assert!(
            !subtree.join(".kuzushi").exists(),
            "a scoped build must never write inside the scanned subtree"
        );

        let (_, second) = ensure_project_in(&scope, "go", &BuildLimits::default()).unwrap();
        assert!(second.reused_cache);
    }

    #[test]
    fn subtree_scope_rejects_traversal_and_absolute_paths() {
        let root = Path::new("/repo");
        assert!(BuildScope::subtree(root, Path::new("../out")).is_err());
        assert!(BuildScope::subtree(root, Path::new("/etc")).is_err());
        assert!(BuildScope::subtree(root, Path::new("")).is_err());
        assert!(BuildScope::subtree(root, Path::new("a/b")).is_ok());
    }
}
