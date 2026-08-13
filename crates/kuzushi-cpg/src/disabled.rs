//! Engine-disabled compile surface for `kuzushi-cpg`.
//!
//! This module intentionally does not emulate the engine. It keeps the
//! adapter's public types available so `kuzushi-core` can be checked in a clean
//! environment, while every engine operation fails closed and every readiness
//! probe reports unavailable.

use std::path::{Component, Path, PathBuf};

pub const GRAPH_SHAPE_VERSION: u32 = 0;
pub const DEFAULT_MAX_SOURCE_FILES: usize = 25_000;
pub const MAX_HARVESTED_NAMES: usize = 200;
pub const MAX_FLOWS_PER_QUERY: usize = 25;

fn unavailable() -> String {
    crate::engine_unavailable_message().to_string()
}

/// Opaque engine handle retained only for API compatibility.
///
/// The private field deliberately prevents callers from manufacturing a
/// validation-only `Project` and obtaining an empty, success-shaped taint
/// result. The only engine entry points that could return one refuse below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    _private: (),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Step {
    pub code: String,
    pub line: Option<u32>,
    pub depth: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Finding {
    pub method: String,
    pub sink: String,
    pub sink_file: Option<String>,
    pub sink_line: Option<u32>,
    pub origin: String,
    pub guard: Option<String>,
    pub authz: Option<String>,
    pub path: Vec<Step>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildScope {
    root: PathBuf,
    subdir: Option<PathBuf>,
}

impl BuildScope {
    pub fn whole(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            subdir: None,
        }
    }

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

    pub fn scan_root(&self) -> PathBuf {
        match &self.subdir {
            Some(subdir) => self.root.join(subdir),
            None => self.root.clone(),
        }
    }

    pub fn artifact_path(&self, lang: &str) -> PathBuf {
        scoped_artifact_path(&self.root, self.subdir.as_deref(), lang)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpgBuildReport {
    pub language: String,
    pub cpg_path: PathBuf,
    pub reused_cache: bool,
    pub source_files: usize,
    pub methods: usize,
    pub calls: usize,
    pub nodes: usize,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Copy)]
pub struct SignalSpec<'a> {
    pub sources: &'a [String],
    pub sinks: &'a [String],
    pub sanitizers: &'a [String],
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HarvestedSpec {
    pub source_names: Vec<String>,
    pub sink_names: Vec<String>,
    pub sanitizer_names: Vec<String>,
    pub source_idents: Vec<String>,
    pub entry_methods: Vec<String>,
    pub source_call_matches: usize,
    pub sink_call_matches: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpgFlowQueryStats {
    pub source_names: usize,
    pub sink_names: usize,
    pub source_call_matches: usize,
    pub sink_call_matches: usize,
    pub flow_count: usize,
}

pub fn artifact_dir(target: &Path) -> PathBuf {
    target.join(".kuzushi").join("cpg-rs")
}

pub fn artifact_path(target: &Path, lang: &str) -> PathBuf {
    artifact_dir(target).join(format!("{lang}.v{GRAPH_SHAPE_VERSION}.cpg"))
}

pub fn scoped_artifact_path(root: &Path, subdir: Option<&Path>, lang: &str) -> PathBuf {
    match subdir {
        None => artifact_path(root, lang),
        Some(subdir) => artifact_dir(root)
            .join("scoped")
            .join(scope_key(subdir))
            .join(format!("{lang}.v{GRAPH_SHAPE_VERSION}.cpg")),
    }
}

fn scope_key(subdir: &Path) -> String {
    subdir
        .to_string_lossy()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub fn has_artifacts(_target: &Path) -> bool {
    false
}

pub fn artifact_langs(_target: &Path) -> Vec<String> {
    Vec::new()
}

pub fn supported_languages() -> &'static [&'static str] {
    &[]
}

pub fn canonical_language(_lang: &str) -> Option<&'static str> {
    None
}

pub fn detect_buildable_languages(_dir: &Path) -> Vec<&'static str> {
    Vec::new()
}

pub fn validate_graph_artifact(_path: &Path) -> Result<(), String> {
    Err(unavailable())
}

pub fn ensure_project(_target: &Path, _lang: &str) -> Result<(Project, CpgBuildReport), String> {
    Err(unavailable())
}

pub fn ensure_project_in(
    _scope: &BuildScope,
    _lang: &str,
    _limits: &BuildLimits,
) -> Result<(Project, CpgBuildReport), String> {
    Err(unavailable())
}

pub fn open_project_in(_scope: &BuildScope, _lang: &str) -> Option<Project> {
    None
}

pub fn harvest_spec(_project: &Project, _signals: &SignalSpec<'_>) -> HarvestedSpec {
    HarvestedSpec::default()
}

pub fn harvest_regex_spec(
    _project: &Project,
    _source_pattern: &str,
    _sink_pattern: &str,
) -> HarvestedSpec {
    HarvestedSpec::default()
}

pub fn run_taint_query(
    _project: &Project,
    harvested: &HarvestedSpec,
) -> (Vec<Finding>, CpgFlowQueryStats) {
    (
        Vec::new(),
        CpgFlowQueryStats {
            source_names: harvested.source_names.len(),
            sink_names: harvested.sink_names.len(),
            source_call_matches: harvested.source_call_matches,
            sink_call_matches: harvested.sink_call_matches,
            flow_count: 0,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_disabled_adapter_never_claims_engine_or_artifact_readiness() {
        let temp = tempfile::tempdir().unwrap();
        let fake = artifact_dir(temp.path());
        std::fs::create_dir_all(&fake).unwrap();
        std::fs::write(fake.join("rust.v0.cpg"), b"CPG1").unwrap();

        assert!(!crate::engine_available());
        assert!(!has_artifacts(temp.path()));
        assert!(artifact_langs(temp.path()).is_empty());
        assert!(supported_languages().is_empty());
    }

    #[test]
    fn engine_disabled_adapter_fails_engine_operations_closed() {
        let temp = tempfile::tempdir().unwrap();
        let scope = BuildScope::whole(temp.path());
        let error = ensure_project_in(&scope, "rust", &BuildLimits::default()).unwrap_err();

        assert!(error.contains("not compiled"), "{error}");
        assert!(open_project_in(&scope, "rust").is_none());
        assert!(validate_graph_artifact(Path::new("graph.cpg")).is_err());
    }

    #[test]
    fn disabled_scope_keeps_artifact_paths_under_the_workspace() {
        let scope = BuildScope::subtree(Path::new("/repo"), Path::new("services/api")).unwrap();
        let path = scope.artifact_path("rust");

        assert_eq!(scope.scan_root(), PathBuf::from("/repo/services/api"));
        assert!(path.starts_with("/repo/.kuzushi/cpg-rs/scoped"));
    }
}
