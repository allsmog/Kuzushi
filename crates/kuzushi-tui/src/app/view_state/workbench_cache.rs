use super::*;
use finding_alias_cache::FindingAliasCache;
use kuzushi_core::{
    list_run_summaries, Finding, NestedProjectScopeTree, PromptMutation, RunSummary,
    RunTargetGitMetadata, StrategyProposal, WorkspaceTarget,
};
use map_artifacts_cache::MapArtifactsCache;
use prompt_override_cache::PromptOverrideCache;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

mod finding_alias_cache;
mod map_artifacts_cache;
mod prompt_override_cache;

const GIT_METADATA_TTL: Duration = Duration::from_secs(2);
const SCOPE_TREE_TTL: Duration = Duration::from_secs(2);

#[derive(Debug, Default)]
pub(crate) struct WorkbenchCache {
    target_base: Option<TargetBaseCache>,
    run_summaries: Option<RunSummaryCache>,
    source_file: Option<SourceFileCache>,
    git_metadata: Option<GitMetadataCache>,
    scope_tree: Option<ScopeTreeCache>,
    strategy_queue: Option<StrategyQueueCache>,
    prompt_mutations: Option<PromptMutationsCache>,
    json_files: BTreeMap<PathBuf, JsonFileCache>,
    map_artifacts: MapArtifactsCache,
    prompt_overrides: PromptOverrideCache,
    finding_aliases: FindingAliasCache,
}

impl WorkbenchCache {
    pub(crate) fn target_base(&mut self, target: Option<&Path>) -> Option<String> {
        let target = target?;
        if let Some(cache) = self
            .target_base
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return Some(cache.base.clone());
        }
        let base = canonical_target_base(target);
        self.target_base = Some(TargetBaseCache {
            target: target.to_path_buf(),
            base: base.clone(),
        });
        Some(base)
    }

    pub(crate) fn run_summary_index(
        &mut self,
        target: Option<&Path>,
        scan_ids: Vec<String>,
    ) -> BTreeMap<String, RunSummary> {
        let Some(target) = target else {
            return BTreeMap::new();
        };
        let key = RunSummaryCacheKey {
            target: target.to_path_buf(),
            scan_ids,
        };
        if let Some(cache) = self.run_summaries.as_ref().filter(|cache| cache.key == key) {
            return cache.summaries.clone();
        }
        let summaries = run_summary_index_for_target(target);
        self.run_summaries = Some(RunSummaryCache {
            key,
            summaries: summaries.clone(),
        });
        summaries
    }

    pub(crate) fn read_source_file(&mut self, path: &Path) -> Result<String, String> {
        let stamp = source_file_stamp(path).map_err(|error| error.to_string())?;
        if let Some(cache) = self
            .source_file
            .as_ref()
            .filter(|cache| cache.path == path && cache.stamp == stamp)
        {
            return Ok(cache.contents.clone());
        }
        let contents = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
        self.source_file = Some(SourceFileCache {
            path: path.to_path_buf(),
            stamp,
            contents: contents.clone(),
        });
        Ok(contents)
    }

    pub(crate) fn git_metadata(&mut self, target: Option<&Path>) -> Option<RunTargetGitMetadata> {
        let target = target?;
        let now = Instant::now();
        if let Some(cache) = self
            .git_metadata
            .as_ref()
            .filter(|cache| cache.target == target && cache.fresh_at(now))
        {
            return cache.metadata.clone();
        }
        let metadata = kuzushi_core::workspace::target_git_metadata(target);
        self.git_metadata = Some(GitMetadataCache {
            target: target.to_path_buf(),
            cached_at: now,
            metadata: metadata.clone(),
        });
        metadata
    }

    pub(crate) fn project_scope_tree(
        &mut self,
        target: Option<&Path>,
    ) -> Option<ProjectScopeTreeState> {
        let target = target?;
        let now = Instant::now();
        if let Some(cache) = self
            .scope_tree
            .as_ref()
            .filter(|cache| cache.target == target && cache.fresh_at(now))
        {
            return Some(cache.state.clone());
        }
        let state = project_scope_tree_for_target(target);
        self.scope_tree = Some(ScopeTreeCache {
            target: target.to_path_buf(),
            cached_at: now,
            state: state.clone(),
        });
        Some(state)
    }

    pub(crate) fn strategy_queue(
        &mut self,
        workspace: Option<&WorkspaceTarget>,
    ) -> Option<StrategyQueueState> {
        let workspace = workspace?;
        let target = workspace.root();
        let path = kuzushi_core::strategy_queue_path(workspace);
        let stamp = source_file_stamp(&path).ok();
        if let Some(cache) = self
            .strategy_queue
            .as_ref()
            .filter(|cache| cache.target == target && cache.stamp == stamp)
        {
            return Some(cache.state.clone());
        }
        let state = match kuzushi_core::load_strategy_queue(workspace) {
            Ok(proposals) => StrategyQueueState::Ready(proposals),
            Err(error) => StrategyQueueState::Unreadable(error.to_string()),
        };
        self.strategy_queue = Some(StrategyQueueCache {
            target: target.to_path_buf(),
            stamp,
            state: state.clone(),
        });
        Some(state)
    }

    pub(crate) fn invalidate_strategy_queue(&mut self) {
        self.strategy_queue = None;
    }

    pub(crate) fn prompt_mutations(
        &mut self,
        workspace: Option<&WorkspaceTarget>,
    ) -> Option<PromptMutationsState> {
        let workspace = workspace?;
        let target = workspace.root();
        let path = kuzushi_core::prompt_mutations_path(workspace);
        let stamp = source_file_stamp(&path).ok();
        if let Some(cache) = self
            .prompt_mutations
            .as_ref()
            .filter(|cache| cache.target == target && cache.stamp == stamp)
        {
            return Some(cache.state.clone());
        }
        let state = match kuzushi_core::load_prompt_mutations(workspace) {
            Ok(mutations) => PromptMutationsState::Ready(mutations),
            Err(_) => PromptMutationsState::Unreadable,
        };
        self.prompt_mutations = Some(PromptMutationsCache {
            target: target.to_path_buf(),
            stamp,
            state: state.clone(),
        });
        Some(state)
    }

    pub(crate) fn invalidate_prompt_mutations(&mut self) {
        self.prompt_mutations = None;
    }

    pub(crate) fn json_file(&mut self, path: &Path) -> JsonFileState {
        let stamp = source_file_stamp(path).ok();
        if let Some(cache) = self
            .json_files
            .get(path)
            .filter(|cache| cache.stamp == stamp)
        {
            return cache.state.clone();
        }
        let state = read_json_file(path);
        self.json_files.insert(
            path.to_path_buf(),
            JsonFileCache {
                stamp,
                state: state.clone(),
            },
        );
        state
    }

    pub(crate) fn map_artifacts_built(&mut self, target: Option<&Path>) -> bool {
        self.map_artifacts.built(target)
    }

    pub(crate) fn invalidate_map_artifacts(&mut self) {
        self.map_artifacts.invalidate();
    }

    pub(crate) fn prompt_override_hash(&mut self, path: &Path) -> Result<Option<String>, String> {
        self.prompt_overrides.hash(path)
    }

    pub(crate) fn sorted_finding_alias_indices(
        &mut self,
        findings: &[Finding],
    ) -> Vec<(String, usize)> {
        self.finding_aliases.sorted_indices(findings)
    }
}

fn canonical_target_base(target: &Path) -> String {
    target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn run_summary_index_for_target(target: &Path) -> BTreeMap<String, RunSummary> {
    list_run_summaries(target)
        .unwrap_or_default()
        .into_iter()
        .map(|summary| (summary.run_id.clone(), summary))
        .collect()
}

fn project_scope_tree_for_target(target: &Path) -> ProjectScopeTreeState {
    match kuzushi_core::load_nested_project_scopes(target) {
        Ok(Some(tree)) => ProjectScopeTreeState::Persisted(tree),
        Ok(None) => discovered_project_scope_tree(target),
        Err(error) => ProjectScopeTreeState::Unreadable(error.to_string()),
    }
}

fn discovered_project_scope_tree(target: &Path) -> ProjectScopeTreeState {
    let tree = kuzushi_core::discover_nested_project_scopes(target);
    if tree.scopes.len() > 1 {
        ProjectScopeTreeState::Discovered(tree)
    } else {
        ProjectScopeTreeState::RootOnly
    }
}

fn read_json_file(path: &Path) -> JsonFileState {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return JsonFileState::NonFile,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return JsonFileState::Missing;
        }
        Err(_) => return JsonFileState::Unreadable,
    };
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => return JsonFileState::Unreadable,
    };
    serde_json::from_str::<serde_json::Value>(&raw)
        .map(JsonFileState::Present)
        .unwrap_or(JsonFileState::Malformed)
}

fn source_file_stamp(path: &Path) -> std::io::Result<SourceFileStamp> {
    let metadata = std::fs::metadata(path)?;
    Ok(SourceFileStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProjectScopeTreeState {
    Persisted(NestedProjectScopeTree),
    Discovered(NestedProjectScopeTree),
    RootOnly,
    Unreadable(String),
}

#[derive(Debug, Clone)]
pub(crate) enum StrategyQueueState {
    Ready(Vec<StrategyProposal>),
    Unreadable(String),
}

#[derive(Debug, Clone)]
pub(crate) enum PromptMutationsState {
    Ready(Vec<PromptMutation>),
    Unreadable,
}

#[derive(Debug, Clone)]
pub(crate) enum JsonFileState {
    Present(serde_json::Value),
    Missing,
    NonFile,
    Malformed,
    Unreadable,
}

#[derive(Debug)]
struct TargetBaseCache {
    target: PathBuf,
    base: String,
}

#[derive(Debug)]
struct RunSummaryCache {
    key: RunSummaryCacheKey,
    summaries: BTreeMap<String, RunSummary>,
}

#[derive(Debug, PartialEq, Eq)]
struct RunSummaryCacheKey {
    target: PathBuf,
    scan_ids: Vec<String>,
}

#[derive(Debug)]
struct SourceFileCache {
    path: PathBuf,
    stamp: SourceFileStamp,
    contents: String,
}

#[derive(Debug)]
struct GitMetadataCache {
    target: PathBuf,
    cached_at: Instant,
    metadata: Option<RunTargetGitMetadata>,
}

#[derive(Debug)]
struct ScopeTreeCache {
    target: PathBuf,
    cached_at: Instant,
    state: ProjectScopeTreeState,
}

#[derive(Debug)]
struct StrategyQueueCache {
    target: PathBuf,
    stamp: Option<SourceFileStamp>,
    state: StrategyQueueState,
}

#[derive(Debug)]
struct PromptMutationsCache {
    target: PathBuf,
    stamp: Option<SourceFileStamp>,
    state: PromptMutationsState,
}

#[derive(Debug)]
struct JsonFileCache {
    stamp: Option<SourceFileStamp>,
    state: JsonFileState,
}

impl GitMetadataCache {
    fn fresh_at(&self, now: Instant) -> bool {
        now.duration_since(self.cached_at) <= GIT_METADATA_TTL
    }
}

impl ScopeTreeCache {
    fn fresh_at(&self, now: Instant) -> bool {
        now.duration_since(self.cached_at) <= SCOPE_TREE_TTL
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceFileStamp {
    len: u64,
    modified: Option<SystemTime>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::write_run_summary;

    #[test]
    fn source_file_cache_refreshes_when_size_changes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("src.rs");
        std::fs::write(&path, "one").unwrap();
        let mut cache = WorkbenchCache::default();

        assert_eq!(cache.read_source_file(&path).unwrap(), "one");
        std::fs::write(&path, "two lines").unwrap();

        assert_eq!(cache.read_source_file(&path).unwrap(), "two lines");
    }

    #[test]
    fn run_summary_cache_refreshes_when_scan_ids_change() {
        let temp = tempfile::tempdir().unwrap();
        let mut cache = WorkbenchCache::default();
        assert!(cache
            .run_summary_index(Some(temp.path()), Vec::new())
            .is_empty());

        let summary = RunSummary::running("scan-a", "scan", None, "target");
        write_run_summary(temp.path(), &summary).unwrap();

        let indexed = cache.run_summary_index(Some(temp.path()), vec!["scan-a".to_string()]);
        assert!(indexed.contains_key("scan-a"));
    }
}
