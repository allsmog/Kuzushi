use super::*;
use crate::ui_view_models::{DfdModel, RiskByModule};
use cache_entries::{
    project_scope_tree_for_target, run_summary_index_from_entries, CompletionValuesCache,
    DirectoryListingCache, FileCompletionValuesCache, GitMetadataCache, JsonFileCache,
    LatestRunPointerCache, PathStateCache, ProjectModelDocumentCache, PromptMutationsCache,
    RunArtifactTextCache, RunSummaryEntriesCache, RunTraceCache, ScopeTreeCache, SourceFileCache,
    StrategyQueueCache, TargetBaseCache, TargetProfileCache,
};
#[cfg(test)]
use cache_entries::{read_json_file, RunSummaryCache, RunSummaryCacheKey};
use finding_alias_cache::FindingAliasCache;
use kuzushi_core::engagement::{ENGAGEMENT_DIR, HARNESS_FILE};
#[cfg(test)]
use kuzushi_core::LatestRunPointerIssue;
use kuzushi_core::{
    Finding, LatestRunPointerState, NestedProjectScopeTree, RunSummary, RunSummaryEntry,
    RunTargetGitMetadata,
};
use map_artifacts_cache::MapArtifactsCache;
use prompt_override_cache::PromptOverrideCache;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use view_model_fragments::ViewModelFragmentCache;

mod cache_entries;
mod completion_values;
mod finding_alias_cache;
mod hydrated_reads;
mod hydration_state;
mod map_artifacts_cache;
mod prompt_override_cache;
#[cfg(test)]
mod tests;
mod view_model_fragments;
pub(crate) use cache_entries::{
    DirectoryListingState, JsonFileState, PathState, ProjectScopeTreeState, PromptMutationsState,
    RunTraceCacheState, StrategyQueueState,
};
pub(crate) use view_model_fragments::{
    DfdModelCacheKey, ReviewQueueCacheKey, RiskByModuleCacheKey, VisibleFindingProjection,
    VisibleFindingsCacheKey,
};

#[derive(Debug, Default)]
pub(crate) struct WorkbenchCache {
    target_base: Option<TargetBaseCache>,
    target_profile: Option<TargetProfileCache>,
    #[cfg(test)]
    run_summaries: Option<RunSummaryCache>,
    run_summary_entries: Option<RunSummaryEntriesCache>,
    file_completion_values: Option<FileCompletionValuesCache>,
    finding_completion_values: Option<CompletionValuesCache>,
    run_id_completion_values: Option<CompletionValuesCache>,
    completion_generation: u64,
    command_provider_generation: u64,
    #[cfg(test)]
    completion_source_reads: std::cell::Cell<usize>,
    latest_run_pointer: Option<LatestRunPointerCache>,
    source_file: Option<SourceFileCache>,
    git_metadata: Option<GitMetadataCache>,
    scope_tree: Option<ScopeTreeCache>,
    project_model_document: Option<ProjectModelDocumentCache>,
    strategy_queue: Option<StrategyQueueCache>,
    prompt_mutations: Option<PromptMutationsCache>,
    harness_file: Option<HarnessFileCache>,
    json_files: BTreeMap<PathBuf, JsonFileCache>,
    path_states: BTreeMap<PathBuf, PathStateCache>,
    directory_listings: BTreeMap<PathBuf, DirectoryListingCache>,
    run_traces: BTreeMap<(PathBuf, String), RunTraceCache>,
    run_artifact_texts: BTreeMap<(PathBuf, String, String), RunArtifactTextCache>,
    map_artifacts: MapArtifactsCache,
    prompt_overrides: PromptOverrideCache,
    health_checks: BTreeMap<String, ViewHealthChecks>,
    finding_aliases: FindingAliasCache,
    view_models: ViewModelFragmentCache,
    hydrating_view_data: BTreeSet<(PathBuf, ViewHydrationKey)>,
}

impl WorkbenchCache {
    pub(crate) fn cached_latest_run_pointer(
        &self,
        target: Option<&Path>,
    ) -> ViewDataState<LatestRunPointerState> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some(cache) = self
            .latest_run_pointer
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return ViewDataState::Ready(cache.state.clone());
        }
        self.loading_state(target, &ViewHydrationKey::LatestRunPointer)
    }

    pub(crate) fn cached_run_artifact_text(
        &self,
        target: &Path,
        run_id: &str,
        leaf: &str,
    ) -> ViewDataState<kuzushi_core::RunArtifactTextRead> {
        let map_key = (target.to_path_buf(), run_id.to_string(), leaf.to_string());
        if let Some(cache) = self.run_artifact_texts.get(&map_key) {
            return ViewDataState::Ready(cache.state.clone());
        }
        self.loading_state(
            target,
            &ViewHydrationKey::RunArtifactText {
                run_id: run_id.to_string(),
                leaf: leaf.to_string(),
            },
        )
    }

    pub(crate) fn cached_run_artifact_json(
        &self,
        target: &Path,
        run_id: &str,
        leaf: &str,
    ) -> ViewDataState<JsonFileState> {
        match self.cached_run_artifact_text(target, run_id, leaf) {
            ViewDataState::NotRequested => ViewDataState::NotRequested,
            ViewDataState::Loading => ViewDataState::Loading,
            ViewDataState::Ready(kuzushi_core::RunArtifactRead::Ready { value, .. }) => {
                ViewDataState::Ready(
                    serde_json::from_str(&value)
                        .map(JsonFileState::Present)
                        .unwrap_or(JsonFileState::Malformed),
                )
            }
            ViewDataState::Ready(kuzushi_core::RunArtifactRead::Missing { .. }) => {
                ViewDataState::Ready(JsonFileState::Missing)
            }
            ViewDataState::Ready(kuzushi_core::RunArtifactRead::NonFile { .. }) => {
                ViewDataState::Ready(JsonFileState::NonFile)
            }
            ViewDataState::Ready(kuzushi_core::RunArtifactRead::Unsafe { .. })
            | ViewDataState::Ready(kuzushi_core::RunArtifactRead::Unreadable { .. }) => {
                ViewDataState::Ready(JsonFileState::Unreadable)
            }
        }
    }

    pub(crate) fn cached_run_trace(
        &self,
        target: &Path,
        run_id: &str,
    ) -> ViewDataState<RunTraceCacheState> {
        let map_key = (target.to_path_buf(), run_id.to_string());
        if let Some(cache) = self.run_traces.get(&map_key) {
            return ViewDataState::Ready(cache.state.clone());
        }
        self.loading_state(
            target,
            &ViewHydrationKey::RunTrace {
                run_id: run_id.to_string(),
            },
        )
    }

    pub(crate) fn cached_map_artifacts_built(&self, target: Option<&Path>) -> ViewDataState<bool> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some(built) = self.map_artifacts.cached(target) {
            return ViewDataState::Ready(built);
        }
        self.loading_state(target, &ViewHydrationKey::MapArtifacts)
    }

    pub(crate) fn cached_target_base(&self, target: Option<&Path>) -> ViewDataState<String> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some(cache) = self
            .target_base
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return ViewDataState::Ready(cache.base.clone());
        }
        self.loading_state(target, &ViewHydrationKey::TargetBase)
    }

    fn loading_state<T>(&self, target: &Path, key: &ViewHydrationKey) -> ViewDataState<T> {
        if self
            .hydrating_view_data
            .contains(&(target.to_path_buf(), key.clone()))
        {
            ViewDataState::Loading
        } else {
            ViewDataState::NotRequested
        }
    }

    pub(crate) fn invalidate_run_summaries(&mut self) {
        self.invalidate_run_summary_dependents();
        self.run_summary_entries = None;
        self.latest_run_pointer = None;
        self.run_id_completion_values = None;
        self.bump_completion_generation();
    }

    #[cfg(test)]
    pub(crate) fn latest_run_pointer(&mut self, target: Option<&Path>) -> LatestRunPointerState {
        let Some(target) = target else {
            return LatestRunPointerState::Missing;
        };
        if let Some(cache) = self
            .latest_run_pointer
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return cache.state.clone();
        }
        let state = kuzushi_core::read_latest_run_pointer(target).unwrap_or_else(|error| {
            LatestRunPointerState::Invalid(LatestRunPointerIssue::UnsafePath(error.to_string()))
        });
        self.latest_run_pointer = Some(LatestRunPointerCache {
            target: target.to_path_buf(),
            state: state.clone(),
        });
        state
    }

    #[cfg(test)]
    pub(crate) fn run_summary_entries(&mut self, target: Option<&Path>) -> Vec<RunSummaryEntry> {
        let Some(target) = target else {
            return Vec::new();
        };
        if let Some(cache) = self
            .run_summary_entries
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return match &cache.state {
                RunSummaryEntriesState::Ready(entries) => entries.clone(),
                RunSummaryEntriesState::Failed(_) => Vec::new(),
            };
        }
        let entries =
            kuzushi_core::list_recent_run_summary_entries(target, 100).unwrap_or_default();
        self.run_summary_entries = Some(RunSummaryEntriesCache {
            target: target.to_path_buf(),
            state: RunSummaryEntriesState::Ready(entries.clone()),
        });
        self.invalidate_run_summary_dependents();
        entries
    }

    #[cfg(test)]
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
        let entries = self.run_summary_entries(Some(target));
        let summaries = run_summary_index_from_entries(&entries);
        self.run_summaries = Some(RunSummaryCache {
            key,
            summaries: summaries.clone(),
        });
        summaries
    }

    #[cfg(test)]
    pub(crate) fn read_source_file(&mut self, path: &Path) -> Result<String, String> {
        if let Some(cache) = self.source_file.as_ref().filter(|cache| cache.path == path) {
            return cache.state.clone();
        }
        let state = std::fs::read_to_string(path).map_err(|error| error.to_string());
        self.source_file = Some(SourceFileCache {
            path: path.to_path_buf(),
            state: state.clone(),
        });
        state
    }

    pub(crate) fn git_metadata(&mut self, target: Option<&Path>) -> Option<RunTargetGitMetadata> {
        let target = target?;
        if let Some(cache) = self
            .git_metadata
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return cache.metadata.clone();
        }
        let metadata = kuzushi_core::workspace::target_git_metadata(target);
        self.git_metadata = Some(GitMetadataCache {
            target: target.to_path_buf(),
            metadata: metadata.clone(),
        });
        metadata
    }

    pub(crate) fn invalidate_workspace_files(&mut self) {
        self.source_file = None;
        self.git_metadata = None;
        self.scope_tree = None;
        self.project_model_document = None;
        self.strategy_queue = None;
        self.prompt_mutations = None;
        self.harness_file = None;
        self.json_files.clear();
        self.path_states.clear();
        self.directory_listings.clear();
        self.file_completion_values = None;
        self.bump_completion_generation();
        self.run_traces.clear();
        self.run_artifact_texts.clear();
        self.map_artifacts.invalidate();
        self.prompt_overrides.invalidate();
        self.health_checks.clear();
        self.clear_view_hydration_loading();
    }

    pub(crate) fn invalidate_json_file(&mut self, path: &Path) {
        self.json_files.remove(path);
    }

    pub(crate) fn invalidate_state_artifact_paths(
        &mut self,
        target: &Path,
        relative_paths: &[PathBuf],
    ) -> (bool, bool) {
        let roots = StateArtifactRoots::new(target);
        let mut findings_changed = false;
        let mut run_summaries_changed = false;
        for relative in relative_paths {
            let changed = self.invalidate_state_artifact_path(&roots, relative);
            findings_changed |= changed.0;
            run_summaries_changed |= changed.1;
        }
        if run_summaries_changed {
            self.invalidate_run_summary_dependents();
            self.run_summary_entries = None;
            self.latest_run_pointer = None;
            self.run_id_completion_values = None;
        }
        if findings_changed {
            self.finding_completion_values = None;
        }
        self.bump_completion_generation_when(findings_changed | run_summaries_changed);
        self.strategy_queue = None;
        self.prompt_mutations = None;
        self.project_model_document = None;
        (findings_changed, run_summaries_changed)
    }

    #[cfg(test)]
    fn invalidate_legacy_run_summary_index(&mut self) {
        self.run_summaries = None;
    }

    #[cfg(not(test))]
    fn invalidate_legacy_run_summary_index(&mut self) {}

    fn invalidate_run_summary_dependents(&mut self) {
        self.invalidate_legacy_run_summary_index();
        self.view_models.invalidate_visible_findings();
    }

    fn invalidate_state_artifact_path(
        &mut self,
        roots: &StateArtifactRoots<'_>,
        relative: &Path,
    ) -> (bool, bool) {
        let path = roots.target.join(relative);
        let broad = path == roots.state;
        self.invalidate_named_artifact(relative);
        self.invalidate_path_caches(&path, &roots.state, broad);
        self.invalidate_run_caches(roots, &path, broad);
        state_change_flags(roots, &path, broad)
    }

    fn invalidate_named_artifact(&mut self, relative: &Path) {
        if is_project_scope_tree_path(relative) {
            self.scope_tree = None;
        }
        if is_map_artifact_path(relative) {
            self.map_artifacts.invalidate();
        }
    }

    fn invalidate_path_caches(&mut self, path: &Path, state_root: &Path, broad: bool) {
        self.json_files.remove(path);
        self.path_states.remove(path);
        if let Some(parent) = path.parent() {
            self.directory_listings.remove(parent);
        }
        if broad {
            self.invalidate_state_root(state_root);
        }
    }

    fn invalidate_run_caches(&mut self, roots: &StateArtifactRoots<'_>, path: &Path, broad: bool) {
        invalidate_cached_trace(
            &mut self.run_traces,
            roots.target,
            &roots.runs,
            &path,
            broad,
        );
        invalidate_cached_run_artifact_text(
            &mut self.run_artifact_texts,
            roots.target,
            &roots.runs,
            &path,
            broad,
        );
    }

    fn invalidate_state_root(&mut self, state_root: &Path) {
        self.json_files
            .retain(|cached, _| !cached.starts_with(state_root));
        self.path_states
            .retain(|cached, _| !cached.starts_with(state_root));
        self.directory_listings
            .retain(|cached, _| !cached.starts_with(state_root));
        self.map_artifacts.invalidate();
    }

    pub(crate) fn project_scope_tree(
        &mut self,
        target: Option<&Path>,
    ) -> Option<ProjectScopeTreeState> {
        let target = target?;
        if let Some(cache) = self
            .scope_tree
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return Some(cache.state.clone());
        }
        let state = project_scope_tree_for_target(target);
        self.scope_tree = Some(ScopeTreeCache {
            target: target.to_path_buf(),
            state: state.clone(),
        });
        Some(state)
    }

    pub(crate) fn cache_persisted_project_scope_tree(
        &mut self,
        target: &Path,
        tree: NestedProjectScopeTree,
    ) {
        self.scope_tree = Some(ScopeTreeCache {
            target: target.to_path_buf(),
            state: ProjectScopeTreeState::Persisted(tree),
        });
    }

    pub(crate) fn invalidate_strategy_queue(&mut self) {
        self.strategy_queue = None;
    }

    pub(crate) fn invalidate_prompt_mutations(&mut self) {
        self.prompt_mutations = None;
    }

    pub(crate) fn invalidate_prompt_overrides(&mut self) {
        self.prompt_overrides.invalidate();
    }

    /// Cached read of the engagement harness file
    /// (`<target>/engagement/harness.toml`); `None` when the target is unset
    /// or the harness file is missing/unreadable.
    #[cfg(test)]
    pub(crate) fn harness_file(&mut self, target: Option<&Path>) -> Option<String> {
        let target = target?;
        let path = harness_file_path(target);
        if let Some(cache) = self
            .harness_file
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return cache.contents.clone();
        }
        let contents = std::fs::read_to_string(&path).ok();
        self.harness_file = Some(HarnessFileCache {
            target: target.to_path_buf(),
            contents: contents.clone(),
        });
        contents
    }

    #[cfg(test)]
    pub(crate) fn json_file(&mut self, path: &Path) -> JsonFileState {
        if let Some(cache) = self.json_files.get(path) {
            return cache.state.clone();
        }
        let state = read_json_file(path);
        self.json_files.insert(
            path.to_path_buf(),
            JsonFileCache {
                state: state.clone(),
            },
        );
        state
    }

    #[cfg(test)]
    pub(crate) fn run_artifact_text(
        &mut self,
        target: &Path,
        run_id: &str,
        leaf: &str,
    ) -> kuzushi_core::RunArtifactTextRead {
        let key = (target.to_path_buf(), run_id.to_string(), leaf.to_string());
        if let Some(cache) = self.run_artifact_texts.get(&key) {
            return cache.state.clone();
        }
        let state = kuzushi_core::read_run_artifact_text(target, run_id, leaf);
        self.run_artifact_texts.insert(
            key,
            RunArtifactTextCache {
                state: state.clone(),
            },
        );
        state
    }

    pub(crate) fn invalidate_map_artifacts(&mut self) {
        self.map_artifacts.invalidate();
    }

    pub(crate) fn sorted_finding_alias_indices(
        &mut self,
        findings: &[Finding],
        findings_revision: u64,
    ) -> Vec<(String, usize)> {
        self.finding_aliases
            .sorted_indices(findings, findings_revision)
    }

    pub(crate) fn visible_findings(
        &self,
        key: &VisibleFindingsCacheKey,
    ) -> Option<Arc<[VisibleFindingProjection]>> {
        self.view_models.visible_findings(key)
    }

    pub(crate) fn cache_visible_findings(
        &mut self,
        key: VisibleFindingsCacheKey,
        projected: Arc<[VisibleFindingProjection]>,
    ) {
        self.view_models.cache_visible_findings(key, projected);
    }

    pub(crate) fn review_queue(
        &self,
        key: &ReviewQueueCacheKey,
    ) -> Option<(Arc<[crate::ui_view_models::ReviewQueueRow]>, usize, usize)> {
        self.view_models.review_queue(key)
    }

    pub(crate) fn cache_review_queue(
        &mut self,
        key: ReviewQueueCacheKey,
        rows: Arc<[crate::ui_view_models::ReviewQueueRow]>,
        open_count: usize,
        complete_count: usize,
    ) {
        self.view_models
            .cache_review_queue(key, rows, open_count, complete_count);
    }

    pub(crate) fn risk_by_module(&self, key: &RiskByModuleCacheKey) -> Option<RiskByModule> {
        self.view_models.risk_by_module(key)
    }

    pub(crate) fn cache_risk_by_module(&mut self, key: RiskByModuleCacheKey, risk: RiskByModule) {
        self.view_models.cache_risk_by_module(key, risk);
    }

    pub(crate) fn dfd_model(&self, key: &DfdModelCacheKey) -> Option<DfdModel> {
        self.view_models.dfd_model(key)
    }

    pub(crate) fn cache_dfd_model(&mut self, key: DfdModelCacheKey, model: DfdModel) {
        self.view_models.cache_dfd_model(key, model);
    }
}

pub(crate) fn harness_file_path(target: &Path) -> PathBuf {
    target.join(ENGAGEMENT_DIR).join(HARNESS_FILE)
}

struct StateArtifactRoots<'a> {
    target: &'a Path,
    state: PathBuf,
    runs: PathBuf,
    latest: PathBuf,
}

impl<'a> StateArtifactRoots<'a> {
    fn new(target: &'a Path) -> Self {
        Self {
            target,
            state: kuzushi_core::workspace_state_dir(target),
            runs: kuzushi_core::runs_root(target),
            latest: kuzushi_core::latest_run_path(target),
        }
    }
}

fn is_findings_store_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("index.sqlite3"))
}

fn state_change_flags(roots: &StateArtifactRoots<'_>, path: &Path, broad: bool) -> (bool, bool) {
    (
        broad || is_findings_store_path(path),
        broad || path == roots.latest || run_metadata_path_changed(path, &roots.runs),
    )
}

fn is_project_scope_tree_path(path: &Path) -> bool {
    path == Path::new(".kuzushi/v3/project-model/scopes.json")
}

fn is_map_artifact_path(path: &Path) -> bool {
    path.starts_with(".kuzushi/codeql-db")
        || matches!(
            path.to_str(),
            Some(
                ".kuzushi/context-snapshot.json"
                    | ".kuzushi/entry-points.json"
                    | ".kuzushi/threat-model.json"
                    | ".kuzushi/threat-model-pasta.json"
                    | ".kuzushi/cpg.bin"
                    | ".kuzushi/threat-intel/candidates.json"
            )
        )
}

fn run_metadata_path_changed(path: &Path, runs_root: &Path) -> bool {
    if path == runs_root {
        return true;
    }
    path.strip_prefix(runs_root).ok().is_some_and(|relative| {
        relative.components().count() <= 1
            || relative.file_name().is_some_and(|name| name == "run.json")
    })
}

fn invalidate_cached_trace(
    traces: &mut BTreeMap<(PathBuf, String), RunTraceCache>,
    target: &Path,
    runs_root: &Path,
    path: &Path,
    broad: bool,
) {
    if broad {
        traces.retain(|(cached_target, _), _| cached_target != target);
        return;
    }
    let Some(run_id) = path
        .strip_prefix(runs_root)
        .ok()
        .filter(|relative| {
            relative
                .file_name()
                .is_some_and(|name| name == "trace.jsonl")
        })
        .and_then(|relative| relative.components().next())
        .and_then(|component| component.as_os_str().to_str())
    else {
        return;
    };
    traces.remove(&(target.to_path_buf(), run_id.to_string()));
}

fn invalidate_cached_run_artifact_text(
    artifacts: &mut BTreeMap<(PathBuf, String, String), RunArtifactTextCache>,
    target: &Path,
    runs_root: &Path,
    path: &Path,
    broad: bool,
) {
    if broad {
        artifacts.retain(|(cached_target, _, _), _| cached_target != target);
        return;
    }
    let Some((run_id, leaf)) = run_artifact_identity(runs_root, path) else {
        return;
    };
    artifacts.remove(&(target.to_path_buf(), run_id.to_string(), leaf.to_string()));
}

fn run_artifact_identity<'a>(runs_root: &Path, path: &'a Path) -> Option<(&'a str, &'a str)> {
    let mut components = path.strip_prefix(runs_root).ok()?.components();
    let run_id = components.next()?.as_os_str().to_str()?;
    let leaf = components.next()?.as_os_str().to_str()?;
    (components.next().is_none()).then_some((run_id, leaf))
}

#[derive(Debug)]
struct HarnessFileCache {
    target: PathBuf,
    contents: Option<String>,
}
