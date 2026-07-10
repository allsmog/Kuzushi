use super::*;
use crate::ui_view_models::{DfdModel, RiskByModule};
use cache_entries::{
    canonical_target_base, project_scope_tree_for_target, read_json_file,
    run_summary_index_for_target, source_file_stamp, GitMetadataCache, JsonFileCache,
    PromptMutationsCache, RunSummaryCache, RunSummaryCacheKey, ScopeTreeCache, SourceFileCache,
    SourceFileStamp, StrategyQueueCache, TargetBaseCache,
};
use finding_alias_cache::FindingAliasCache;
use kuzushi_core::engagement::{ENGAGEMENT_DIR, HARNESS_FILE};
use kuzushi_core::{
    Finding, NestedProjectScopeTree, RunSummary, RunTargetGitMetadata, WorkspaceTarget,
};
use map_artifacts_cache::MapArtifactsCache;
use prompt_override_cache::PromptOverrideCache;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;
use view_model_fragments::ViewModelFragmentCache;

mod cache_entries;
mod finding_alias_cache;
mod map_artifacts_cache;
mod prompt_override_cache;
#[cfg(test)]
mod tests;
mod view_model_fragments;
pub(crate) use cache_entries::{
    JsonFileState, ProjectScopeTreeState, PromptMutationsState, StrategyQueueState,
};
pub(crate) use view_model_fragments::{
    DfdModelCacheKey, RiskByModuleCacheKey, VisibleFindingProjection, VisibleFindingsCacheKey,
};

#[derive(Debug, Default)]
pub(crate) struct WorkbenchCache {
    target_base: Option<TargetBaseCache>,
    run_summaries: Option<RunSummaryCache>,
    source_file: Option<SourceFileCache>,
    git_metadata: Option<GitMetadataCache>,
    scope_tree: Option<ScopeTreeCache>,
    strategy_queue: Option<StrategyQueueCache>,
    prompt_mutations: Option<PromptMutationsCache>,
    harness_file: Option<HarnessFileCache>,
    json_files: BTreeMap<PathBuf, JsonFileCache>,
    map_artifacts: MapArtifactsCache,
    prompt_overrides: PromptOverrideCache,
    finding_aliases: FindingAliasCache,
    view_models: ViewModelFragmentCache,
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

    pub(crate) fn cache_persisted_project_scope_tree(
        &mut self,
        target: &Path,
        tree: NestedProjectScopeTree,
    ) {
        self.scope_tree = Some(ScopeTreeCache {
            target: target.to_path_buf(),
            cached_at: Instant::now(),
            state: ProjectScopeTreeState::Persisted(tree),
        });
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

    /// Cached read of the engagement harness file
    /// (`<target>/engagement/harness.toml`); `None` when the target is unset
    /// or the harness file is missing/unreadable.
    pub(crate) fn harness_file(&mut self, target: Option<&Path>) -> Option<String> {
        let target = target?;
        let path = harness_file_path(target);
        let stamp = source_file_stamp(&path).ok();
        if let Some(cache) = self
            .harness_file
            .as_ref()
            .filter(|cache| cache.target == target && cache.stamp == stamp)
        {
            return cache.contents.clone();
        }
        let contents = std::fs::read_to_string(&path).ok();
        self.harness_file = Some(HarnessFileCache {
            target: target.to_path_buf(),
            stamp,
            contents: contents.clone(),
        });
        contents
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

    pub(crate) fn visible_findings(
        &self,
        key: &VisibleFindingsCacheKey,
    ) -> Option<Vec<VisibleFindingProjection>> {
        self.view_models.visible_findings(key)
    }

    pub(crate) fn cache_visible_findings(
        &mut self,
        key: VisibleFindingsCacheKey,
        projected: Vec<VisibleFindingProjection>,
    ) {
        self.view_models.cache_visible_findings(key, projected);
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

#[derive(Debug)]
struct HarnessFileCache {
    target: PathBuf,
    stamp: Option<SourceFileStamp>,
    contents: Option<String>,
}
