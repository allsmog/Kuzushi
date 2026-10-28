use super::*;
use crate::app::view_hydration::RunResultDocumentRead;
use crate::ui_view_models::{DfdModel, EntryPointBreakdown, RiskByModule, WorklistViewModel};
use audit_dataflow::FindingAuditDataflowCache;
use cache_entries::{
    project_scope_tree_for_target, run_summary_index_from_entries, CompletionValuesCache,
    DirectoryListingCache, FileCompletionValuesCache, GitMetadataCache, JsonFileCache,
    LatestRunPointerCache, PathStateCache, ProjectModelDocumentCache, PromptMutationsCache,
    RunArtifactTextCache, RunProjectionCache, RunSummaryEntriesCache, ScanRecommendationsCache,
    ScopeTreeCache, SourceFileCache, StrategyQueueCache, TargetBaseCache, TargetProfileCache,
};
#[cfg(test)]
use cache_entries::{read_json_file, RunSummaryCache, RunSummaryCacheKey};
use cpg_artifacts_cache::CpgArtifactsCache;
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
use remediation_projection::FindingPatchTruthCache;
use repository_index_cache::RepositoryIndexCache;
use scanned_snippet::ScannedSnippetCache;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use view_model_fragments::ViewModelFragmentCache;

const MAX_PATH_CACHE_ENTRIES: usize = 128;
const MAX_RUN_CACHE_ENTRIES: usize = 32;
// A two-run comparison and its navigation origin need more than eight artifacts.
// The shared byte ceiling still bounds retained payloads independently of count.
const MAX_LARGE_RUN_CACHE_ENTRIES: usize = MAX_RUN_CACHE_ENTRIES;
const MAX_LARGE_RUN_CACHE_BYTES: usize = kuzushi_core::MAX_RUN_ARTIFACT_READ_BYTES as usize;
const MAX_FINDING_TRUTH_CACHE_ENTRIES: usize = 256;
const MAX_STATUS_CACHE_ENTRIES: usize = 32;

type MapRunContextRead = Result<Option<kuzushi_core::workflow_attempts::MapRunContext>, String>;
type InvestigationReportRead =
    Result<Option<Arc<kuzushi_core::workspace::InvestigationReportDocument>>, String>;

mod audit_dataflow;
mod cache_entries;
mod completion_values;
mod cpg_artifacts_cache;
mod executable_options;
mod finding_alias_cache;
mod groups;
mod hydrated_reads;
mod hydration_state;
mod investigation_allowance;
mod map_artifacts_cache;
mod prompt_override_cache;
mod relationships;
mod remediation_projection;
mod report_reads;
mod repository_index_cache;
mod review_source;
mod scan_study;
use report_reads::ReportReadCache;
mod run_request_context;
mod scanned_snippet;
mod study_history;
mod study_usage;
#[cfg(test)]
mod tests;
mod view_model_fragments;
pub(crate) use cache_entries::{
    DirectoryListingState, JsonFileState, PathState, ProjectScopeTreeState, PromptMutationsState,
    StrategyQueueState,
};
pub(crate) use view_model_fragments::{
    DfdModelCacheKey, EntryPointBreakdownCacheKey, ReviewQueueCacheKey, RiskByModuleCacheKey,
    VisibleFindingProjection, VisibleFindingsCacheKey, WorklistCacheKey,
};

#[derive(Debug, Default)]
pub(crate) struct WorkbenchCache {
    pub(crate) lesson_pages:
        BTreeMap<(PathBuf, usize), Result<kuzushi_core::findings::FindingLessonPage, String>>,
    pub(crate) group_pages: BTreeMap<
        (PathBuf, ViewHydrationKey),
        Result<kuzushi_core::findings::FindingGroupsPage, String>,
    >,
    pub(crate) relationship_pages: BTreeMap<
        (PathBuf, Option<i64>, usize),
        Result<kuzushi_core::findings::FindingRelationshipPage, String>,
    >,
    pub(crate) answer_document: Option<crate::ui_view_models::AnswerDocumentCache>,
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
    revision_relationships:
        BTreeMap<(PathBuf, String, String), kuzushi_core::workspace::RevisionRelationship>,
    scope_tree: Option<ScopeTreeCache>,
    threat_model_store: Option<(PathBuf, ThreatModelStoreState)>,
    map_run_context: BTreeMap<(PathBuf, Vec<String>), MapRunContextRead>,
    investigation_report:
        ReportReadCache<Option<Arc<kuzushi_core::workspace::InvestigationReportDocument>>>,
    workspace_report_review: ReportReadCache<Arc<kuzushi_core::workspace::WorkspaceReviewSummary>>,
    project_model_document: Option<ProjectModelDocumentCache>,
    strategy_queue: Option<StrategyQueueCache>,
    prompt_mutations: Option<PromptMutationsCache>,
    harness_file: Option<HarnessFileCache>,
    json_files: BTreeMap<PathBuf, JsonFileCache>,
    json_file_generation: u64,
    path_states: BTreeMap<PathBuf, PathStateCache>,
    directory_listings: BTreeMap<PathBuf, DirectoryListingCache>,
    run_projections: BTreeMap<(PathBuf, String), RunProjectionCache>,
    run_result_document: Option<(PathBuf, ViewHydrationKey, RunResultDocumentRead)>,
    run_request_context: Option<(PathBuf, String, crate::app::RunRequestContextRead)>,
    investigation_allowance: Option<investigation_allowance::InvestigationAllowanceCache>,
    scan_study_progress: Option<scan_study::ScanStudyProgressCache>,
    phase_receipt_outcomes: BTreeMap<
        (PathBuf, String),
        Result<Option<kuzushi_core::workflow_attempts::PhaseAttemptOutcome>, String>,
    >,
    run_artifact_texts: BTreeMap<(PathBuf, String, String), RunArtifactTextCache>,
    scan_stage_receipts: BTreeMap<(PathBuf, String), ScanStageReceiptState>,
    study_usage_catalogue: Option<(PathBuf, StudyUsageCatalogueRead)>,
    study_history: Option<(PathBuf, StudyHistoryRead)>,
    study_usage_runs: BTreeMap<(PathBuf, String), StudyUsageRunRead>,
    matrix_reports: BTreeMap<
        (PathBuf, ViewHydrationKey),
        Result<kuzushi_core::findings::ContextMatrixOccurrenceReport, String>,
    >,
    map_artifacts: MapArtifactsCache,
    repository_index: RepositoryIndexCache,
    cpg_artifacts: CpgArtifactsCache,
    scan_recommendations: Option<ScanRecommendationsCache>,
    prompt_overrides: PromptOverrideCache,
    health_checks: BTreeMap<String, ViewHealthChecks>,
    executable_options: BTreeMap<(PathBuf, ViewHydrationKey), Vec<String>>,
    executable_generation: u64,
    finding_aliases: FindingAliasCache,
    finding_patch_truth: FindingPatchTruthCache,
    finding_audit_dataflow: FindingAuditDataflowCache,
    finding_review_sources:
        BTreeMap<(PathBuf, ViewHydrationKey), crate::app::view_hydration::FindingReviewSourceRead>,
    scanned_snippets: ScannedSnippetCache,
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

    /// The content-identity stamp of a hydrated run artifact, or `None` when the
    /// artifact has not hydrated for this target/run/leaf. Read-path callers key
    /// a memo on this `u64` instead of re-cloning and re-parsing the artifact
    /// text every frame (the version was computed once at hydration).
    pub(crate) fn cached_run_artifact_version(
        &self,
        target: &Path,
        run_id: &str,
        leaf: &str,
    ) -> Option<u64> {
        let map_key = (target.to_path_buf(), run_id.to_string(), leaf.to_string());
        self.run_artifact_texts
            .get(&map_key)
            .map(|cache| cache.version)
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

    pub(crate) fn cached_run_projection(
        &self,
        target: &Path,
        run_id: &str,
    ) -> ViewDataState<Result<kuzushi_core::run_lifecycle::RunProjectionRead, String>> {
        let map_key = (target.to_path_buf(), run_id.to_string());
        if let Some(cache) = self.run_projections.get(&map_key) {
            return ViewDataState::Ready(cache.state.clone());
        }
        self.loading_state(
            target,
            &ViewHydrationKey::RunProjection {
                run_id: run_id.to_string(),
            },
        )
    }

    pub(crate) fn cached_run_result_document(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> ViewDataState<RunResultDocumentRead> {
        if let Some((_, _, state)) = self
            .run_result_document
            .as_ref()
            .filter(|(saved_target, saved_key, _)| saved_target == target && saved_key == key)
        {
            return ViewDataState::Ready(state.clone());
        }
        self.loading_state(target, key)
    }

    pub(crate) fn cached_phase_receipt_outcome(
        &self,
        target: &Path,
        attempt_id: &str,
    ) -> ViewDataState<Result<Option<kuzushi_core::workflow_attempts::PhaseAttemptOutcome>, String>>
    {
        let map_key = (target.to_path_buf(), attempt_id.to_string());
        if let Some(state) = self.phase_receipt_outcomes.get(&map_key) {
            return ViewDataState::Ready(state.clone());
        }
        self.loading_state(
            target,
            &ViewHydrationKey::PhaseReceiptOutcome {
                attempt_id: attempt_id.to_string(),
            },
        )
    }

    pub(crate) fn cached_scan_stage_receipt(
        &self,
        target: &Path,
        run_id: &str,
    ) -> ViewDataState<ScanStageReceiptState> {
        let map_key = (target.to_path_buf(), run_id.to_string());
        if let Some(state) = self.scan_stage_receipts.get(&map_key) {
            return ViewDataState::Ready(state.clone());
        }
        self.loading_state(
            target,
            &ViewHydrationKey::ScanStageReceipt {
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

    /// Whether the target has usable whole-graph cpg-rs artifacts, read from the
    /// hydration cache so the health view never runs `read_dir` on the render
    /// path. `NotRequested`/`Loading` until the hydration worker resolves it.
    pub(crate) fn cached_cpg_artifacts_built(&self, target: Option<&Path>) -> ViewDataState<bool> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some(built) = self.cpg_artifacts.cached(target) {
            return ViewDataState::Ready(built);
        }
        self.loading_state(target, &ViewHydrationKey::CpgArtifacts)
    }

    pub(crate) fn cached_scan_recommendations(
        &self,
        target: Option<&Path>,
    ) -> ViewDataState<ScanRecommendationsState> {
        let Some(target) = target else {
            return ViewDataState::NotRequested;
        };
        if let Some(cache) = self
            .scan_recommendations
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            return ViewDataState::Ready(cache.state.clone());
        }
        self.loading_state(target, &ViewHydrationKey::ScanRecommendations)
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
        self.mark_run_summary_entries_stale();
        self.latest_run_pointer = None;
        self.run_id_completion_values = None;
        drop_unsettled_scan_stage_receipts(&mut self.scan_stage_receipts);
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

    /// Whether the entries index must be (re-)read: never loaded for this
    /// target, or loaded but marked stale by an invalidation. Stale entries
    /// keep serving through `cached_run_summary_entries` in the meantime.
    pub(crate) fn run_summary_entries_need_refresh(&self, target: &Path) -> bool {
        match self
            .run_summary_entries
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            Some(cache) => cache.stale,
            None => true,
        }
    }

    /// Ask for a fresh read of one run's lifecycle while the current read
    /// keeps serving (used while following a run that is still executing).
    pub(crate) fn mark_run_projection_stale(&mut self, target: &Path, run_id: &str) {
        let key = (target.to_path_buf(), run_id.to_string());
        if let Some(cache) = self.run_projections.get_mut(&key) {
            cache.stale = true;
        }
    }

    pub(crate) fn run_projection_is_stale(&self, target: &Path, run_id: &str) -> bool {
        let key = (target.to_path_buf(), run_id.to_string());
        self.run_projections
            .get(&key)
            .is_some_and(|cache| cache.stale)
    }

    fn mark_run_summary_entries_stale(&mut self) {
        if let Some(cache) = self.run_summary_entries.as_mut() {
            cache.stale = true;
        }
    }

    /// Whether the git probe must be (re-)run: never loaded for this target,
    /// or loaded but marked stale by an invalidation. Stale metadata keeps
    /// serving through `cached_git_metadata` in the meantime, so the
    /// revision label never regresses to "rev:unknown" mid-refresh.
    pub(crate) fn git_metadata_needs_refresh(&self, target: &Path) -> bool {
        match self
            .git_metadata
            .as_ref()
            .filter(|cache| cache.target == target)
        {
            Some(cache) => cache.stale,
            None => true,
        }
    }

    fn mark_git_metadata_stale(&mut self) {
        if let Some(cache) = self.git_metadata.as_mut() {
            cache.stale = true;
        }
    }

    #[cfg(test)]
    pub(crate) fn run_summary_entries(&mut self, target: Option<&Path>) -> Vec<RunSummaryEntry> {
        let Some(target) = target else {
            return Vec::new();
        };
        if let Some(cache) = self
            .run_summary_entries
            .as_ref()
            .filter(|cache| cache.target == target && !cache.stale)
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
            stale: false,
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

    pub(crate) fn invalidate_workspace_files(&mut self) {
        self.repository_index.invalidate();
        self.lesson_pages.clear();
        self.investigation_report.invalidate();
        self.workspace_report_review.invalidate();
        self.source_file = None;
        self.mark_git_metadata_stale();
        self.revision_relationships.clear();
        self.scope_tree = None;
        self.threat_model_store = None;
        self.map_run_context.clear();
        self.project_model_document = None;
        self.strategy_queue = None;
        self.prompt_mutations = None;
        self.harness_file = None;
        self.json_files.clear();
        self.path_states.clear();
        self.directory_listings.clear();
        self.file_completion_values = None;
        self.bump_completion_generation();
        self.run_projections.clear();
        self.run_result_document = None;
        self.phase_receipt_outcomes.clear();
        self.run_artifact_texts.clear();
        drop_unsettled_scan_stage_receipts(&mut self.scan_stage_receipts);
        self.finding_patch_truth.invalidate(None);
        self.finding_audit_dataflow.invalidate(None);
        self.finding_review_sources.clear();
        self.scanned_snippets.invalidate();
        self.map_artifacts.invalidate();
        self.cpg_artifacts.invalidate();
        self.scan_recommendations = None;
        self.prompt_overrides.invalidate();
        self.health_checks.clear();
        self.invalidate_executable_options();
        self.clear_view_hydration_loading();
    }

    /// Refresh data derived from live target source without evicting durable
    /// `.kuzushi` artifacts. Editor saves can arrive several times per second;
    /// dropping Map, run, JSON, or revision caches here makes accepted phase
    /// evidence oscillate through Loading even though those files did not
    /// change.
    pub(crate) fn invalidate_source_file_changes(&mut self) {
        self.repository_index.invalidate();
        self.source_file = None;
        self.mark_git_metadata_stale();
        self.file_completion_values = None;
        self.bump_completion_generation();
        self.finding_patch_truth.invalidate(None);
        self.scan_recommendations = None;
        self.clear_view_hydration_loading();
    }

    fn trim_large_run_caches(&mut self, keep: &LargeRunCacheKey) {
        self.trim_large_run_caches_to(keep, MAX_LARGE_RUN_CACHE_BYTES);
    }

    fn trim_large_run_caches_to(&mut self, keep: &LargeRunCacheKey, max_bytes: usize) {
        while self.large_run_cache_bytes() > max_bytes {
            if !self.evict_large_run_cache_entry_except(keep) {
                self.remove_large_run_cache_entry(keep);
                break;
            }
        }
    }

    fn large_run_cache_bytes(&self) -> usize {
        self.run_artifact_texts
            .values()
            .map(|entry| entry.bytes)
            .chain(self.run_projections.values().map(|entry| entry.bytes))
            .fold(0, usize::saturating_add)
    }

    fn evict_large_run_cache_entry_except(&mut self, keep: &LargeRunCacheKey) -> bool {
        evict_artifact_text_except(&mut self.run_artifact_texts, keep)
            || evict_run_projection_except(&mut self.run_projections, keep)
    }

    fn remove_large_run_cache_entry(&mut self, key: &LargeRunCacheKey) {
        match key {
            LargeRunCacheKey::Artifact(key) => {
                self.run_artifact_texts.remove(key);
            }
            LargeRunCacheKey::Projection(key) => {
                self.run_projections.remove(key);
            }
        }
    }

    pub(crate) fn invalidate_json_file(&mut self, path: &Path) {
        self.json_files.remove(path);
    }

    pub(crate) fn invalidate_threat_model(&mut self, target: &Path) {
        self.threat_model_store = None;
        self.map_run_context.clear();
        self.invalidate_json_file(&kuzushi_core::capabilities::persistent_threat_model_path(
            target,
        ));
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
            self.mark_run_summary_entries_stale();
            self.latest_run_pointer = None;
            self.run_id_completion_values = None;
        }
        if findings_changed {
            self.finding_completion_values = None;
            self.finding_patch_truth.invalidate(None);
            self.finding_audit_dataflow.invalidate(None);
            self.finding_review_sources.clear();
            self.scanned_snippets.invalidate();
        }
        self.bump_completion_generation_when(findings_changed | run_summaries_changed);
        self.strategy_queue = None;
        self.prompt_mutations = None;
        self.project_model_document = None;
        self.scan_recommendations = None;
        (findings_changed, run_summaries_changed)
    }

    #[cfg(test)]
    fn invalidate_legacy_run_summary_index(&mut self) {
        self.run_summaries = None;
    }

    #[cfg(not(test))]
    fn invalidate_legacy_run_summary_index(&mut self) {}

    fn invalidate_run_summary_dependents(&mut self) {
        self.study_usage_catalogue = None;
        self.study_history = None;
        self.study_usage_runs.clear();
        self.investigation_report.invalidate();
        self.workspace_report_review.invalidate();
        self.invalidate_legacy_run_summary_index();
        self.map_run_context.clear();
        self.view_models.invalidate_visible_findings();
    }

    fn invalidate_state_artifact_path(
        &mut self,
        roots: &StateArtifactRoots<'_>,
        relative: &Path,
    ) -> (bool, bool) {
        let path = roots.target.join(relative);
        let broad = path == roots.state;
        if phase_receipt_source_changed(roots, &path, broad) {
            self.phase_receipt_outcomes
                .retain(|(target, _), _| target != roots.target);
        }
        self.invalidate_named_artifact(relative);
        self.invalidate_path_caches(&path, &roots.state, broad);
        self.invalidate_run_caches(roots, &path, broad);
        state_change_flags(roots, &path, broad)
    }

    fn invalidate_named_artifact(&mut self, relative: &Path) {
        self.repository_index.invalidate_path(relative);
        if is_project_scope_tree_path(relative) {
            self.scope_tree = None;
        }
        if is_threat_model_store_path(relative) {
            self.threat_model_store = None;
            self.map_run_context.clear();
        }
        if is_map_artifact_path(relative) {
            self.map_artifacts.invalidate();
            self.cpg_artifacts.invalidate();
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
        if broad || path == roots.runs {
            self.invalidate_target_run_caches(roots.target);
            return;
        }
        if let Some(run_id) = run_directory_identity(&roots.runs, path) {
            self.invalidate_one_run_cache(roots.target, run_id);
            return;
        }
        invalidate_cached_run_artifact_text(
            &mut self.run_artifact_texts,
            roots.target,
            &roots.runs,
            &path,
        );
        invalidate_cached_run_projection(
            &mut self.run_projections,
            roots.target,
            &roots.runs,
            path,
        );
        invalidate_cached_scan_stage_receipt(
            &mut self.scan_stage_receipts,
            roots.target,
            &roots.runs,
            &path,
        );
    }

    fn invalidate_target_run_caches(&mut self, target: &Path) {
        self.clear_matching_result_document(target, None);
        self.run_projections
            .retain(|(cached_target, _), _| cached_target != target);
        self.run_artifact_texts
            .retain(|(cached_target, _, _), _| cached_target != target);
        self.scan_stage_receipts
            .retain(|(cached_target, _), state| {
                cached_target != target || scan_stage_receipt_is_settled(state)
            });
    }

    pub(crate) fn invalidate_one_run_cache(&mut self, target: &Path, run_id: &str) {
        self.clear_matching_result_document(target, Some(run_id));
        let key = (target.to_path_buf(), run_id.to_string());
        self.run_projections.remove(&key);
        self.run_artifact_texts
            .retain(|(cached_target, cached_run, _), _| {
                cached_target != target || cached_run != run_id
            });
        if self
            .scan_stage_receipts
            .get(&key)
            .is_some_and(|state| !scan_stage_receipt_is_settled(state))
        {
            self.scan_stage_receipts.remove(&key);
        }
    }

    fn clear_matching_result_document(&mut self, target: &Path, run_id: Option<&str>) {
        let matches = self
            .run_result_document
            .as_ref()
            .is_some_and(|(cached_target, key, _)| {
                let ViewHydrationKey::RunResultDocument {
                    run_id: cached_run, ..
                } = key
                else {
                    return false;
                };
                cached_target == target && run_id.is_none_or(|run| cached_run == run)
            });
        if matches {
            self.run_result_document = None;
        }
    }

    fn invalidate_state_root(&mut self, state_root: &Path) {
        self.repository_index.invalidate_path(state_root);
        self.json_files
            .retain(|cached, _| !cached.starts_with(state_root));
        self.path_states
            .retain(|cached, _| !cached.starts_with(state_root));
        self.directory_listings
            .retain(|cached, _| !cached.starts_with(state_root));
        self.threat_model_store = None;
        self.map_run_context.clear();
        self.map_artifacts.invalidate();
        self.cpg_artifacts.invalidate();
        self.finding_patch_truth.invalidate(None);
        self.finding_audit_dataflow.invalidate(None);
        self.finding_review_sources.clear();
        self.scanned_snippets.invalidate();
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
        self.json_file_generation = self.json_file_generation.wrapping_add(1).max(1);
        insert_bounded(
            &mut self.json_files,
            path.to_path_buf(),
            JsonFileCache {
                state: state.clone(),
                version: self.json_file_generation,
                content_sha256: None,
                entry_point_catalog_authentication: None,
                entry_point_catalog_context_authentication: None,
            },
            MAX_PATH_CACHE_ENTRIES,
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
        insert_bounded(
            &mut self.run_artifact_texts,
            key.clone(),
            RunArtifactTextCache {
                bytes: run_artifact_text_bytes(&state),
                version: run_artifact_version(&state),
                state: state.clone(),
            },
            MAX_LARGE_RUN_CACHE_ENTRIES,
        );
        self.trim_large_run_caches(&LargeRunCacheKey::Artifact(key));
        state
    }

    pub(crate) fn invalidate_map_artifacts(&mut self) {
        self.map_artifacts.invalidate();
        self.cpg_artifacts.invalidate();
        self.scan_recommendations = None;
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
        before_search: Arc<[VisibleFindingProjection]>,
    ) {
        self.view_models
            .cache_visible_findings(key, projected, before_search);
    }

    pub(crate) fn visible_findings_before_search(
        &self,
        key: &VisibleFindingsCacheKey,
    ) -> Option<Arc<[VisibleFindingProjection]>> {
        self.view_models.visible_findings_before_search(key)
    }

    pub(crate) fn review_queue(
        &self,
        key: &ReviewQueueCacheKey,
    ) -> Option<(
        Arc<[crate::ui_view_models::ReviewQueueRow]>,
        usize,
        usize,
        Arc<[crate::ui_view_models::ReviewFacetGroup]>,
    )> {
        self.view_models.review_queue(key)
    }

    pub(crate) fn cache_review_queue(
        &mut self,
        key: ReviewQueueCacheKey,
        rows: Arc<[crate::ui_view_models::ReviewQueueRow]>,
        open_count: usize,
        complete_count: usize,
        facet_groups: Arc<[crate::ui_view_models::ReviewFacetGroup]>,
    ) {
        self.view_models
            .cache_review_queue(key, rows, open_count, complete_count, facet_groups);
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

    pub(crate) fn dfd_model_is_empty(&self, key: &DfdModelCacheKey) -> Option<bool> {
        self.view_models.dfd_model_is_empty(key)
    }

    pub(crate) fn worklist(&self, key: &WorklistCacheKey) -> Option<WorklistViewModel> {
        self.view_models.worklist(key)
    }

    pub(crate) fn cache_worklist(&mut self, key: WorklistCacheKey, model: WorklistViewModel) {
        self.view_models.cache_worklist(key, model);
    }

    pub(crate) fn cache_dfd_model(&mut self, key: DfdModelCacheKey, model: DfdModel) {
        self.view_models.cache_dfd_model(key, model);
    }

    pub(crate) fn entry_point_breakdown(
        &self,
        key: &EntryPointBreakdownCacheKey,
    ) -> Option<Arc<EntryPointBreakdown>> {
        self.view_models.entry_point_breakdown(key)
    }

    pub(crate) fn cache_entry_point_breakdown(
        &mut self,
        key: EntryPointBreakdownCacheKey,
        model: Arc<EntryPointBreakdown>,
    ) {
        self.view_models.cache_entry_point_breakdown(key, model);
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

fn phase_receipt_source_changed(roots: &StateArtifactRoots<'_>, path: &Path, broad: bool) -> bool {
    broad || path.starts_with(&roots.runs) || path.starts_with(roots.state.join("workflow"))
}

fn is_project_scope_tree_path(path: &Path) -> bool {
    path == Path::new(".kuzushi/v3/project-model/scopes.json")
}

fn is_map_artifact_path(path: &Path) -> bool {
    path.starts_with(".kuzushi/v3/codeql-db")
        || path.starts_with(".kuzushi/cpg-rs")
        || matches!(
            path.to_str(),
            Some(
                ".kuzushi/context-snapshot.json"
                    | ".kuzushi/entry-points.json"
                    | ".kuzushi/threat-model.json"
                    | ".kuzushi/threat-intel/candidates.json"
            )
        )
}

fn is_threat_model_store_path(path: &Path) -> bool {
    path == Path::new(".kuzushi/threat-model.json") || path.starts_with(".kuzushi/threat-models")
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum LargeRunCacheKey {
    Artifact((PathBuf, String, String)),
    Projection((PathBuf, String)),
}

fn evict_artifact_text_except(
    entries: &mut BTreeMap<(PathBuf, String, String), RunArtifactTextCache>,
    keep: &LargeRunCacheKey,
) -> bool {
    let protected = match keep {
        LargeRunCacheKey::Artifact(key) => Some(key),
        _ => None,
    };
    let candidate = entries.keys().find(|key| Some(*key) != protected).cloned();
    candidate.is_some_and(|key| entries.remove(&key).is_some())
}

fn evict_run_projection_except(
    entries: &mut BTreeMap<(PathBuf, String), RunProjectionCache>,
    keep: &LargeRunCacheKey,
) -> bool {
    let protected = match keep {
        LargeRunCacheKey::Projection(key) => Some(key),
        _ => None,
    };
    let candidate = entries.keys().find(|key| Some(*key) != protected).cloned();
    candidate.is_some_and(|key| entries.remove(&key).is_some())
}

/// Hash the artifact's content once at hydration so render-path memo keys can
/// track "which revision is loaded" without re-parsing the artifact. A `Ready`
/// read hashes the raw text (so a moved line changes the version even when
/// summary counts are unchanged); non-`Ready` reads hash a stable discriminant.
fn run_artifact_version(state: &kuzushi_core::RunArtifactTextRead) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    match state {
        kuzushi_core::RunArtifactRead::Ready { value, .. } => {
            0u8.hash(&mut hasher);
            value.hash(&mut hasher);
        }
        kuzushi_core::RunArtifactRead::Missing { .. } => 1u8.hash(&mut hasher),
        kuzushi_core::RunArtifactRead::NonFile { .. } => 2u8.hash(&mut hasher),
        kuzushi_core::RunArtifactRead::Unsafe { error } => {
            3u8.hash(&mut hasher);
            error.hash(&mut hasher);
        }
        kuzushi_core::RunArtifactRead::Unreadable { error, .. } => {
            4u8.hash(&mut hasher);
            error.hash(&mut hasher);
        }
    }
    hasher.finish()
}

fn run_artifact_text_bytes(state: &kuzushi_core::RunArtifactTextRead) -> usize {
    match state {
        kuzushi_core::RunArtifactRead::Ready { value, .. } => value.len(),
        kuzushi_core::RunArtifactRead::Unsafe { error }
        | kuzushi_core::RunArtifactRead::Unreadable { error, .. } => error.len(),
        _ => 1,
    }
}

fn run_projection_bytes(
    state: &Result<kuzushi_core::run_lifecycle::RunProjectionRead, String>,
) -> usize {
    match state {
        Ok(read) => serialized_bytes(read),
        Err(error) => error.len(),
    }
}

fn serialized_bytes(value: &impl serde::Serialize) -> usize {
    let mut counter = ByteCounter::default();
    serde_json::to_writer(&mut counter, value).map_or(usize::MAX, |_| counter.bytes)
}

#[derive(Default)]
struct ByteCounter {
    bytes: usize,
}

impl std::io::Write for ByteCounter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.saturating_add(buffer.len());
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn invalidate_cached_run_artifact_text(
    artifacts: &mut BTreeMap<(PathBuf, String, String), RunArtifactTextCache>,
    target: &Path,
    runs_root: &Path,
    path: &Path,
) {
    let Some((run_id, leaf)) = run_artifact_identity(runs_root, path) else {
        return;
    };
    artifacts.remove(&(target.to_path_buf(), run_id.to_string(), leaf.to_string()));
}

fn invalidate_cached_run_projection(
    projections: &mut BTreeMap<(PathBuf, String), RunProjectionCache>,
    target: &Path,
    runs_root: &Path,
    path: &Path,
) {
    let Some((run_id, leaf)) = run_artifact_identity(runs_root, path) else {
        return;
    };
    if leaf == "items.jsonl" {
        projections.remove(&(target.to_path_buf(), run_id.to_string()));
    }
}

fn invalidate_cached_scan_stage_receipt(
    receipts: &mut BTreeMap<(PathBuf, String), ScanStageReceiptState>,
    target: &Path,
    runs_root: &Path,
    path: &Path,
) {
    let Some(run_id) = path
        .strip_prefix(runs_root)
        .ok()
        .and_then(|relative| relative.components().next())
        .and_then(|component| component.as_os_str().to_str())
    else {
        return;
    };
    let key = (target.to_path_buf(), run_id.to_string());
    if receipts
        .get(&key)
        .is_some_and(|state| !scan_stage_receipt_is_settled(state))
    {
        receipts.remove(&key);
    }
}

/// A `Ready` receipt describes a terminal run and is written exactly once,
/// so cache invalidation keeps it; only `Missing`/`Failed` can still
/// transition (the receipt file lands later, a transient read error clears).
/// Dropping `Ready` entries made the Scan page fall back to its legacy
/// projection on every external workspace refresh — a visible flap.
fn scan_stage_receipt_is_settled(state: &ScanStageReceiptState) -> bool {
    matches!(state, ScanStageReceiptState::Ready(_))
}

fn drop_unsettled_scan_stage_receipts(
    receipts: &mut BTreeMap<(PathBuf, String), ScanStageReceiptState>,
) {
    receipts.retain(|_, state| scan_stage_receipt_is_settled(state));
}

fn run_artifact_identity<'a>(runs_root: &Path, path: &'a Path) -> Option<(&'a str, &'a str)> {
    let mut components = path.strip_prefix(runs_root).ok()?.components();
    let run_id = components.next()?.as_os_str().to_str()?;
    let leaf = components.next()?.as_os_str().to_str()?;
    (components.next().is_none()).then_some((run_id, leaf))
}

fn run_directory_identity<'a>(runs_root: &Path, path: &'a Path) -> Option<&'a str> {
    let mut components = path.strip_prefix(runs_root).ok()?.components();
    let run_id = components.next()?.as_os_str().to_str()?;
    components.next().is_none().then_some(run_id)
}

fn insert_bounded<K: Ord, V>(entries: &mut BTreeMap<K, V>, key: K, value: V, max_entries: usize) {
    debug_assert!(max_entries > 0);
    if !entries.contains_key(&key) {
        while entries.len() >= max_entries {
            entries.pop_first();
        }
    }
    entries.insert(key, value);
}

#[derive(Debug)]
struct HarnessFileCache {
    target: PathBuf,
    contents: Option<String>,
}
