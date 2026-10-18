use super::*;
use kuzushi_core::workspace::ProjectModelDocument;
use kuzushi_core::{
    LatestRunPointerState, RunArtifactTextRead, RunSummaryEntry, RunTargetGitMetadata,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
mod completion_tests;
mod investigation_allowance;
mod reader;
#[cfg(test)]
mod reader_tests;
#[cfg(test)]
mod report_refresh_tests;
mod requests;
mod runtime;
mod scan_study;
#[cfg(test)]
mod study_usage_tests;
#[cfg(test)]
mod tests;

use requests::active_view_hydration_keys;
pub(crate) use runtime::ViewHydrationRuntime;

pub(crate) const GLOBAL_HEALTH_HYDRATION_SCOPE: &str = "global-health-view-data";

pub(crate) type StudyUsageCatalogueRead =
    Result<kuzushi_core::capabilities::campaign::ScanUsageCatalogue, String>;
pub(crate) type StudyHistoryRead =
    Result<kuzushi_core::capabilities::campaign::StudyUsageCatalogue, String>;
pub(crate) type StudyUsageRunRead =
    Result<kuzushi_core::capabilities::campaign::ScanResourceEvidence, String>;
pub(crate) type FindingReviewSourceRead = Result<Option<FindingReviewSource>, String>;
pub(crate) type RunResultDocumentRead =
    Result<Arc<kuzushi_core::run_artifacts::RunResultDocument>, String>;
pub(crate) type RunRequestContextRead =
    Result<Arc<kuzushi_core::run_artifacts::RunRequestContext>, String>;
pub(crate) type InvestigationAllowanceRead =
    Result<Option<Arc<kuzushi_core::allowance::AllowanceSnapshot>>, String>;
pub(crate) type ScanStudyProgressRead =
    Result<Arc<kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot>, String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingReviewSource {
    pub(crate) basis: kuzushi_core::workspace::WorkspaceReviewDecisionBasis,
    pub(crate) reviewed_source: Option<kuzushi_core::findings::ReviewSourceCapture>,
    pub(crate) decided_revision: RecordedSourceRevision,
    pub(crate) later_revision: Option<RecordedSourceRevision>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecordedSourceRevision {
    Known(RunTargetGitMetadata),
    NotRecorded,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ViewDataState<T> {
    NotRequested,
    Loading,
    Ready(T),
}

impl<T> ViewDataState<T> {
    pub(crate) fn is_not_requested(&self) -> bool {
        matches!(self, Self::NotRequested)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum RunSummaryEntriesState {
    Ready(Vec<RunSummaryEntry>),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RunSummaryEntriesHydration {
    pub(crate) state: RunSummaryEntriesState,
    pub(crate) newly_recovered: Vec<kuzushi_core::RecoveredRun>,
}

impl RunSummaryEntriesHydration {
    pub(crate) fn without_recoveries(state: RunSummaryEntriesState) -> Self {
        Self {
            state,
            newly_recovered: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ScanStageReceiptState {
    Ready(kuzushi_core::run_artifacts::PhaseStageReceipt),
    Missing,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ScanRecommendationsState {
    Ready(Vec<kuzushi_core::capabilities::scan_recommender::ScanRecommendation>),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ThreatModelStoreState {
    Legacy,
    Ready {
        manifest: kuzushi_core::ThreatModelManifest,
        active: Option<kuzushi_core::ActiveThreatModel>,
    },
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FindingPatchTruthState {
    Ready(FindingPatchTruth),
    Missing,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FindingAuditDataflowState {
    Ready(Vec<kuzushi_core::findings::DataflowEvidenceRow>),
    Missing,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScannedSnippetState {
    Ready(ScannedSnippetWindow),
    Missing,
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FileCompletionLimit {
    EntryVisits,
    RetainedResults,
    Depth,
    PathBytes,
    UnreadableDirectory,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FileCompletionIndex {
    pub(crate) values: Vec<String>,
    pub(crate) limits_reached: BTreeSet<FileCompletionLimit>,
    pub(crate) entries_visited: usize,
    pub(crate) path_bytes_observed: usize,
}

impl FileCompletionIndex {
    #[cfg(test)]
    pub(crate) fn complete(values: Vec<String>) -> Self {
        Self {
            values,
            ..Self::default()
        }
    }

    pub(crate) fn is_truncated(&self) -> bool {
        !self.limits_reached.is_empty()
    }

    pub(crate) fn truncation_hint(&self) -> Option<&'static str> {
        self.is_truncated().then_some(
            "partial index; paste an exact workspace-relative or absolute path if it is missing",
        )
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ViewHydrationCancellation {
    scan: kuzushi_core::ScanCancellation,
}

impl ViewHydrationCancellation {
    pub(crate) fn cancel(&self) {
        self.scan.cancel();
    }

    pub(crate) fn is_canceled(&self) -> bool {
        self.scan.is_cancelled()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ViewHydrationKey {
    FindingGroups(kuzushi_core::findings::FindingGroupsRequest),
    FindingRelationships {
        finding_id: Option<i64>,
        offset: usize,
    },
    FindingLessons {
        offset: usize,
    },
    FindingsProjection(super::findings::FindingsReadRequest),
    FileCompletionValues,
    FindingCompletionValues,
    RunIdCompletionValues,
    LatestRunPointer,
    RunSummaryEntries,
    StudyUsageCatalogue,
    StudyHistory,
    ContextMatrixReport {
        campaign_id: String,
        plan_sha256: String,
    },
    StudyUsageRun {
        run_id: String,
    },
    WorkspaceReportReview {
        findings_watermark: Option<u64>,
    },
    InvestigationReport {
        run_refs: Vec<String>,
        findings_watermark: Option<u64>,
    },
    InvestigationStudyReport {
        campaign_id: String,
        plan_sha256: String,
        findings_watermark: Option<u64>,
    },
    RunArtifactText {
        run_id: String,
        leaf: String,
    },
    RunProjection {
        run_id: String,
    },
    RunResultDocument {
        run_id: String,
        producer: kuzushi_core::run_lifecycle::RunItemId,
        digest: String,
    },
    RunRequestContext {
        run_id: String,
    },
    InvestigationAllowance {
        run_refs: Vec<String>,
    },
    ScanStudyProgress {
        campaign_id: String,
    },
    PhaseReceiptOutcome {
        attempt_id: String,
    },
    ScanStageReceipt {
        run_id: String,
    },
    FindingPatchTruth {
        fingerprint: String,
        finding_scan_id: Option<String>,
        target_revision: Option<String>,
    },
    FindingAuditDataflow {
        fingerprint: String,
    },
    FindingReviewSource {
        stable_fp: String,
        decision_id: i64,
        decision_watermark: u64,
        observation_watermark: Option<u64>,
    },
    ScannedSnippet {
        stable_fp: String,
        scan_id: Option<String>,
        focus_line: u32,
    },
    SourceFile {
        path: PathBuf,
    },
    GitMetadata,
    RevisionRelationship {
        accepted_revision: String,
        current_revision: String,
    },
    ProjectScopeTree,
    ThreatModelStore,
    MapRunContext {
        run_refs: Vec<String>,
    },
    ProjectModelDocument {
        scope_id: String,
        revision: Option<String>,
    },
    StrategyQueue,
    PromptMutations,
    HarnessFile,
    JsonFile {
        path: PathBuf,
    },
    PathState {
        path: PathBuf,
    },
    DirectoryListing {
        path: PathBuf,
    },
    PromptOverrideHash {
        path: PathBuf,
    },
    HealthChecks {
        credential_env: String,
    },
    ExecutableOptions {
        requirements: Vec<kuzushi_core::modules::ExecutableRequirement>,
        generation: u64,
    },
    TargetProfile,
    MapArtifacts,
    CpgArtifacts,
    ScanRecommendations,
    TargetBase,
}

#[derive(Debug, Clone)]
pub(crate) enum ViewHydrationValue {
    ExecutableOptions(Vec<String>),
    FindingGroups(Result<kuzushi_core::findings::FindingGroupsPage, String>),
    FindingRelationships(Result<kuzushi_core::findings::FindingRelationshipPage, String>),
    FindingLessons(Result<kuzushi_core::findings::FindingLessonPage, String>),
    FindingsProjection(Result<super::findings::FindingsReadSnapshot, String>),
    FileCompletionValues(FileCompletionIndex),
    FindingCompletionValues(Vec<String>),
    RunIdCompletionValues(Vec<String>),
    LatestRunPointer(LatestRunPointerState),
    RunSummaryEntries(RunSummaryEntriesHydration),
    StudyUsageCatalogue(StudyUsageCatalogueRead),
    StudyHistory(StudyHistoryRead),
    ContextMatrixReport(Result<kuzushi_core::findings::ContextMatrixOccurrenceReport, String>),
    StudyUsageRun(StudyUsageRunRead),
    WorkspaceReportReview(Result<kuzushi_core::workspace::WorkspaceReviewSummary, String>),
    InvestigationReport(
        Result<Option<kuzushi_core::workspace::InvestigationReportDocument>, String>,
    ),
    RunArtifactText(RunArtifactTextRead),
    RunProjection(Result<kuzushi_core::run_lifecycle::RunProjectionRead, String>),
    RunResultDocument(RunResultDocumentRead),
    RunRequestContext(RunRequestContextRead),
    InvestigationAllowance(InvestigationAllowanceRead),
    ScanStudyProgress(ScanStudyProgressRead),
    PhaseReceiptOutcome(
        Result<Option<kuzushi_core::workflow_attempts::PhaseAttemptOutcome>, String>,
    ),
    ScanStageReceipt(ScanStageReceiptState),
    FindingPatchTruth(FindingPatchTruthState),
    FindingAuditDataflow(FindingAuditDataflowState),
    FindingReviewSource(FindingReviewSourceRead),
    ScannedSnippet(ScannedSnippetState),
    SourceFile(Result<String, String>),
    GitMetadata(Option<RunTargetGitMetadata>),
    RevisionRelationship(kuzushi_core::workspace::RevisionRelationship),
    ProjectScopeTree(ProjectScopeTreeState),
    ThreatModelStore(ThreatModelStoreState),
    MapRunContext(Result<Option<kuzushi_core::workflow_attempts::MapRunContext>, String>),
    ProjectModelDocument(Option<ProjectModelDocument>),
    StrategyQueue(StrategyQueueState),
    PromptMutations(PromptMutationsState),
    HarnessFile(Option<String>),
    JsonFile(JsonFileHydration),
    PathState(PathState),
    DirectoryListing(DirectoryListingState),
    PromptOverrideHash(Result<Option<String>, String>),
    HealthChecks(ViewHealthChecks),
    TargetProfile(TargetProfile),
    MapArtifacts(bool),
    CpgArtifacts(bool),
    ScanRecommendations(ScanRecommendationsState),
    TargetBase(String),
}

#[derive(Debug, Clone)]
pub(crate) struct JsonFileHydration {
    pub(crate) state: JsonFileState,
    pub(crate) content_sha256: Option<String>,
    pub(crate) entry_point_catalog_authentication: Option<
        Result<kuzushi_core::capabilities::entry_points::EntryPointCatalogAuthentication, String>,
    >,
    pub(crate) entry_point_catalog_context_authentication:
        Option<EntryPointCatalogContextAuthentication>,
}

#[derive(Debug, Clone)]
pub(crate) enum EntryPointCatalogContextAuthentication {
    Authenticated(kuzushi_core::capabilities::entry_points::EntryPointCatalogAuthentication),
    Rejected(String),
    Unavailable(String),
}

impl JsonFileHydration {
    pub(crate) fn state(state: JsonFileState) -> Self {
        Self {
            state,
            content_sha256: None,
            entry_point_catalog_authentication: None,
            entry_point_catalog_context_authentication: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ViewHealthChecks {
    pub(crate) semgrep_error: Option<String>,
    pub(crate) codeql_error: Option<String>,
    pub(crate) credential_set: bool,
}

#[derive(Debug)]
pub(crate) struct ViewHydrationResult {
    pub(crate) target: PathBuf,
    pub(crate) key: ViewHydrationKey,
    pub(crate) value: ViewHydrationValue,
}

#[derive(Debug)]
pub(crate) struct ViewHydrationFailure {
    pub(crate) target: PathBuf,
    pub(crate) key: ViewHydrationKey,
}

#[derive(Debug, Default)]
pub(crate) struct ViewHydrationDrain {
    pub(crate) results: Vec<ViewHydrationResult>,
    pub(crate) failures: Vec<ViewHydrationFailure>,
}

pub(crate) trait ViewArtifactReader: std::fmt::Debug + Send + Sync {
    fn read(&self, target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue;

    fn read_cancellable(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
        cancellation: &ViewHydrationCancellation,
    ) -> Option<ViewHydrationValue> {
        (!cancellation.is_canceled()).then(|| self.read(target, key))
    }
}

impl ShellApp {
    pub(crate) fn schedule_active_view_hydration(&mut self) -> bool {
        let Some(target) = self.active_view_hydration_scope() else {
            return false;
        };
        let keys = self.pending_active_view_hydration_keys(&target);
        self.schedule_view_hydration_keys(target, keys)
    }

    pub(crate) fn schedule_target_profile_hydration(&mut self, target: &Path) -> bool {
        let key = ViewHydrationKey::TargetProfile;
        let needed = self
            .workbench_cache()
            .borrow()
            .view_hydration_needed(target, &key);
        needed && self.schedule_view_hydration_keys(target.to_path_buf(), vec![key])
    }

    pub(crate) fn apply_view_hydration_results(&mut self) -> bool {
        let scheduled = self.schedule_pending_findings_refresh();
        let drain = self.runtime_state.drain_view_hydration();
        if drain.results.is_empty() && drain.failures.is_empty() {
            return scheduled;
        }
        self.apply_view_hydration_drain(drain);
        true
    }

    pub(crate) fn hydrate_active_view_blocking(&mut self) {
        for _ in 0..3 {
            let Some(target) = self.active_view_hydration_scope() else {
                return;
            };
            let keys = self.pending_active_view_hydration_keys(&target);
            if keys.is_empty() {
                return;
            }
            self.workbench_cache()
                .borrow_mut()
                .mark_view_hydration_loading(&target, &keys);
            let drain = self.runtime_state.hydrate_view_blocking(target, keys);
            self.apply_view_hydration_drain(drain);
        }
    }

    pub(crate) fn hydrate_view_keys_blocking(
        &mut self,
        target: &Path,
        keys: Vec<ViewHydrationKey>,
    ) {
        let keys = {
            let cache = self.workbench_cache().borrow();
            keys.into_iter()
                .filter(|key| cache.view_hydration_needed(target, key))
                .collect::<Vec<_>>()
        };
        if keys.is_empty() {
            return;
        }
        self.workbench_cache()
            .borrow_mut()
            .mark_view_hydration_loading(target, &keys);
        let drain = self
            .runtime_state
            .hydrate_view_blocking(target.to_path_buf(), keys);
        self.apply_view_hydration_drain(drain);
    }

    pub(crate) fn invalidate_view_hydration(&mut self) {
        self.runtime_state.invalidate_view_hydration();
        self.editor_mut().invalidate_completion_preview();
        self.workbench_cache()
            .borrow_mut()
            .clear_view_hydration_loading();
    }

    fn apply_view_hydration_drain(&mut self, drain: ViewHydrationDrain) {
        let drain = self.apply_findings_projection_drain(drain);
        let refresh_file_picker = drain
            .results
            .iter()
            .any(|result| result.key == ViewHydrationKey::FileCompletionValues);
        let refresh_target_profile = drain.results.iter().any(|result| {
            matches!(
                (&result.key, &result.value),
                (
                    ViewHydrationKey::TargetProfile,
                    ViewHydrationValue::TargetProfile(_)
                )
            )
        });
        let recovered_runs = drain
            .results
            .iter()
            .filter_map(|result| match &result.value {
                ViewHydrationValue::RunSummaryEntries(hydration) => {
                    Some(hydration.newly_recovered.as_slice())
                }
                _ => None,
            })
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        {
            let mut cache = self.workbench_cache().borrow_mut();
            for result in drain.results {
                cache.apply_view_hydration(result);
            }
            cache.clear_failed_view_hydrations(&drain.failures);
        }
        if refresh_file_picker {
            self.refresh_open_file_picker_candidates();
        }
        if refresh_target_profile {
            self.apply_ready_target_profile();
        }
        self.disclose_returning_workspace_drift();
        self.announce_recovered_runs(&recovered_runs);
        self.refresh_study_usage_from_cache();
    }

    fn disclose_returning_workspace_drift(&mut self) {
        let (current, history) = {
            let cache = self.workbench_cache().borrow();
            (
                cache.cached_git_metadata(self.target()),
                cache.cached_run_summary_entries(self.target()),
            )
        };
        let (
            ViewDataState::Ready(Some(current)),
            ViewDataState::Ready(RunSummaryEntriesState::Ready(history)),
        ) = (current, history)
        else {
            return;
        };
        self.domain_mut()
            .set_returning_source_unverified(returning_source_unverified(&current, &history));
        if self.workspace_stale().is_some() {
            return;
        }
        let Some((change, message)) = returning_workspace_drift(&current, &history) else {
            return;
        };
        self.domain_mut().apply_workspace_changes(&[change]);
        self.log("workspace", message);
    }

    fn announce_recovered_runs(&mut self, recovered: &[kuzushi_core::RecoveredRun]) {
        let Some(first) = recovered.first() else {
            return;
        };
        let message = if recovered.len() == 1 {
            let run_ref = crate::app::compact_run_reference(&first.run_id);
            format!(
                "Recovered 1 abandoned run as interrupted · {run_ref} · open `jobs` or `replay {run_ref}`"
            )
        } else {
            format!(
                "Recovered {} abandoned runs as interrupted · open `jobs`",
                recovered.len()
            )
        };
        self.set_warn_notice("recovery", message);
    }

    fn pending_active_view_hydration_keys(&self, target: &Path) -> Vec<ViewHydrationKey> {
        let keys = active_view_hydration_keys(self);
        let cache = self.workbench_cache().borrow();
        keys.into_iter()
            .filter(|key| cache.view_hydration_needed(target, key))
            .collect()
    }

    fn schedule_view_hydration_keys(
        &mut self,
        target: PathBuf,
        keys: Vec<ViewHydrationKey>,
    ) -> bool {
        if keys.is_empty() {
            return false;
        }
        let scheduled = self
            .runtime_state
            .schedule_view_hydration(target.clone(), keys);
        if scheduled.is_empty() {
            return false;
        }
        self.workbench_cache()
            .borrow_mut()
            .mark_view_hydration_loading(&target, &scheduled);
        true
    }

    fn active_view_hydration_scope(&self) -> Option<PathBuf> {
        self.target_owned().or_else(|| {
            let keys = active_view_hydration_keys(self);
            (!keys.is_empty()
                && keys
                    .iter()
                    .all(|key| matches!(key, ViewHydrationKey::HealthChecks { .. })))
            .then(|| PathBuf::from(GLOBAL_HEALTH_HYDRATION_SCOPE))
        })
    }

    #[cfg(test)]
    pub(crate) fn set_view_artifact_reader_for_test(
        &mut self,
        reader: std::sync::Arc<dyn ViewArtifactReader>,
    ) {
        self.runtime_state.set_view_artifact_reader(reader);
        self.workbench_cache()
            .borrow_mut()
            .clear_view_hydration_loading();
    }

    #[doc(hidden)]
    pub fn hydrate_all_view_data_for_test(&mut self) {
        let original = self.shell_view();
        for view in [
            ShellView::Workbench,
            ShellView::Recommend,
            ShellView::Module,
            ShellView::PromptsEditor,
            ShellView::Threat,
            ShellView::Health,
            ShellView::ProjectModel,
            ShellView::StrategyQueue,
            ShellView::FailureHandoff,
            ShellView::Runs,
        ] {
            self.set_shell_view(view);
            self.hydrate_active_view_blocking();
        }
        self.set_shell_view(original);
    }
}

fn returning_workspace_drift(
    current: &RunTargetGitMetadata,
    history: &[kuzushi_core::RunSummaryEntry],
) -> Option<(kuzushi_core::incremental_index::WorkspaceChange, String)> {
    let prior = latest_run_git(history)?;
    if prior.sha != current.sha {
        return Some((
            kuzushi_core::incremental_index::WorkspaceChange::GitHeadChanged,
            format!(
                "workspace changed since the latest run · {} → {}",
                compact_revision(&prior.sha),
                compact_revision(&current.sha)
            ),
        ));
    }
    None
}

fn returning_source_unverified(
    current: &RunTargetGitMetadata,
    history: &[kuzushi_core::RunSummaryEntry],
) -> bool {
    latest_run_git(history)
        .is_some_and(|prior| prior.sha == current.sha && (prior.dirty || current.dirty))
}

fn latest_run_git(history: &[kuzushi_core::RunSummaryEntry]) -> Option<&RunTargetGitMetadata> {
    history.iter().find_map(|entry| match &entry.state {
        kuzushi_core::RunSummaryEntryState::Ready(summary) => summary.target_git.as_ref(),
        kuzushi_core::RunSummaryEntryState::Issue(_) => None,
    })
}

fn compact_revision(revision: &str) -> &str {
    revision.get(..revision.len().min(8)).unwrap_or(revision)
}
