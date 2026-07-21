use super::*;
use kuzushi_core::workspace::ProjectModelDocument;
use kuzushi_core::{
    LatestRunPointerState, RunArtifactTextRead, RunSummaryEntry, RunTargetGitMetadata, RunTraceRead,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(test)]
mod completion_tests;
mod reader;
#[cfg(test)]
mod reader_tests;
mod requests;
mod runtime;
#[cfg(test)]
mod tests;

use requests::active_view_hydration_keys;
pub(crate) use runtime::ViewHydrationRuntime;

pub(crate) const GLOBAL_HEALTH_HYDRATION_SCOPE: &str = "global-health-view-data";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FindingPatchTruthState {
    Ready(FindingPatchTruth),
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
    canceled: Arc<AtomicBool>,
}

impl ViewHydrationCancellation {
    pub(crate) fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
    }

    pub(crate) fn is_canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ViewHydrationKey {
    FileCompletionValues,
    FindingCompletionValues,
    RunIdCompletionValues,
    LatestRunPointer,
    RunSummaryEntries,
    RunArtifactText {
        run_id: String,
        leaf: String,
    },
    RunTrace {
        run_id: String,
    },
    RunProjection {
        run_id: String,
    },
    ScanStageReceipt {
        run_id: String,
    },
    FindingPatchTruth {
        fingerprint: String,
        finding_scan_id: Option<String>,
        target_revision: Option<String>,
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
    ProjectScopeTree,
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
    TargetProfile,
    MapArtifacts,
    ScanRecommendations,
    TargetBase,
}

#[derive(Debug, Clone)]
pub(crate) enum ViewHydrationValue {
    FileCompletionValues(FileCompletionIndex),
    FindingCompletionValues(Vec<String>),
    RunIdCompletionValues(Vec<String>),
    LatestRunPointer(LatestRunPointerState),
    RunSummaryEntries(RunSummaryEntriesState),
    RunArtifactText(RunArtifactTextRead),
    RunTrace(Option<RunTraceRead>),
    RunProjection(Result<kuzushi_core::run_lifecycle::RunProjectionRead, String>),
    ScanStageReceipt(ScanStageReceiptState),
    FindingPatchTruth(FindingPatchTruthState),
    ScannedSnippet(ScannedSnippetState),
    SourceFile(Result<String, String>),
    GitMetadata(Option<RunTargetGitMetadata>),
    ProjectScopeTree(ProjectScopeTreeState),
    ProjectModelDocument(Option<ProjectModelDocument>),
    StrategyQueue(StrategyQueueState),
    PromptMutations(PromptMutationsState),
    HarnessFile(Option<String>),
    JsonFile(JsonFileState),
    PathState(PathState),
    DirectoryListing(DirectoryListingState),
    PromptOverrideHash(Result<Option<String>, String>),
    HealthChecks(ViewHealthChecks),
    TargetProfile(TargetProfile),
    MapArtifacts(bool),
    ScanRecommendations(ScanRecommendationsState),
    TargetBase(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ViewHealthChecks {
    pub(crate) semgrep_error: Option<String>,
    pub(crate) codeql_error: Option<String>,
    pub(crate) joern_path: Option<PathBuf>,
    pub(crate) credential_set: bool,
    pub(crate) configured_joern_cpg: Option<PathBuf>,
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
        let drain = self.runtime_state.drain_view_hydration();
        if drain.results.is_empty() && drain.failures.is_empty() {
            return false;
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
