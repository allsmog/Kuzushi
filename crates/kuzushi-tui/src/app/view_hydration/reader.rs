use super::*;
use kuzushi_core::{CodeqlScanner, ScanEngine, SemgrepScanner};
use kuzushi_core::{LatestRunPointerIssue, LatestRunPointerState};

mod completion_io;
mod workspace_io;
use completion_io::*;
use workspace_io::*;

#[derive(Debug, Default)]
pub(super) struct FsViewArtifactReader;

impl ViewArtifactReader for FsViewArtifactReader {
    fn read(&self, target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        read_artifact_value(target, key).unwrap_or_else(|| read_environment_value(key))
    }

    fn read_cancellable(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
        cancellation: &ViewHydrationCancellation,
    ) -> Option<ViewHydrationValue> {
        if cancellation.is_canceled() {
            return None;
        }
        if key == &ViewHydrationKey::TargetProfile {
            return TargetProfile::detect_cancellable(target, || cancellation.is_canceled())
                .map(ViewHydrationValue::TargetProfile);
        }
        if key != &ViewHydrationKey::FileCompletionValues {
            return Some(self.read(target, key));
        }
        let index = crate::app::workspace_file_candidates_cancellable(
            target,
            crate::app::FILE_PICKER_MAX_FILES,
            || cancellation.is_canceled(),
        )?;
        Some(ViewHydrationValue::FileCompletionValues(index))
    }
}

fn read_artifact_value(target: &Path, key: &ViewHydrationKey) -> Option<ViewHydrationValue> {
    read_completion_value(target, key)
        .or_else(|| read_run_value(target, key))
        .or_else(|| read_project_value(target, key))
        .or_else(|| read_workspace_file_value(target, key))
}

fn read_run_value(target: &Path, key: &ViewHydrationKey) -> Option<ViewHydrationValue> {
    const RECENT_RUN_HISTORY_LIMIT: usize = 100;
    match key {
        ViewHydrationKey::LatestRunPointer => Some(read_latest_pointer(target)),
        ViewHydrationKey::RunSummaryEntries => Some(ViewHydrationValue::RunSummaryEntries(
            read_recent_run_history(target, RECENT_RUN_HISTORY_LIMIT),
        )),
        ViewHydrationKey::RunArtifactText { run_id, leaf } => {
            Some(ViewHydrationValue::RunArtifactText(
                kuzushi_core::read_run_artifact_text(target, run_id, leaf),
            ))
        }
        ViewHydrationKey::RunTrace { run_id } => Some(ViewHydrationValue::RunTrace(
            kuzushi_core::load_run_trace(target, run_id).ok(),
        )),
        _ => None,
    }
}

fn read_recent_run_history(target: &Path, limit: usize) -> RunSummaryEntriesState {
    match kuzushi_core::list_recent_run_summary_entries(target, limit) {
        Ok(entries) => RunSummaryEntriesState::Ready(entries),
        Err(error) => RunSummaryEntriesState::Failed(error.to_string()),
    }
}

fn read_project_value(target: &Path, key: &ViewHydrationKey) -> Option<ViewHydrationValue> {
    match key {
        ViewHydrationKey::GitMetadata => Some(ViewHydrationValue::GitMetadata(
            kuzushi_core::workspace::target_git_metadata(target),
        )),
        ViewHydrationKey::ProjectScopeTree => Some(ViewHydrationValue::ProjectScopeTree(
            project_scope_tree(target),
        )),
        ViewHydrationKey::ProjectModelDocument { scope_id, revision } => {
            Some(ViewHydrationValue::ProjectModelDocument(
                kuzushi_core::workspace::load_project_model_document(
                    target,
                    scope_id,
                    revision.as_deref(),
                )
                .ok()
                .flatten(),
            ))
        }
        ViewHydrationKey::StrategyQueue => {
            Some(ViewHydrationValue::StrategyQueue(strategy_queue(target)))
        }
        ViewHydrationKey::PromptMutations => Some(ViewHydrationValue::PromptMutations(
            prompt_mutations(target),
        )),
        ViewHydrationKey::TargetProfile => Some(ViewHydrationValue::TargetProfile(
            TargetProfile::detect(target),
        )),
        ViewHydrationKey::MapArtifacts => Some(ViewHydrationValue::MapArtifacts(
            map_artifact_exists(target),
        )),
        ViewHydrationKey::TargetBase => Some(ViewHydrationValue::TargetBase(target_base(target))),
        _ => None,
    }
}

fn read_workspace_file_value(target: &Path, key: &ViewHydrationKey) -> Option<ViewHydrationValue> {
    match key {
        ViewHydrationKey::SourceFile { path } => Some(ViewHydrationValue::SourceFile(
            read_workspace_text(target, path, MAX_VIEW_SOURCE_BYTES),
        )),
        ViewHydrationKey::HarnessFile => Some(ViewHydrationValue::HarnessFile(
            read_optional_workspace_text(
                target,
                &crate::app::harness_file_path(target),
                MAX_VIEW_HARNESS_BYTES,
            )
            .ok()
            .flatten(),
        )),
        ViewHydrationKey::JsonFile { path } => {
            Some(ViewHydrationValue::JsonFile(read_json_file(target, path)))
        }
        ViewHydrationKey::PathState { path } => Some(ViewHydrationValue::PathState(
            inspect_view_path(target, path),
        )),
        ViewHydrationKey::DirectoryListing { path } => Some(ViewHydrationValue::DirectoryListing(
            read_directory(target, path),
        )),
        ViewHydrationKey::PromptOverrideHash { path } => Some(
            ViewHydrationValue::PromptOverrideHash(prompt_override_hash(target, path)),
        ),
        _ => None,
    }
}

fn read_environment_value(key: &ViewHydrationKey) -> ViewHydrationValue {
    let ViewHydrationKey::HealthChecks { credential_env } = key else {
        unreachable!("view hydration key was not assigned to a reader boundary")
    };
    ViewHydrationValue::HealthChecks(health_checks(credential_env))
}

fn read_latest_pointer(target: &Path) -> ViewHydrationValue {
    let state = kuzushi_core::read_latest_run_pointer(target).unwrap_or_else(|error| {
        LatestRunPointerState::Invalid(LatestRunPointerIssue::UnsafePath(error.to_string()))
    });
    ViewHydrationValue::LatestRunPointer(state)
}

fn map_artifact_exists(target: &Path) -> bool {
    PlanningTaskId::in_phase(WorkflowPhase::Map)
        .into_iter()
        .filter_map(PlanningTaskId::artifact_relative_path)
        .any(|relative| valid_map_artifact(target, relative))
}

fn valid_map_artifact(target: &Path, relative: &str) -> bool {
    let Ok(Some(checked)) = checked_workspace_path(target, &target.join(relative)) else {
        return false;
    };
    if relative == ".kuzushi/codeql-db" {
        checked.metadata.is_dir()
    } else {
        checked.metadata.is_file()
    }
}

fn project_scope_tree(target: &Path) -> ProjectScopeTreeState {
    match kuzushi_core::load_nested_project_scopes(target) {
        Ok(Some(tree)) => ProjectScopeTreeState::Persisted(tree),
        Ok(None) => ProjectScopeTreeState::RootOnly,
        Err(error) => ProjectScopeTreeState::Unreadable(error.to_string()),
    }
}

fn strategy_queue(target: &Path) -> StrategyQueueState {
    let workspace = match kuzushi_core::WorkspaceTarget::new(target) {
        Ok(workspace) => workspace,
        Err(error) => return StrategyQueueState::Unreadable(error.to_string()),
    };
    match kuzushi_core::load_strategy_queue(&workspace) {
        Ok(proposals) => StrategyQueueState::Ready(proposals),
        Err(error) => StrategyQueueState::Unreadable(error.to_string()),
    }
}

fn prompt_mutations(target: &Path) -> PromptMutationsState {
    let workspace = match kuzushi_core::WorkspaceTarget::new(target) {
        Ok(workspace) => workspace,
        Err(_) => return PromptMutationsState::Unreadable,
    };
    match kuzushi_core::load_prompt_mutations(&workspace) {
        Ok(mutations) => PromptMutationsState::Ready(mutations),
        Err(_) => PromptMutationsState::Unreadable,
    }
}

fn target_base(target: &Path) -> String {
    target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn inspect_path(path: &Path) -> PathState {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => PathState::Other,
        Ok(metadata) if metadata.is_file() => PathState::File {
            len: metadata.len(),
        },
        Ok(metadata) if metadata.is_dir() => PathState::Directory,
        Ok(_) => PathState::Other,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => PathState::Missing,
        Err(_) => PathState::Unreadable,
    }
}

fn inspect_view_path(target: &Path, path: &Path) -> PathState {
    if path.starts_with(target) {
        inspect_workspace_path(target, path)
    } else {
        inspect_path(path)
    }
}

fn health_checks(credential_env: &str) -> ViewHealthChecks {
    ViewHealthChecks {
        semgrep_error: SemgrepScanner::default()
            .preflight()
            .err()
            .map(|error| error.to_string()),
        codeql_error: CodeqlScanner::default()
            .preflight()
            .err()
            .map(|error| error.to_string()),
        joern_path: configured_binary("KUZUSHI_JOERN_BIN")
            .or_else(|| kuzushi_core::executable_on_path("joern"))
            .or_else(fallback_joern_path),
        credential_set: env_is_set(credential_env),
        configured_joern_cpg: configured_path("KUZUSHI_JOERN_CPG"),
    }
}

fn fallback_joern_path() -> Option<PathBuf> {
    [
        "/opt/joern/joern-cli/joern",
        "/usr/local/bin/joern",
        "/usr/bin/joern",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| matches!(inspect_path(path), PathState::File { .. }))
}

fn configured_binary(name: &str) -> Option<PathBuf> {
    configured_path(name).filter(|path| matches!(inspect_path(path), PathState::File { .. }))
}

fn configured_path(name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os(name)?);
    (!path.as_os_str().is_empty()).then_some(path)
}

fn env_is_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}
