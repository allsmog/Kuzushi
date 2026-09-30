use super::{
    reusable_stage_prefix_len, stage_implementation_identity, StageCheckpointFile,
    StageCheckpointHandle, STAGE_CHECKPOINT_VERSION,
};
use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

thread_local! {
    static ACTIVE_STAGE_CHECKPOINTS: RefCell<Vec<Option<Arc<StageCheckpointHandle>>>> =
        const { RefCell::new(Vec::new()) };
}

/// Dispatch-scoped installation of the active stage-checkpoint handle. One
/// scope is pushed per dispatch (None for non-staged tools) so nested tool
/// dispatch never leaks a parent's handle into a child executor.
pub struct StageCheckpointScope {
    _private: (),
}

impl StageCheckpointScope {
    pub fn install(handle: Option<Arc<StageCheckpointHandle>>) -> Self {
        ACTIVE_STAGE_CHECKPOINTS.with(|stack| stack.borrow_mut().push(handle));
        Self { _private: () }
    }
}

impl Drop for StageCheckpointScope {
    fn drop(&mut self) {
        ACTIVE_STAGE_CHECKPOINTS.with(|stack| {
            stack.borrow_mut().pop();
        });
    }
}

/// The stage-checkpoint handle of the innermost active dispatch on this
/// thread. Executors that spawn worker threads must capture the Arc first.
pub fn active_stage_checkpoints() -> Option<Arc<StageCheckpointHandle>> {
    ACTIVE_STAGE_CHECKPOINTS.with(|stack| stack.borrow().last().cloned().flatten())
}

/// Machine-usable resume coordinates for a failed run, read back from the
/// checkpoint the run wrote. Feeds `failures.json` and TUI disclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageCheckpointCoordinates {
    pub fingerprint: String,
    pub resume_from: Option<String>,
    pub completed_stages: Vec<String>,
    pub checkpoint_artifacts: Vec<String>,
}

pub fn checkpoint_coordinates_for_run(
    target: &Path,
    run_id: &str,
) -> Option<StageCheckpointCoordinates> {
    checkpoint_files(target)
        .into_iter()
        .find(|(_, file)| file.source_run_id == run_id)
        .map(|(_, file)| coordinates(target, file))
}

/// Continuation coordinates are eligible only when they match the operation
/// requested by that exact failed run and retain at least one reusable stage.
pub fn matching_checkpoint_coordinates_for_run(
    target: &Path,
    run_id: &str,
) -> Option<StageCheckpointCoordinates> {
    let coordinates = checkpoint_coordinates_for_run(target, run_id)?;
    let requested = requested_operation_fingerprint(target, run_id)?;
    (requested == coordinates.fingerprint && !coordinates.completed_stages.is_empty())
        .then_some(coordinates)
}

fn requested_operation_fingerprint(target: &Path, run_id: &str) -> Option<String> {
    let read = crate::run_lifecycle::read_run_items(target, run_id).ok()??;
    read.items.into_iter().find_map(|envelope| {
        let crate::run_lifecycle::RunItemV1::ToolCallRequested {
            operation_fingerprint,
            ..
        } = envelope.item
        else {
            return None;
        };
        operation_fingerprint
            .as_str()
            .strip_prefix("blake3:")
            .map(str::to_string)
    })
}

fn coordinates(target: &Path, file: StageCheckpointFile) -> StageCheckpointCoordinates {
    let reusable = reusable_stage_prefix_len(target, &file.completed);
    let completed = &file.completed[..reusable];
    let resume_from = if reusable < file.completed.len() {
        Some(file.completed[reusable].stage.clone())
    } else {
        file.current_stage
    };
    StageCheckpointCoordinates {
        fingerprint: file.fingerprint,
        resume_from,
        completed_stages: completed
            .iter()
            .map(|receipt| receipt.stage.clone())
            .collect(),
        checkpoint_artifacts: completed
            .iter()
            .flat_map(|receipt| receipt.artifacts.iter().cloned())
            .collect(),
    }
}

/// A saved-but-unconsumed stage checkpoint: a failed staged run whose
/// completed stages wait to be resumed by re-running the same operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingStageCheckpoint {
    pub tool: String,
    pub source_run_id: String,
    pub completed_stages: u32,
    pub current_stage: Option<String>,
    pub modified_at_unix: Option<u64>,
    pub reuse_eligible: bool,
}

/// List the target's pending stage checkpoints, newest first. Presentation
/// surfaces use this to disclose that re-running the failed operation
/// resumes from its checkpointed stages.
pub fn pending_stage_checkpoints(target: &Path) -> Vec<PendingStageCheckpoint> {
    let source_identity = crate::incremental_index::current_workspace_resume_identity(target).ok();
    let mut pending: Vec<PendingStageCheckpoint> = checkpoint_files(target)
        .into_iter()
        .map(|(path, file)| pending_checkpoint(target, path, file, source_identity.as_deref()))
        .collect();
    pending.sort_by_key(|entry| std::cmp::Reverse(entry.modified_at_unix));
    pending
}

fn pending_checkpoint(
    target: &Path,
    path: PathBuf,
    file: StageCheckpointFile,
    source_identity: Option<&str>,
) -> PendingStageCheckpoint {
    let source_matches = source_identity.is_some_and(|current| file.source_identity == current);
    let reusable = if source_matches {
        reusable_stage_prefix_len(target, &file.completed)
    } else {
        0
    };
    let current_stage = if !source_matches {
        None
    } else if reusable < file.completed.len() {
        Some(file.completed[reusable].stage.clone())
    } else {
        file.current_stage.clone()
    };
    PendingStageCheckpoint {
        tool: file.tool,
        source_run_id: file.source_run_id,
        completed_stages: reusable as u32,
        current_stage,
        modified_at_unix: modified_at_unix(&path),
        reuse_eligible: reusable > 0,
    }
}

fn checkpoint_files(target: &Path) -> Vec<(PathBuf, StageCheckpointFile)> {
    let dir = target.join(".kuzushi").join("v3").join("checkpoints");
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| is_stage_checkpoint_leaf(path))
        .filter_map(|path| parse_checkpoint_file(&path).map(|file| (path, file)))
        .collect()
}

fn is_stage_checkpoint_leaf(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("stage-") && name.ends_with(".json"))
}

fn parse_checkpoint_file(path: &Path) -> Option<StageCheckpointFile> {
    let raw = crate::bounded_file::read_utf8_text(path, 8 * 1024 * 1024).ok()?;
    let file = serde_json::from_str::<StageCheckpointFile>(&raw).ok()?;
    let implementation_identity = stage_implementation_identity()?;
    (file.version == STAGE_CHECKPOINT_VERSION
        && file.implementation_identity == implementation_identity)
        .then_some(file)
}

fn modified_at_unix(path: &Path) -> Option<u64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let elapsed = modified.duration_since(UNIX_EPOCH).ok()?;
    Some(elapsed.as_secs())
}
