use super::tool_stage::{append_tool_stage_receipt, ToolStageReceipt};
use super::*;
use crate::run_artifacts::scan_stage::PhaseStageOutcome;
use std::sync::Mutex;

#[path = "stage_checkpoint/discovery.rs"]
mod discovery;
pub use discovery::{
    active_stage_checkpoints, checkpoint_coordinates_for_run, pending_stage_checkpoints,
    PendingStageCheckpoint, StageCheckpointCoordinates, StageCheckpointScope,
};

#[cfg(test)]
#[path = "stage_checkpoint/tests.rs"]
mod tests;

/// Cross-run stage checkpoint for `ContinuationSupport::Staged` tools.
///
/// A multi-stage tool that fails mid-flight has already paid for every
/// completed stage. Dispatch discovers a checkpoint keyed by the operation
/// fingerprint (same registry, descriptor, tool, input, workspace) before
/// invoking the executor; the tool skips stages whose receipts and artifacts
/// survive, and re-dispatching the identical operation after a failure
/// resumes at the failed stage. Completion clears the checkpoint. All writes
/// are best-effort: a failed checkpoint write must never fail the paid run.
pub(super) const STAGE_CHECKPOINT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StageCheckpointFile {
    pub version: u32,
    /// Full hex operation fingerprint; the file name carries the first 16
    /// chars, the body keeps the whole value for match validation.
    pub fingerprint: String,
    pub tool: String,
    /// The run that most recently wrote this checkpoint.
    pub source_run_id: String,
    /// Workspace content identity at write time (clean git revision). None
    /// for dirty or non-git targets — resume proceeds but discloses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_identity: Option<String>,
    /// Last stage that started but has not completed — the resume point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_stage: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completed: Vec<ToolStageReceipt>,
}

pub struct StageCheckpointStore {
    path: PathBuf,
    fingerprint: String,
}

impl StageCheckpointStore {
    /// A store exists only when the target is already a Kuzushi workspace —
    /// the checkpoint must never be the reason `.kuzushi` appears somewhere.
    pub fn discover(target: &Path, operation_fingerprint: &[u8; 32]) -> Option<Self> {
        let kuzushi_dir = target.join(".kuzushi");
        if !kuzushi_dir.is_dir() {
            return None;
        }
        let fingerprint = hex_fingerprint(operation_fingerprint);
        let path = kuzushi_dir
            .join("v3")
            .join("checkpoints")
            .join(format!("stage-{}.json", &fingerprint[..16]));
        Some(Self { path, fingerprint })
    }

    fn load(&self) -> Option<StageCheckpointFile> {
        let raw = fs::read_to_string(&self.path).ok()?;
        let file = serde_json::from_str::<StageCheckpointFile>(&raw).ok()?;
        let matches =
            file.version == STAGE_CHECKPOINT_VERSION && file.fingerprint == self.fingerprint;
        matches.then_some(file)
    }

    fn save(&self, file: &StageCheckpointFile) {
        let Ok(serialized) = serde_json::to_string(file) else {
            return;
        };
        let _ = write_checkpoint_atomically(&self.path, &serialized);
    }

    pub fn clear(&self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn write_checkpoint_atomically(path: &Path, contents: &str) -> std::io::Result<()> {
    let parent = path.parent().expect("checkpoint path has a parent");
    fs::create_dir_all(parent)?;
    let temp = path.with_extension("json.tmp");
    fs::write(&temp, contents)?;
    fs::rename(&temp, path)
}

fn hex_fingerprint(fingerprint: &[u8; 32]) -> String {
    fingerprint.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct StageCheckpointState {
    prior: Vec<ToolStageReceipt>,
    completed_now: Vec<ToolStageReceipt>,
    current: Option<String>,
}

/// Live checkpoint handle for one dispatched run of a `Staged` tool.
///
/// Cross-thread note: dispatch installs the handle for the executor's
/// thread. Executors that fan work out to worker threads must capture the
/// `Arc` (via `ToolExecutionContext::stage_checkpoints`) before spawning.
pub struct StageCheckpointHandle {
    store: StageCheckpointStore,
    target: PathBuf,
    run_id: String,
    tool: String,
    tree_identity: Option<String>,
    resumed_from: Option<String>,
    state: Mutex<StageCheckpointState>,
}

impl StageCheckpointHandle {
    pub fn open(store: StageCheckpointStore, target: &Path, run_id: &str, tool: &str) -> Self {
        let tree_identity = clean_tree_identity(target);
        let prior_file = store
            .load()
            .filter(|file| prior_checkpoint_is_fresh(file, tool, tree_identity.as_deref()));
        let resumed_from = prior_file.as_ref().map(|file| file.source_run_id.clone());
        let prior = prior_file.map(|file| file.completed).unwrap_or_default();
        Self {
            store,
            target: target.to_path_buf(),
            run_id: run_id.to_string(),
            tool: tool.to_string(),
            tree_identity,
            resumed_from,
            state: Mutex::new(StageCheckpointState {
                prior,
                completed_now: Vec::new(),
                current: None,
            }),
        }
    }

    /// The failed run whose completed stages this run resumes, when any.
    pub fn resumed_from(&self) -> Option<String> {
        self.resumed_from.clone()
    }

    /// A completed receipt for `stage`, only while every artifact it
    /// declared still exists — otherwise the stage must re-run.
    pub fn completed_stage(&self, stage: &str) -> Option<ToolStageReceipt> {
        let state = self.state.lock().ok()?;
        state
            .completed_now
            .iter()
            .chain(state.prior.iter())
            .find(|receipt| receipt.stage == stage)
            .filter(|receipt| self.artifacts_exist(receipt))
            .cloned()
    }

    /// Begin a stage: records it as the resume point and returns the RAII
    /// guard. Dropping the guard without `complete`/`skip` records nothing —
    /// an incomplete stage is implied by absence.
    pub fn stage(&self, stage: &str) -> StageGuard<'_> {
        self.mark_current(stage);
        StageGuard {
            handle: self,
            stage: stage.to_string(),
        }
    }

    /// Persist `stage` as the last started stage so a failure after this
    /// point reports a real resume coordinate.
    pub fn mark_current(&self, stage: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.current = Some(stage.to_string());
            self.save_locked(&state);
        }
    }

    pub fn clear_checkpoint(&self) {
        self.store.clear();
    }

    /// Persist a JSON payload as this stage's durable artifact under the
    /// run dir, returning its target-relative path for `StageGuard::complete`.
    /// Best-effort: None when the write fails.
    pub fn write_stage_payload(&self, stage: &str, payload: &Value) -> Option<String> {
        let leaf = format!("stage-{}.json", sanitized_stage_leaf(stage));
        let artifact =
            write_run_artifact_json(&self.target, &self.run_id, &leaf, "stage payload", payload)
                .ok()?;
        relative_to_target(&self.target, &artifact.path)
    }

    /// Read back the payload a completed stage persisted (possibly in a
    /// prior failed run).
    pub fn read_stage_payload(&self, receipt: &ToolStageReceipt) -> Option<Value> {
        let relative = receipt.artifacts.first()?;
        let raw = fs::read_to_string(self.target.join(relative)).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn artifacts_exist(&self, receipt: &ToolStageReceipt) -> bool {
        receipt
            .artifacts
            .iter()
            .all(|artifact| self.target.join(artifact).exists())
    }

    fn record_completed(&self, stage: &str, artifacts: Vec<String>) {
        let receipt = stage_receipt(stage, PhaseStageOutcome::Completed, artifacts, None);
        let _ = append_tool_stage_receipt(&self.target, &self.run_id, &receipt);
        if let Ok(mut state) = self.state.lock() {
            state.prior.retain(|prior| prior.stage != stage);
            state.completed_now.push(receipt);
            state.current = None;
            self.save_locked(&state);
        }
    }

    fn record_skipped(&self, stage: &str, detail: &str) {
        let receipt = stage_receipt(
            stage,
            PhaseStageOutcome::Skipped,
            Vec::new(),
            Some(detail.to_string()),
        );
        let _ = append_tool_stage_receipt(&self.target, &self.run_id, &receipt);
        if let Ok(mut state) = self.state.lock() {
            if state.current.as_deref() == Some(stage) {
                state.current = None;
                self.save_locked(&state);
            }
        }
    }

    fn save_locked(&self, state: &StageCheckpointState) {
        let completed = state
            .prior
            .iter()
            .chain(state.completed_now.iter())
            .cloned()
            .collect();
        self.store.save(&StageCheckpointFile {
            version: STAGE_CHECKPOINT_VERSION,
            fingerprint: self.store.fingerprint.clone(),
            tool: self.tool.clone(),
            source_run_id: self.run_id.clone(),
            tree_identity: self.tree_identity.clone(),
            current_stage: state.current.clone(),
            completed,
        });
    }
}

/// A prior checkpoint is only trusted for the same tool and, when both
/// sides know their tree identity, the same workspace content.
fn prior_checkpoint_is_fresh(
    file: &StageCheckpointFile,
    tool: &str,
    tree_identity: Option<&str>,
) -> bool {
    if file.tool != tool {
        return false;
    }
    match (file.tree_identity.as_deref(), tree_identity) {
        (Some(prior), Some(current)) => prior == current,
        _ => true,
    }
}

fn sanitized_stage_leaf(stage: &str) -> String {
    stage
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn relative_to_target(target: &Path, path: &str) -> Option<String> {
    let path = Path::new(path);
    let relative = path.strip_prefix(target).unwrap_or(path);
    Some(relative.to_string_lossy().replace('\\', "/"))
}

fn clean_tree_identity(target: &Path) -> Option<String> {
    crate::workspace::target_git_metadata(target)
        .filter(|metadata| !metadata.dirty)
        .map(|metadata| metadata.sha)
}

fn stage_receipt(
    stage: &str,
    outcome: PhaseStageOutcome,
    artifacts: Vec<String>,
    detail: Option<String>,
) -> ToolStageReceipt {
    ToolStageReceipt {
        stage: stage.to_string(),
        outcome,
        artifacts,
        detail,
        recorded_at_ms: epoch_ms(),
    }
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// RAII guard for one stage. `complete` records the paid work durably;
/// dropping without a call records nothing.
pub struct StageGuard<'a> {
    handle: &'a StageCheckpointHandle,
    stage: String,
}

impl StageGuard<'_> {
    pub fn complete(self, artifacts: Vec<String>) {
        self.handle.record_completed(&self.stage, artifacts);
    }

    pub fn skip(self, detail: &str) {
        self.handle.record_skipped(&self.stage, detail);
    }
}
