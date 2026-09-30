use super::tool_stage::{append_tool_stage_receipt, ToolStageReceipt};
use super::*;
use crate::run_artifacts::scan_stage::PhaseStageOutcome;
use std::collections::BTreeMap;
use std::sync::Mutex;

#[path = "stage_checkpoint/discovery.rs"]
mod discovery;
pub use discovery::{
    active_stage_checkpoints, checkpoint_coordinates_for_run,
    matching_checkpoint_coordinates_for_run, pending_stage_checkpoints, PendingStageCheckpoint,
    StageCheckpointCoordinates, StageCheckpointScope,
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
pub(super) const STAGE_CHECKPOINT_VERSION: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StageCheckpointFile {
    pub version: u32,
    /// Full hex operation fingerprint; the file name carries the first 16
    /// chars, the body keeps the whole value for match validation.
    pub fingerprint: String,
    /// Kuzushi build that owns the staged executor contract. Checkpoints from
    /// another build never cross the live Rust dispatch boundary.
    pub implementation_identity: String,
    pub tool: String,
    /// The run that most recently wrote this checkpoint.
    pub source_run_id: String,
    /// Bounded workspace content identity at write time. Git targets include
    /// the revision as an additional binding; dirty and non-Git targets remain
    /// reusable only while their indexed content is byte-for-byte unchanged.
    pub source_identity: String,
    /// Last stage that started but has not completed — the resume point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_stage: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completed: Vec<ToolStageReceipt>,
}

pub struct StageCheckpointStore {
    path: PathBuf,
    fingerprint: String,
    implementation_identity: String,
}

impl StageCheckpointStore {
    /// A store exists only when the target is already a Kuzushi workspace —
    /// the checkpoint must never be the reason `.kuzushi` appears somewhere.
    pub fn discover(target: &Path, operation_fingerprint: &[u8; 32]) -> Option<Self> {
        let kuzushi_dir = target.join(".kuzushi");
        if !kuzushi_dir.is_dir() {
            return None;
        }
        let implementation_identity = stage_implementation_identity()?;
        let fingerprint = hex_fingerprint(operation_fingerprint);
        let path = kuzushi_dir
            .join("v3")
            .join("checkpoints")
            .join(format!("stage-{}.json", &fingerprint[..16]));
        Some(Self {
            path,
            fingerprint,
            implementation_identity,
        })
    }

    fn load(&self) -> Option<StageCheckpointFile> {
        let raw = crate::bounded_file::read_utf8_text(&self.path, 8 * 1024 * 1024).ok()?;
        let file = serde_json::from_str::<StageCheckpointFile>(&raw).ok()?;
        let matches = file.version == STAGE_CHECKPOINT_VERSION
            && file.fingerprint == self.fingerprint
            && file.implementation_identity == self.implementation_identity;
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
    crate::fs_atomic::write_atomic(path, contents).map_err(std::io::Error::other)
}

fn hex_fingerprint(fingerprint: &[u8; 32]) -> String {
    fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn stage_implementation_identity() -> Option<String> {
    let git_sha = option_env!("KUZUSHI_GIT_SHA")?.trim();
    (!git_sha.is_empty()).then(|| format!("{}@{git_sha}", env!("CARGO_PKG_VERSION")))
}

struct StageCheckpointState {
    prior: Vec<ToolStageReceipt>,
    reused_prior: usize,
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
    source_identity: String,
    resumed_from: Option<String>,
    state: Mutex<StageCheckpointState>,
}

impl StageCheckpointHandle {
    pub fn open(store: StageCheckpointStore, target: &Path, run_id: &str, tool: &str) -> Self {
        let source_identity =
            crate::incremental_index::current_workspace_resume_identity(target).ok();
        Self::open_with_source_identity(store, target, run_id, tool, source_identity)
    }

    fn open_with_source_identity(
        store: StageCheckpointStore,
        target: &Path,
        run_id: &str,
        tool: &str,
        source_identity: Option<String>,
    ) -> Self {
        let prior_file = store
            .load()
            .filter(|file| prior_checkpoint_is_fresh(file, tool, source_identity.as_deref()));
        let (resumed_from, prior) = prior_file
            .map(|file| {
                let mut prior = file.completed;
                let reusable = reusable_stage_prefix_len(target, &prior);
                prior.truncate(reusable);
                let resumed_from = (!prior.is_empty()).then_some(file.source_run_id);
                (resumed_from, prior)
            })
            .unwrap_or_default();
        Self {
            store,
            target: target.to_path_buf(),
            run_id: run_id.to_string(),
            tool: tool.to_string(),
            source_identity: source_identity.unwrap_or_default(),
            resumed_from,
            state: Mutex::new(StageCheckpointState {
                prior,
                reused_prior: 0,
                completed_now: Vec::new(),
                current: None,
            }),
        }
    }

    /// The failed run whose completed stages this run resumes, when any.
    pub fn resumed_from(&self) -> Option<String> {
        self.resumed_from.clone()
    }

    /// A completed receipt for `stage`, only while every stage through it is
    /// still reusable. Stage checkpoints form an ordered dependency chain: if
    /// an upstream artifact is missing or changed, that stage and every later
    /// stage must re-run even when a downstream artifact still matches.
    pub fn completed_stage(&self, stage: &str) -> Option<ToolStageReceipt> {
        let mut state = self.state.lock().ok()?;
        let reusable_prior = reusable_stage_prefix_len(&self.target, &state.prior);
        if reusable_prior < state.prior.len() {
            state.prior.truncate(reusable_prior);
            state.reused_prior = state.reused_prior.min(reusable_prior);
            state.completed_now.clear();
        }
        let reusable_now = reusable_stage_prefix_len(&self.target, &state.completed_now);
        state.completed_now.truncate(reusable_now);
        if let Some(receipt) = state
            .completed_now
            .iter()
            .chain(state.prior[..state.reused_prior].iter())
            .find(|receipt| receipt.stage == stage)
        {
            return Some(receipt.clone());
        }
        let next = state.prior.get(state.reused_prior)?.clone();
        if next.stage != stage {
            let reused = state.reused_prior;
            state.prior.truncate(reused);
            self.save_locked(&state);
            return None;
        }
        state.reused_prior += 1;
        Some(next)
    }

    /// Record that a previously completed stage was consumed by this run.
    /// This writes a visible Skipped receipt and advances checkpoint ownership
    /// without entering the execution path that invalidates a stage suffix.
    pub fn record_reused_stage(&self, stage: &str, detail: &str) {
        let receipt = stage_receipt(
            stage,
            PhaseStageOutcome::Skipped,
            Vec::new(),
            BTreeMap::new(),
            Some(detail.to_string()),
        );
        let Ok(state) = self.state.lock() else {
            return;
        };
        let was_reused = state.prior[..state.reused_prior]
            .iter()
            .chain(state.completed_now.iter())
            .any(|completed| completed.stage == stage);
        if !was_reused {
            return;
        }
        let _ = append_tool_stage_receipt(&self.target, &self.run_id, &receipt);
        self.save_locked(&state);
    }

    /// Begin a stage: records it as the resume point and returns the RAII
    /// guard. Starting a previously completed stage invalidates that stage's
    /// old receipt and every later receipt before execution begins, so a crash
    /// during the rerun cannot resurrect a stale downstream suffix. Dropping
    /// the guard without `complete`/`skip` records no completion.
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
            invalidate_from_stage(&mut state, stage);
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
        write_run_artifact_json(&self.target, &self.run_id, &leaf, "stage payload", payload)
            .ok()?;
        let path = run_dir(&self.target, &self.run_id).join(leaf);
        relative_to_target(&self.target, &path.to_string_lossy())
    }

    /// Read back the payload a completed stage persisted (possibly in a
    /// prior failed run).
    pub fn read_stage_payload(&self, receipt: &ToolStageReceipt) -> Option<Value> {
        let relative = receipt.artifacts.first()?;
        let raw = crate::bounded_file::read_utf8_text_within(
            &self.target,
            &self.target.join(relative),
            8 * 1024 * 1024,
        )
        .ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn record_completed(&self, stage: &str, artifacts: Vec<String>) {
        let artifact_digests = stage_artifact_digests(&self.target, &artifacts);
        let receipt = stage_receipt(
            stage,
            PhaseStageOutcome::Completed,
            artifacts,
            artifact_digests,
            None,
        );
        let _ = append_tool_stage_receipt(&self.target, &self.run_id, &receipt);
        if let Ok(mut state) = self.state.lock() {
            invalidate_from_stage(&mut state, stage);
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
            BTreeMap::new(),
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
            implementation_identity: self.store.implementation_identity.clone(),
            tool: self.tool.clone(),
            source_run_id: self.run_id.clone(),
            source_identity: self.source_identity.clone(),
            current_stage: state.current.clone(),
            completed,
        });
    }
}

fn invalidate_from_stage(state: &mut StageCheckpointState, stage: &str) {
    if let Some(index) = state.prior.iter().position(|prior| prior.stage == stage) {
        state.prior.truncate(index);
        state.reused_prior = state.reused_prior.min(index);
        state.completed_now.clear();
    } else if let Some(index) = state
        .completed_now
        .iter()
        .position(|completed| completed.stage == stage)
    {
        state.completed_now.truncate(index);
    } else if state.reused_prior < state.prior.len() {
        state.prior.truncate(state.reused_prior);
    }
}

/// A prior checkpoint is trusted only for the same tool and exact bounded
/// workspace content identity.
fn prior_checkpoint_is_fresh(
    file: &StageCheckpointFile,
    tool: &str,
    source_identity: Option<&str>,
) -> bool {
    file.tool == tool && source_identity.is_some_and(|current| file.source_identity == current)
}

pub(super) fn reusable_stage_prefix_len(target: &Path, completed: &[ToolStageReceipt]) -> usize {
    completed
        .iter()
        .take_while(|receipt| stage_receipt_artifacts_are_current(target, receipt))
        .count()
}

fn stage_receipt_artifacts_are_current(target: &Path, receipt: &ToolStageReceipt) -> bool {
    if receipt.artifacts.is_empty() {
        return receipt.artifact_digests.is_empty();
    }
    if receipt.artifact_digests.len() != receipt.artifacts.len() {
        return false;
    }
    receipt.artifacts.iter().all(|artifact| {
        let Some(expected) = receipt.artifact_digests.get(artifact) else {
            return false;
        };
        stage_artifact_digest(target, artifact).as_deref() == Some(expected.as_str())
    })
}

fn stage_artifact_digests(target: &Path, artifacts: &[String]) -> BTreeMap<String, String> {
    artifacts
        .iter()
        .filter_map(|artifact| {
            stage_artifact_digest(target, artifact).map(|digest| (artifact.clone(), digest))
        })
        .collect()
}

fn stage_artifact_digest(target: &Path, artifact: &str) -> Option<String> {
    let canonical_target = target.canonicalize().ok()?;
    let canonical_artifact = target.join(artifact).canonicalize().ok()?;
    if !canonical_artifact.starts_with(&canonical_target) {
        return None;
    }
    let bytes = crate::bounded_file::read_regular_bytes_within(
        &canonical_target,
        &canonical_artifact,
        64 * 1024 * 1024,
    )
    .ok()?;
    Some(crate::identity::hash_parts("kuzushi.stage-artifact.v1", &[bytes.as_slice()]).to_string())
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

fn stage_receipt(
    stage: &str,
    outcome: PhaseStageOutcome,
    artifacts: Vec<String>,
    artifact_digests: BTreeMap<String, String>,
    detail: Option<String>,
) -> ToolStageReceipt {
    ToolStageReceipt {
        stage: stage.to_string(),
        outcome,
        artifacts,
        artifact_digests,
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
