use super::tool_stage::{append_tool_stage_receipt, ToolStageReceipt};
use super::*;
use crate::checkpoint_limits::{self, MAX_CHECKPOINT_BYTES, MAX_RECORDS};
use crate::run_artifacts::scan_stage::PhaseStageOutcome;
use std::collections::BTreeMap;
use std::sync::Mutex;

#[path = "stage_checkpoint/discovery.rs"]
mod discovery;
#[path = "stage_checkpoint/health.rs"]
mod health;
pub use discovery::{
    active_stage_checkpoints, checkpoint_coordinates_for_run,
    matching_checkpoint_coordinates_for_run, pending_stage_checkpoints, PendingStageCheckpoint,
    StageCheckpointCoordinates, StageCheckpointScope,
};
pub use health::{StageResumeHealth, StageResumeProblem};

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
#[serde(
    rename_all = "camelCase",
    bound(deserialize = "C: Default + FromIterator<ToolStageReceipt>")
)]
pub struct StageCheckpointFile<C = Vec<ToolStageReceipt>> {
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
    #[serde(default, deserialize_with = "deserialize_completed")]
    pub completed: C,
}

fn deserialize_completed<'de, D, C>(deserializer: D) -> std::result::Result<C, D::Error>
where
    D: serde::Deserializer<'de>,
    C: FromIterator<ToolStageReceipt>,
{
    checkpoint_limits::deserialize_records::<D, ToolStageReceipt, C>(deserializer)
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

    fn load(&self) -> Result<Option<StageCheckpointFile>> {
        let raw = match crate::bounded_file::read_utf8_text(&self.path, MAX_CHECKPOINT_BYTES) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let file = serde_json::from_str::<StageCheckpointFile>(&raw)?;
        let matches = file.version == STAGE_CHECKPOINT_VERSION
            && file.fingerprint == self.fingerprint
            && file.implementation_identity == self.implementation_identity;
        Ok(matches.then_some(file))
    }

    fn save(&self, file: &impl Serialize) -> Result<()> {
        let serialized = checkpoint_limits::encode(file, MAX_CHECKPOINT_BYTES)?;
        write_checkpoint_atomically(&self.path, std::str::from_utf8(&serialized)?)?;
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => crate::fs_atomic::sync_parent_dir(&self.path).map_err(Into::into),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
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
    health: Mutex<StageResumeHealth>,
    trace: Option<TraceHandle>,
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
        let (resumed_from, prior, load_error) =
            recover_prior(&store, target, tool, source_identity.as_deref());
        let health = StageResumeHealth::from_prior(&prior, resumed_from.clone());
        let handle = Self {
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
            health: Mutex::new(health),
            trace: None,
        };
        if let Some(error) = load_error {
            handle.resume_problem("load", &error);
        }
        handle
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
        self.append_stage_receipt(&receipt);
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
            stage: if self.resume_health().degraded {
                String::new()
            } else {
                stage.to_string()
            },
        }
    }

    /// Persist `stage` as the last started stage so a failure after this
    /// point reports a real resume coordinate.
    pub fn mark_current(&self, stage: &str) {
        if self.resume_health().degraded {
            return;
        }
        if let Err(error) = checkpoint_limits::validate_record(&stage) {
            self.resume_problem("save", &error);
            return;
        }
        if let Ok(mut state) = self.state.lock() {
            invalidate_from_stage(&mut state, stage);
            state.current = Some(stage.to_string());
            self.save_locked(&state);
        }
    }

    pub fn clear_checkpoint(&self) {
        if let Err(error) = self.store.clear() {
            self.resume_problem("clear", &error);
            return;
        }
        if let Ok(mut health) = self.health.lock() {
            health.checkpoint_cleared = true;
            health.retry_on_next_dispatch = false;
        }
        self.persist_resume_health();
    }

    /// Persist a JSON payload as this stage's durable artifact under the
    /// run dir, returning its target-relative path for `StageGuard::complete`.
    /// Best-effort: None when the write fails.
    pub fn write_stage_payload(&self, stage: &str, payload: &Value) -> Option<String> {
        if self.resume_health().degraded {
            return None;
        }
        let leaf = format!("stage-{}.json", sanitized_stage_leaf(stage));
        let written = write_run_artifact_json_bounded(
            &self.target,
            &self.run_id,
            &leaf,
            "stage payload",
            payload,
            MAX_CHECKPOINT_BYTES,
        );
        if let Err(error) = written {
            self.resume_problem("payload", &error);
            return None;
        }
        let path = run_dir(&self.target, &self.run_id).join(leaf);
        relative_to_target(&self.target, &path.to_string_lossy())
    }

    /// Read back the payload a completed stage persisted (possibly in a
    /// prior failed run).
    pub fn read_stage_payload(&self, receipt: &ToolStageReceipt) -> Option<Value> {
        let relative = receipt.artifacts.first()?;
        match self.load_stage_payload(relative) {
            Ok(payload) => Some(payload),
            Err(error) => {
                self.resume_problem("payload-read", &error);
                None
            }
        }
    }

    fn load_stage_payload(&self, relative: &str) -> Result<Value> {
        let raw = crate::bounded_file::read_utf8_text_within(
            &self.target,
            &self.target.join(relative),
            MAX_CHECKPOINT_BYTES,
        )
        .context("stage checkpoint payload is unreadable")?;
        serde_json::from_str(&raw).context("stage checkpoint payload is malformed")
    }

    fn record_completed(&self, stage: &str, artifacts: Vec<String>) {
        if self.resume_health().degraded {
            return;
        }
        let receipt = match completed_receipt(&self.target, stage, artifacts) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.resume_problem("receipt", &error);
                return;
            }
        };
        if !self.append_stage_receipt(&receipt) {
            return;
        }
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
        self.append_stage_receipt(&receipt);
        if let Ok(mut state) = self.state.lock() {
            if state.current.as_deref() == Some(stage) {
                state.current = None;
                self.save_locked(&state);
            }
        }
    }

    fn save_locked(&self, state: &StageCheckpointState) {
        if self.resume_health().degraded {
            return;
        }
        match self.try_save_locked(state) {
            Ok(()) => self.saved_checkpoint(state),
            Err(error) => self.resume_problem("save", &error),
        }
    }

    fn admit_stage_receipt(&self, receipt: &ToolStageReceipt) -> bool {
        if let Err(error) = checkpoint_limits::validate_record(receipt) {
            self.resume_problem("receipt", &error);
            return false;
        }
        true
    }

    fn append_stage_receipt(&self, receipt: &ToolStageReceipt) -> bool {
        if !self.admit_stage_receipt(receipt) {
            return false;
        }
        if let Err(error) = append_tool_stage_receipt(&self.target, &self.run_id, receipt) {
            self.resume_problem("receipt", &error);
            return false;
        }
        true
    }

    fn try_save_locked(&self, state: &StageCheckpointState) -> Result<()> {
        anyhow::ensure!(
            state.prior.len() + state.completed_now.len() <= MAX_RECORDS,
            "stage checkpoint exceeds {MAX_RECORDS} records; resume unavailable"
        );
        let completed = state
            .prior
            .iter()
            .chain(state.completed_now.iter())
            .collect::<Vec<_>>();
        for receipt in &completed {
            checkpoint_limits::validate_record(receipt)?;
        }
        self.store.save(&StageCheckpointFile {
            version: STAGE_CHECKPOINT_VERSION,
            fingerprint: self.store.fingerprint.clone(),
            implementation_identity: self.store.implementation_identity.clone(),
            tool: self.tool.clone(),
            source_run_id: self.run_id.clone(),
            source_identity: self.source_identity.clone(),
            current_stage: state.current.clone(),
            completed,
        })
    }
}

fn recover_prior(
    store: &StageCheckpointStore,
    target: &Path,
    tool: &str,
    identity: Option<&str>,
) -> (Option<String>, Vec<ToolStageReceipt>, Option<anyhow::Error>) {
    let file = match store.load() {
        Ok(file) => file,
        Err(error) => return (None, Vec::new(), Some(error)),
    };
    if identity.is_none() {
        return (
            None,
            Vec::new(),
            Some(anyhow::anyhow!("workspace recovery identity unavailable")),
        );
    }
    let Some(file) = file.filter(|file| prior_checkpoint_is_fresh(file, tool, identity)) else {
        return (None, Vec::new(), None);
    };
    let mut prior = file.completed;
    prior.truncate(reusable_stage_prefix_len(target, &prior));
    let resumed_from = (!prior.is_empty()).then_some(file.source_run_id);
    (resumed_from, prior, None)
}

fn validate_stage_artifacts(stage: &str, artifacts: &[String]) -> Result<()> {
    anyhow::ensure!(
        artifacts.len() <= 128,
        "stage has more than 128 checkpoint artifacts"
    );
    checkpoint_limits::validate_record(&(stage, artifacts))
}

fn completed_receipt(
    target: &Path,
    stage: &str,
    artifacts: Vec<String>,
) -> Result<ToolStageReceipt> {
    validate_stage_artifacts(stage, &artifacts)?;
    let digests = stage_artifact_digests(target, &artifacts);
    anyhow::ensure!(
        digests.len() == artifacts.len(),
        "stage artifact identity unavailable"
    );
    Ok(stage_receipt(
        stage,
        PhaseStageOutcome::Completed,
        artifacts,
        digests,
        None,
    ))
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
