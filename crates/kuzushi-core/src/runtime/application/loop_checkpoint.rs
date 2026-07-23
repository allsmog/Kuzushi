use super::*;
use std::fs;
use std::path::{Path, PathBuf};

/// Best-effort transcript checkpoint for agent tool loops.
///
/// A multi-turn loop that dies mid-flight (provider outage, terminal rate
/// limit, crash) has already paid for every completed round-trip. The driver
/// persists the transcript after each completed round so re-running the same
/// request resumes at the failed turn instead of re-buying the whole loop.
/// Checkpoints live under the target's existing `.kuzushi` directory and are
/// keyed by a fingerprint of the request; a changed prompt, model, toolset,
/// or step budget starts fresh. Completion (final answer or truncation)
/// clears the checkpoint.
pub(super) struct LoopCheckpointStore {
    path: PathBuf,
    fingerprint: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LoopCheckpointFile {
    version: u32,
    fingerprint: String,
    transcript: Vec<LoopHistoryEntry>,
}

const LOOP_CHECKPOINT_VERSION: u32 = 1;

impl LoopCheckpointStore {
    /// A store exists only when the request's cwd is already a Kuzushi
    /// target (`.kuzushi` present). The checkpoint must never be the reason
    /// a `.kuzushi` directory appears somewhere new.
    pub(super) fn discover(request: &AgentToolLoopRequest) -> Option<Self> {
        let kuzushi_dir = request.cwd.join(".kuzushi");
        if !kuzushi_dir.is_dir() {
            return None;
        }
        let fingerprint = loop_request_fingerprint(request);
        let path = kuzushi_dir
            .join("v3")
            .join("checkpoints")
            .join(format!("agent-loop-{fingerprint}.json"));
        Some(Self { path, fingerprint })
    }

    /// Restore the transcript from an interrupted run of this exact request.
    pub(super) fn load(&self) -> Option<Vec<LoopHistoryEntry>> {
        let raw = fs::read_to_string(&self.path).ok()?;
        let file = serde_json::from_str::<LoopCheckpointFile>(&raw).ok()?;
        let matches = file.version == LOOP_CHECKPOINT_VERSION
            && file.fingerprint == self.fingerprint
            && !file.transcript.is_empty();
        matches.then_some(file.transcript)
    }

    /// Persist the transcript after a completed round. Best-effort: a failed
    /// checkpoint write must not fail the paid run it is protecting.
    pub(super) fn save(&self, transcript: &[LoopHistoryEntry]) {
        let file = LoopCheckpointFile {
            version: LOOP_CHECKPOINT_VERSION,
            fingerprint: self.fingerprint.clone(),
            transcript: transcript.to_vec(),
        };
        let Ok(serialized) = serde_json::to_string(&file) else {
            return;
        };
        let _ = write_atomically(&self.path, &serialized);
    }

    pub(super) fn clear(&self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn write_atomically(path: &Path, contents: &str) -> std::io::Result<()> {
    let parent = path.parent().expect("checkpoint path has a parent");
    fs::create_dir_all(parent)?;
    let temp = path.with_extension("json.tmp");
    fs::write(&temp, contents)?;
    fs::rename(&temp, path)
}

/// Identity of a loop request for resume purposes: same model, prompts,
/// tool vocabulary, and step budget. Tool schemas/descriptions are excluded
/// on purpose — wording tweaks should not orphan an expensive checkpoint,
/// but a different tool *set* changes what the transcript can contain.
fn loop_request_fingerprint(request: &AgentToolLoopRequest) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(request.model.as_bytes());
    hasher.update(request.system_prompt.as_bytes());
    hasher.update(request.prompt.as_bytes());
    for tool in &request.tools {
        hasher.update(tool.name.as_bytes());
    }
    hasher.update(&request.max_steps.to_le_bytes());
    let digest = hasher.finalize().to_hex();
    digest.as_str()[..16].to_string()
}

/// A saved-but-unconsumed loop checkpoint: an interrupted agent run whose
/// completed turns are waiting to be resumed by re-running the same request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLoopCheckpoint {
    pub completed_turns: u32,
    pub modified_at_unix: Option<u64>,
}

/// List the target's pending agent-loop checkpoints, newest first.
/// Presentation surfaces use this to disclose that rerunning the failed
/// request resumes from the checkpoint instead of restarting.
pub fn pending_agent_loop_checkpoints(target: &Path) -> Vec<PendingLoopCheckpoint> {
    let dir = target.join(".kuzushi").join("v3").join("checkpoints");
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut pending: Vec<PendingLoopCheckpoint> = entries
        .flatten()
        .filter_map(|entry| pending_checkpoint(&entry.path()))
        .collect();
    pending.sort_by(|left, right| right.modified_at_unix.cmp(&left.modified_at_unix));
    pending
}

fn pending_checkpoint(path: &Path) -> Option<PendingLoopCheckpoint> {
    let name = path.file_name()?.to_str()?;
    if !name.starts_with("agent-loop-") || !name.ends_with(".json") {
        return None;
    }
    let raw = fs::read_to_string(path).ok()?;
    let file = serde_json::from_str::<LoopCheckpointFile>(&raw).ok()?;
    let pending = file.version == LOOP_CHECKPOINT_VERSION && !file.transcript.is_empty();
    pending.then(|| PendingLoopCheckpoint {
        completed_turns: restored_step_count(&file.transcript),
        modified_at_unix: modified_at_unix(path),
    })
}

fn modified_at_unix(path: &Path) -> Option<u64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let elapsed = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(elapsed.as_secs())
}

/// Model round-trips already consumed by a restored transcript; the loop's
/// `max_steps` budget covers restored and new rounds together.
pub(super) fn restored_step_count(transcript: &[LoopHistoryEntry]) -> u32 {
    transcript
        .iter()
        .filter(|entry| matches!(entry, LoopHistoryEntry::AssistantToolCall(_)))
        .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{AgentTool, ToolCall};

    fn request(root: &Path, prompt: &str) -> AgentToolLoopRequest {
        AgentToolLoopRequest {
            model: "anthropic:claude-test".to_string(),
            cwd: root.to_path_buf(),
            system_prompt: "system".to_string(),
            prompt: prompt.to_string(),
            tools: vec![AgentTool {
                name: "read_source".to_string(),
                description: "read".to_string(),
                input_schema: serde_json::json!({}),
            }],
            max_steps: 8,
            runtime_options: None,
            temperature: None,
        }
    }

    fn transcript() -> Vec<LoopHistoryEntry> {
        vec![LoopHistoryEntry::AssistantToolCall(ToolCall {
            name: "read_source".to_string(),
            input: serde_json::json!({"path": "a.rs"}),
            call_id: "call-1".to_string(),
        })]
    }

    #[test]
    fn checkpoints_require_an_existing_kuzushi_target() {
        let temp = tempfile::tempdir().unwrap();
        assert!(LoopCheckpointStore::discover(&request(temp.path(), "p")).is_none());

        std::fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
        assert!(LoopCheckpointStore::discover(&request(temp.path(), "p")).is_some());
    }

    #[test]
    fn saved_transcript_round_trips_and_clears() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
        let store = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();

        assert!(store.load().is_none());
        store.save(&transcript());
        let restored = store.load().expect("restored transcript");
        assert_eq!(restored.len(), 1);
        assert_eq!(restored_step_count(&restored), 1);

        store.clear();
        assert!(store.load().is_none());
    }

    #[test]
    fn pending_checkpoints_list_newest_first_with_turn_counts() {
        let temp = tempfile::tempdir().unwrap();
        assert!(pending_agent_loop_checkpoints(temp.path()).is_empty());

        std::fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
        let store = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();
        store.save(&transcript());

        let pending = pending_agent_loop_checkpoints(temp.path());
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].completed_turns, 1);

        store.clear();
        assert!(pending_agent_loop_checkpoints(temp.path()).is_empty());
    }

    #[test]
    fn changed_request_identity_orphans_the_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
        let store = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();
        store.save(&transcript());

        let other = LoopCheckpointStore::discover(&request(temp.path(), "different")).unwrap();
        assert!(other.load().is_none(), "different prompt must start fresh");
    }
}
