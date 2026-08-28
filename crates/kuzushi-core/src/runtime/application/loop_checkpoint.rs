use super::*;
use std::fs;
use std::path::{Path, PathBuf};

/// Best-effort transcript checkpoint for agent tool loops.
///
/// A multi-turn loop that dies mid-flight (provider outage, terminal rate
/// limit, crash) has already paid for every completed round-trip. The driver
/// persists the transcript after each completed round so re-running the same
/// request resumes at the failed turn instead of re-buying the whole loop.
///
/// Resume is fail-closed: a checkpoint belongs to one canonical workspace
/// root, one source identity, one complete tool contract, and one set of model
/// execution settings. Source or contract drift starts a fresh loop rather
/// than replaying tool results produced against different code or schemas.
/// Checkpoints live only under an existing target `.kuzushi` directory;
/// completion (final answer or truncation) clears the checkpoint.
pub(super) struct LoopCheckpointStore {
    path: PathBuf,
    fingerprint: String,
    workspace_root: String,
    source_identity: String,
    tool_contract_fingerprint: String,
    runtime_contract_fingerprint: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoopCheckpointFile {
    version: u32,
    fingerprint: String,
    workspace_root: String,
    source_identity: String,
    tool_contract_fingerprint: String,
    runtime_contract_fingerprint: String,
    transcript: Vec<LoopHistoryEntry>,
}

const LOOP_CHECKPOINT_VERSION: u32 = 2;
const LOOP_CHECKPOINT_FINGERPRINT_PREFIX: usize = 16;

impl LoopCheckpointStore {
    /// A store exists only when the request's canonical cwd is already a
    /// Kuzushi target and a source identity can be established. Every target
    /// uses a content-derived workspace tree identity; Git targets bind the
    /// commit in addition to that tree. If either required binding cannot be
    /// established, checkpointing is disabled rather than weakened.
    pub(super) fn discover(request: &AgentToolLoopRequest) -> Option<Self> {
        let canonical_root = request.cwd.canonicalize().ok()?;
        let kuzushi_dir = canonical_root.join(".kuzushi");
        if !kuzushi_dir.is_dir() {
            return None;
        }
        let workspace_root = canonical_root.to_string_lossy().into_owned();
        let source_identity =
            crate::incremental_index::current_workspace_resume_identity(&canonical_root).ok()?;
        let tool_contract_fingerprint = tool_contract_fingerprint(&request.tools)?;
        let runtime_contract_fingerprint =
            runtime_contract_fingerprint(request.runtime_options.as_ref())?;
        let fingerprint = loop_request_fingerprint(
            request,
            &workspace_root,
            &source_identity,
            &tool_contract_fingerprint,
            &runtime_contract_fingerprint,
        )?;
        let leaf = checkpoint_leaf(&fingerprint)?;
        let path = kuzushi_dir.join("v3").join("checkpoints").join(leaf);
        Some(Self {
            path,
            fingerprint,
            workspace_root,
            source_identity,
            tool_contract_fingerprint,
            runtime_contract_fingerprint,
        })
    }

    /// Restore the transcript from an interrupted run of this exact request.
    pub(super) fn load(&self) -> Option<Vec<LoopHistoryEntry>> {
        let raw = fs::read_to_string(&self.path).ok()?;
        let file = serde_json::from_str::<LoopCheckpointFile>(&raw).ok()?;
        let matches = file.version == LOOP_CHECKPOINT_VERSION
            && file.fingerprint == self.fingerprint
            && file.workspace_root == self.workspace_root
            && file.source_identity == self.source_identity
            && file.tool_contract_fingerprint == self.tool_contract_fingerprint
            && file.runtime_contract_fingerprint == self.runtime_contract_fingerprint
            && !file.transcript.is_empty();
        matches.then_some(file.transcript)
    }

    /// Persist the transcript after a completed round. Best-effort: a failed
    /// checkpoint write must not fail the paid run it is protecting.
    pub(super) fn save(&self, transcript: &[LoopHistoryEntry]) {
        let file = LoopCheckpointFile {
            version: LOOP_CHECKPOINT_VERSION,
            fingerprint: self.fingerprint.clone(),
            workspace_root: self.workspace_root.clone(),
            source_identity: self.source_identity.clone(),
            tool_contract_fingerprint: self.tool_contract_fingerprint.clone(),
            runtime_contract_fingerprint: self.runtime_contract_fingerprint.clone(),
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
    crate::fs_atomic::write_atomic(path, contents).map_err(std::io::Error::other)
}

/// The provider-visible tool contract includes names, descriptions, order, and
/// complete JSON Schemas. Hash only the serialized contract; never persist
/// schema text or runtime environment values in checkpoint metadata.
fn tool_contract_fingerprint(tools: &[AgentTool]) -> Option<String> {
    let encoded = serde_json::to_vec(tools).ok()?;
    Some(
        crate::identity::hash_parts("agent-loop-tool-contract-v1", &[encoded.as_slice()])
            .to_string(),
    )
}

/// Runtime options are part of the execution contract, but environment values
/// may contain credentials. Never persist even a secret-derived digest: loops
/// carrying MCP environment values simply run without resume checkpoints.
fn runtime_contract_fingerprint(options: Option<&AgentRuntimeOptions>) -> Option<String> {
    if options.is_some_and(|options| !options.mcp_environment.is_empty()) {
        return None;
    }
    let encoded = serde_json::to_vec(&options).ok()?;
    Some(
        crate::identity::hash_parts("agent-loop-runtime-contract-v1", &[encoded.as_slice()])
            .to_string(),
    )
}

/// Identity of one resumable loop request. Every value that can change model
/// behavior or the meaning of a prior tool result is bound into this digest:
/// source, canonical root, full tool contract, model/prompts, step budget,
/// runtime options, temperature, package version, and checkpoint protocol.
fn loop_request_fingerprint(
    request: &AgentToolLoopRequest,
    workspace_root: &str,
    source_identity: &str,
    tool_contract_fingerprint: &str,
    runtime_contract_fingerprint: &str,
) -> Option<String> {
    let temperature = serde_json::to_vec(&request.temperature).ok()?;
    let max_steps = request.max_steps.to_be_bytes();
    let protocol_version = LOOP_CHECKPOINT_VERSION.to_be_bytes();
    Some(
        crate::identity::hash_parts(
            "agent-loop-checkpoint-request-v2",
            &[
                env!("CARGO_PKG_VERSION").as_bytes(),
                &protocol_version,
                workspace_root.as_bytes(),
                source_identity.as_bytes(),
                request.model.as_bytes(),
                request.system_prompt.as_bytes(),
                request.prompt.as_bytes(),
                tool_contract_fingerprint.as_bytes(),
                runtime_contract_fingerprint.as_bytes(),
                &max_steps,
                temperature.as_slice(),
            ],
        )
        .to_string(),
    )
}

fn checkpoint_leaf(fingerprint: &str) -> Option<String> {
    let prefix = fingerprint.get(..LOOP_CHECKPOINT_FINGERPRINT_PREFIX)?;
    Some(format!("agent-loop-{prefix}.json"))
}

/// A saved-but-unconsumed loop checkpoint: an interrupted agent run whose
/// completed turns are waiting to be resumed by re-running the same request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLoopCheckpoint {
    pub completed_turns: u32,
    pub modified_at_unix: Option<u64>,
}

/// List source-current agent-loop checkpoints for the target, newest first.
///
/// A checkpoint from an older source tree is deliberately omitted rather than
/// presented as resumable. Exact request and tool-contract matching is enforced
/// again by [`LoopCheckpointStore::load`] when a loop is re-dispatched.
pub fn pending_agent_loop_checkpoints(target: &Path) -> Vec<PendingLoopCheckpoint> {
    let Ok(canonical_root) = target.canonicalize() else {
        return Vec::new();
    };
    let Ok(source_identity) =
        crate::incremental_index::current_workspace_resume_identity(&canonical_root)
    else {
        return Vec::new();
    };
    let workspace_root = canonical_root.to_string_lossy().into_owned();
    let dir = canonical_root
        .join(".kuzushi")
        .join("v3")
        .join("checkpoints");
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut pending: Vec<PendingLoopCheckpoint> = entries
        .flatten()
        .filter_map(|entry| pending_checkpoint(&entry.path(), &workspace_root, &source_identity))
        .collect();
    pending.sort_by_key(|entry| std::cmp::Reverse(entry.modified_at_unix));
    pending
}

fn pending_checkpoint(
    path: &Path,
    workspace_root: &str,
    source_identity: &str,
) -> Option<PendingLoopCheckpoint> {
    let name = path.file_name()?.to_str()?;
    let raw = fs::read_to_string(path).ok()?;
    let file = serde_json::from_str::<LoopCheckpointFile>(&raw).ok()?;
    let expected_leaf = checkpoint_leaf(&file.fingerprint)?;
    let pending = name == expected_leaf
        && file.version == LOOP_CHECKPOINT_VERSION
        && file.workspace_root == workspace_root
        && file.source_identity == source_identity
        && !file.tool_contract_fingerprint.is_empty()
        && !file.runtime_contract_fingerprint.is_empty()
        && !file.transcript.is_empty();
    pending.then_some(PendingLoopCheckpoint {
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
    use std::process::Command;

    fn workspace() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
        temp
    }

    fn request(root: &Path, prompt: &str) -> AgentToolLoopRequest {
        AgentToolLoopRequest {
            model: "test:model".to_string(),
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

        fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
        assert!(LoopCheckpointStore::discover(&request(temp.path(), "p")).is_some());
    }

    #[test]
    fn saved_transcript_round_trips_and_clears() {
        let temp = workspace();
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
        let temp = workspace();
        assert!(pending_agent_loop_checkpoints(temp.path()).is_empty());

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
        let temp = workspace();
        let store = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();
        store.save(&transcript());

        let other = LoopCheckpointStore::discover(&request(temp.path(), "different")).unwrap();
        assert_ne!(other.path, store.path);
        assert!(other.load().is_none(), "different prompt must start fresh");
    }

    #[test]
    fn changed_source_tree_orphans_the_checkpoint_and_pending_claim() {
        let temp = workspace();
        fs::write(temp.path().join("source.rs"), "fn first() {}\n").unwrap();
        let store = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();
        store.save(&transcript());
        assert_eq!(pending_agent_loop_checkpoints(temp.path()).len(), 1);

        fs::write(temp.path().join("source.rs"), "fn second() {}\n").unwrap();
        let other = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();

        assert_ne!(other.path, store.path);
        assert!(other.load().is_none());
        assert!(
            pending_agent_loop_checkpoints(temp.path()).is_empty(),
            "a checkpoint for stale source must not be advertised as pending"
        );
    }

    #[test]
    fn changed_tool_schema_orphans_the_checkpoint() {
        let temp = workspace();
        let original = request(temp.path(), "p");
        let store = LoopCheckpointStore::discover(&original).unwrap();
        store.save(&transcript());

        let mut changed = request(temp.path(), "p");
        changed.tools[0].input_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" }
            },
            "required": ["path"]
        });
        let other = LoopCheckpointStore::discover(&changed).unwrap();

        assert_ne!(other.path, store.path);
        assert!(other.load().is_none());
    }

    #[test]
    fn changed_runtime_settings_orphan_the_checkpoint() {
        let temp = workspace();
        let store = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();
        store.save(&transcript());

        let mut changed = request(temp.path(), "p");
        changed.runtime_options = Some(AgentRuntimeOptions {
            mcp_tool_timeout_ms: Some(5_000),
            ..AgentRuntimeOptions::default()
        });
        let other = LoopCheckpointStore::discover(&changed).unwrap();

        assert_ne!(other.path, store.path);
        assert!(other.load().is_none());
    }

    #[test]
    fn secret_bearing_runtime_environment_disables_checkpointing() {
        let temp = workspace();
        let mut request = request(temp.path(), "p");
        request.runtime_options = Some(AgentRuntimeOptions {
            mcp_environment: [("API_TOKEN".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
            ..AgentRuntimeOptions::default()
        });

        assert!(
            LoopCheckpointStore::discover(&request).is_none(),
            "checkpoint metadata must not contain a secret-derived request digest"
        );
    }

    #[test]
    fn legacy_checkpoint_version_fails_closed() {
        let temp = workspace();
        let store = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();
        let parent = store.path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::write(
            &store.path,
            serde_json::to_string(&serde_json::json!({
                "version": 1,
                "fingerprint": store.fingerprint.clone(),
                "transcript": transcript(),
            }))
            .unwrap(),
        )
        .unwrap();

        assert!(store.load().is_none());
    }

    #[test]
    fn checkpoint_publish_does_not_reuse_a_fixed_temp_sibling() {
        let temp = workspace();
        let store = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();
        let parent = store.path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let fixed = store.path.with_extension("json.tmp");
        fs::write(&fixed, "unrelated staging file").unwrap();

        store.save(&transcript());

        assert_eq!(fs::read_to_string(fixed).unwrap(), "unrelated staging file");
        assert!(store.load().is_some());
    }

    #[test]
    fn clean_git_revision_is_bound_into_checkpoint_identity() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let temp = workspace();
        git(temp.path(), &["init"]);
        git(temp.path(), &["config", "user.email", "test@example.com"]);
        git(temp.path(), &["config", "user.name", "Kuzushi Test"]);
        fs::write(temp.path().join(".gitignore"), ".kuzushi/\n").unwrap();
        fs::write(temp.path().join("source.rs"), "fn first() {}\n").unwrap();
        git(temp.path(), &["add", ".gitignore", "source.rs"]);
        git(temp.path(), &["commit", "-m", "first"]);

        let first = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();
        first.save(&transcript());
        assert!(first.source_identity.starts_with("git:"));
        assert!(first.source_identity.contains(";tree:"));

        fs::write(temp.path().join("source.rs"), "fn second() {}\n").unwrap();
        git(temp.path(), &["add", "source.rs"]);
        git(temp.path(), &["commit", "-m", "second"]);
        let second = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();

        assert!(second.source_identity.starts_with("git:"));
        assert_ne!(second.source_identity, first.source_identity);
        assert_ne!(second.path, first.path);
        assert!(second.load().is_none());
    }

    #[test]
    fn untracked_git_source_change_orphans_checkpoint() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let temp = workspace();
        git(temp.path(), &["init"]);
        git(temp.path(), &["config", "user.email", "test@example.com"]);
        git(temp.path(), &["config", "user.name", "Kuzushi Test"]);
        fs::write(temp.path().join(".gitignore"), ".kuzushi/\n").unwrap();
        fs::write(temp.path().join("tracked.rs"), "fn tracked() {}\n").unwrap();
        git(temp.path(), &["add", ".gitignore", "tracked.rs"]);
        git(temp.path(), &["commit", "-m", "tracked"]);
        fs::write(temp.path().join("draft.rs"), "fn first() {}\n").unwrap();

        let first = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();
        first.save(&transcript());
        assert!(first.source_identity.starts_with("git:"));
        assert!(first.source_identity.contains(";tree:"));
        assert_eq!(pending_agent_loop_checkpoints(temp.path()).len(), 1);

        fs::write(temp.path().join("draft.rs"), "fn second() {}\n").unwrap();
        let second = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();

        assert!(second.source_identity.starts_with("git:"));
        assert_ne!(second.source_identity, first.source_identity);
        assert_ne!(second.path, first.path);
        assert!(second.load().is_none());
        assert!(pending_agent_loop_checkpoints(temp.path()).is_empty());
    }

    #[test]
    fn git_ignored_source_change_orphans_checkpoint() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let temp = workspace();
        git(temp.path(), &["init"]);
        git(temp.path(), &["config", "user.email", "test@example.com"]);
        git(temp.path(), &["config", "user.name", "Kuzushi Test"]);
        fs::write(
            temp.path().join(".gitignore"),
            ".kuzushi/\nlocal-policy.toml\n",
        )
        .unwrap();
        fs::write(temp.path().join("tracked.rs"), "fn tracked() {}\n").unwrap();
        fs::write(temp.path().join("local-policy.toml"), "mode = 'first'\n").unwrap();
        git(temp.path(), &["add", ".gitignore", "tracked.rs"]);
        git(temp.path(), &["commit", "-m", "tracked"]);

        let first = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();
        first.save(&transcript());
        assert_eq!(pending_agent_loop_checkpoints(temp.path()).len(), 1);

        fs::write(temp.path().join("local-policy.toml"), "mode = 'second'\n").unwrap();
        let second = LoopCheckpointStore::discover(&request(temp.path(), "p")).unwrap();

        assert_ne!(second.source_identity, first.source_identity);
        assert_ne!(second.path, first.path);
        assert!(second.load().is_none());
        assert!(pending_agent_loop_checkpoints(temp.path()).is_empty());
    }

    fn git(target: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(target)
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
