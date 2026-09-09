use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionMetadata {
    pub shell_mode: String,
    pub cwd: PathBuf,
    pub argv: Vec<String>,
    pub kuzushi_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    pub process_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_start_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<SessionGitMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_target: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_source: Option<String>,
}

impl SessionMetadata {
    pub fn new(shell_mode: impl Into<String>, cwd: impl Into<PathBuf>) -> Self {
        let process_id = std::process::id();
        Self {
            shell_mode: shell_mode.into(),
            cwd: cwd.into(),
            argv: std::env::args().collect(),
            kuzushi_version: env!("CARGO_PKG_VERSION").to_string(),
            build: option_env!("KUZUSHI_BUILD_ID").map(str::to_string),
            process_id,
            process_start_token: super::process_identity::start_token(process_id),
            git: None,
            initial_target: None,
            target_source: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionGitMetadata {
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub dirty: Option<bool>,
    pub remote: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum SessionEvent {
    CommandSubmitted {
        command: String,
    },
    TargetActivated {
        target: PathBuf,
        source: String,
    },
    TargetCleared {
        source: String,
    },
    ViewChanged {
        from: Option<String>,
        to: String,
    },
    LogEmitted {
        level: String,
        message: String,
    },
    RunStarted {
        run_id: String,
        tool_name: String,
    },
    RunFinished {
        run_id: String,
        tool_name: String,
        status: String,
    },
    OperatorQuestion {
        question_id: String,
        kind: String,
        prompt: Option<String>,
    },
    OperatorAnswer {
        question_id: String,
        kind: String,
        outcome: String,
        answer: Option<String>,
    },
    AgentUserTurn {
        text: String,
    },
    AgentAssistantTurn {
        text: String,
    },
    AgentConversation {
        snapshot: super::ConversationSnapshot,
    },
    AgentConversationCleared {
        target: PathBuf,
    },
    AttachmentRef {
        attachment_id: String,
        path: Option<PathBuf>,
        digest: Option<String>,
    },
    SessionWarning {
        message: String,
    },
    SessionEnd {
        reason: String,
    },
}

impl SessionEvent {
    /// Boundaries whose durability must be confirmed before the shell moves on.
    pub fn requires_flush_barrier(&self) -> bool {
        matches!(
            self,
            Self::RunStarted { .. }
                | Self::RunFinished { .. }
                | Self::OperatorAnswer { .. }
                | Self::AgentUserTurn { .. }
                | Self::AgentAssistantTurn { .. }
                | Self::AgentConversation { .. }
                | Self::AgentConversationCleared { .. }
                | Self::SessionEnd { .. }
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecord {
    pub schema_version: u8,
    pub timestamp: String,
    pub session_id: String,
    pub sequence: u64,
    pub event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<String>,
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionTruncation {
    pub original_type: String,
    pub original_bytes: usize,
    pub digest: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Running,
    Completed,
    Interrupted,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub session_id: String,
    pub path: PathBuf,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub status: SessionStatus,
    pub process_id: u32,
    pub shell_mode: String,
    pub initial_target: Option<PathBuf>,
    pub current_target: Option<PathBuf>,
    pub event_count: usize,
    pub warning_count: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionListOptions {
    pub target: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionReadResult {
    pub path: PathBuf,
    #[serde(skip_serializing)]
    pub raw_jsonl: String,
    pub summary: SessionSummary,
    pub records: Vec<SessionRecord>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPruneOptions {
    pub older_than_days: u64,
    pub dry_run: bool,
}

impl Default for SessionPruneOptions {
    fn default() -> Self {
        Self {
            older_than_days: super::DEFAULT_SESSION_RETENTION_DAYS,
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionPruneReport {
    pub examined: usize,
    pub removed: Vec<PathBuf>,
    pub skipped_live: Vec<String>,
    pub errors: Vec<String>,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionRecorderHealth {
    Healthy,
    Warning,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecorderStatus {
    pub session_id: String,
    pub path: PathBuf,
    pub health: SessionRecorderHealth,
    pub last_flushed_sequence: u64,
    pub pending_records: usize,
    pub last_error: Option<String>,
}
