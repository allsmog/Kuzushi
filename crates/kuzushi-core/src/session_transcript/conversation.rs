use crate::capabilities::ThreatModelRef;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreadContextKey {
    pub canonical_target: PathBuf,
    pub target_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_model_ref: Option<ThreatModelRef>,
    /// Exact digest named by the threat-model attachment captured for this
    /// thread. Legacy mirrors have no truthful lineage ref, so this remains
    /// populated even when `threat_model_ref` is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached_model_sha256: Option<String>,
    pub policy_version: String,
}

impl ThreadContextKey {
    pub fn changed_dimensions(&self, next: &Self) -> Vec<&'static str> {
        [
            (
                self.canonical_target != next.canonical_target,
                "target changed",
            ),
            (
                self.target_revision != next.target_revision,
                "target revision changed",
            ),
            (
                self.threat_model_ref != next.threat_model_ref
                    || self.attached_model_sha256 != next.attached_model_sha256,
                "threat model changed",
            ),
            (
                self.policy_version != next.policy_version,
                "Ask tool policy changed",
            ),
        ]
        .into_iter()
        .filter_map(|(changed, label)| changed.then_some(label))
        .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatTurn {
    pub question: String,
    pub answer: Option<String>,
    /// Unfinished public response text, excluded from model history.
    pub partial_answer: String,
    pub error: Option<String>,
}

/// A recoverable public Ask document; never contains an assembled model prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationSnapshot {
    pub version: u8,
    pub context: ThreadContextKey,
    pub current: ChatTurn,
    pub history: Vec<ChatTurn>,
    pub run_id: String,
    pub started_secs: u64,
    pub screen_context_scope: Option<String>,
    pub interrupted: bool,
}

impl ConversationSnapshot {
    /// Refuse oversize snapshots rather than silently truncate reusable context.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.version == 1, "unsupported Ask history version");
        anyhow::ensure!(self.history.len() <= 12, "too many saved Ask turns");
        anyhow::ensure!(
            self.context.canonical_target.is_absolute(),
            "Ask target is not absolute"
        );
        anyhow::ensure!(!self.run_id.is_empty(), "Ask run id is missing");
        self.validate_size()
    }

    fn validate_size(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            serde_json::to_vec(self)?.len() <= 512 * 1024,
            "Ask history exceeds the 512 KiB recovery limit; the session transcript remains available"
        );
        Ok(())
    }
}
