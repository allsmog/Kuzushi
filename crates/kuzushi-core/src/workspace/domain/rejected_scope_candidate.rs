use anyhow::Result;
use serde::{Deserialize, Serialize};

pub const MAX_REJECTED_SCOPE_BYTES: usize = 16 * 1024;

/// Unaccepted model text, retained separately from every valid scope revision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RejectedScopeCandidate {
    pub schema_version: u32,
    pub candidate: String,
    pub original_bytes: usize,
    pub complete: bool,
    pub reason: String,
}

impl RejectedScopeCandidate {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == 1,
            "unsupported rejected scope diagnostic"
        );
        anyhow::ensure!(
            self.candidate.len() <= MAX_REJECTED_SCOPE_BYTES && self.reason.len() <= 8192,
            "rejected scope diagnostic exceeds its text limits"
        );
        anyhow::ensure!(
            self.original_bytes >= self.candidate.len(),
            "invalid diagnostic byte count"
        );
        anyhow::ensure!(
            !self.complete || self.original_bytes == self.candidate.len(),
            "incomplete scope output cannot be labeled complete"
        );
        Ok(())
    }
}
