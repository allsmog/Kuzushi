use serde::{Deserialize, Serialize};

/// Durable state of a reviewed patch after synthesis has finished.
///
/// `PatchResult` remains the truth for synthesis and disposable-worktree
/// validation. This record starts only when an operator applies that reviewed
/// diff to the active target, so a SOUND candidate is never mistaken for an
/// applied or re-verified fix.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatchLifecycleState {
    Applying,
    ApplyFailed,
    Applied,
    ReverifyRunning,
    Verified,
    StillVulnerable,
    NotRediscovered,
    Inconclusive,
    Failed,
    Interrupted,
    ChangedSinceApply,
}

impl PatchLifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applying => "applying",
            Self::ApplyFailed => "apply_failed",
            Self::Applied => "applied",
            Self::ReverifyRunning => "reverify_running",
            Self::Verified => "verified",
            Self::StillVulnerable => "still_vulnerable",
            Self::NotRediscovered => "not_rediscovered",
            Self::Inconclusive => "inconclusive",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
            Self::ChangedSinceApply => "changed_since_apply",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "applying" => Self::Applying,
            "apply_failed" => Self::ApplyFailed,
            "applied" => Self::Applied,
            "reverify_running" => Self::ReverifyRunning,
            "verified" => Self::Verified,
            "still_vulnerable" => Self::StillVulnerable,
            "not_rediscovered" => Self::NotRediscovered,
            "inconclusive" => Self::Inconclusive,
            "failed" => Self::Failed,
            "interrupted" => Self::Interrupted,
            "changed_since_apply" => Self::ChangedSinceApply,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PatchLifecycleFile {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PatchLifecycleRecord {
    pub application_id: String,
    pub stable_fp: String,
    pub fingerprint: String,
    /// Discovery generation the reviewed patch and its detector replay bind
    /// to. Missing only on legacy lifecycle rows, which cannot complete Fix
    /// reality for a current finding generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_scan_id: Option<String>,
    pub patch_run_id: String,
    pub target: String,
    pub diff_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_commit: Option<String>,
    pub touched_files: Vec<PatchLifecycleFile>,
    pub state: PatchLifecycleState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverify_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub actor: String,
    #[serde(default)]
    pub application_started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_at: Option<String>,
    pub updated_at: String,
}

impl PatchLifecycleRecord {
    pub fn touched_paths(&self) -> impl Iterator<Item = &str> {
        self.touched_files.iter().map(|file| file.path.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_state_round_trips_every_public_label() {
        for state in [
            PatchLifecycleState::Applying,
            PatchLifecycleState::ApplyFailed,
            PatchLifecycleState::Applied,
            PatchLifecycleState::ReverifyRunning,
            PatchLifecycleState::Verified,
            PatchLifecycleState::StillVulnerable,
            PatchLifecycleState::NotRediscovered,
            PatchLifecycleState::Inconclusive,
            PatchLifecycleState::Failed,
            PatchLifecycleState::Interrupted,
            PatchLifecycleState::ChangedSinceApply,
        ] {
            assert_eq!(PatchLifecycleState::from_str(state.as_str()), Some(state));
        }
        assert_eq!(PatchLifecycleState::from_str("made_up"), None);
    }
}
