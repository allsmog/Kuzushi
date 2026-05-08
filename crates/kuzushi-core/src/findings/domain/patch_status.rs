use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PatchStatus {
    ApplyFailed,
    BuildFailed,
    StillVulnerable,
    TestsFailed,
    Sound,
    Verified,
    Unknown,
}

impl PatchStatus {
    pub fn as_str(self) -> &'static str {
        PATCH_STATUS_LABELS
            .iter()
            .find_map(|(status, label)| (*status == self).then_some(*label))
            .unwrap_or("UNKNOWN")
    }
}

impl TryFrom<&str> for PatchStatus {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        PATCH_STATUS_LABELS
            .iter()
            .find_map(|(status, label)| (*label == value).then_some(*status))
            .with_context(|| format!("unknown patch status {value:?}"))
    }
}

const PATCH_STATUS_LABELS: &[(PatchStatus, &str)] = &[
    (PatchStatus::ApplyFailed, "APPLY_FAILED"),
    (PatchStatus::BuildFailed, "BUILD_FAILED"),
    (PatchStatus::StillVulnerable, "STILL_VULNERABLE"),
    (PatchStatus::TestsFailed, "TESTS_FAILED"),
    (PatchStatus::Sound, "SOUND"),
    (PatchStatus::Verified, "VERIFIED"),
    (PatchStatus::Unknown, "UNKNOWN"),
];
