use crate::modules::WorkflowPhase;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReasonTag {
    /// No baseline at all for this scope: a full scan seeds coverage.
    NeverScanned,
    /// Earlier phases ran but this phase never did.
    PhaseGap,
    /// Files under the scope changed since the recorded baseline.
    Changed,
    /// Surface-bearing files with zero findings citing them.
    SinkGap,
    /// Legacy compatibility value. New recommendations do not infer saturation
    /// from baseline counts, which lack pass grouping and finding-yield evidence.
    Saturated,
}

impl ReasonTag {
    pub fn label(self) -> &'static str {
        match self {
            Self::NeverScanned => "never-scanned",
            Self::PhaseGap => "phase-gap",
            Self::Changed => "changed",
            Self::SinkGap => "sink-gap",
            Self::Saturated => "saturated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRecommendation {
    pub scope_id: String,
    pub phase: WorkflowPhase,
    pub reason: ReasonTag,
    /// Deterministic rank weight in [0, 1]; ties broken by scope id.
    pub score: f32,
    /// The mechanical fact behind the row, e.g. "14 files changed since
    /// a1b2c3d4" or "6 surface-bearing files, 0 findings".
    pub evidence: String,
    pub suggested_mode: Option<String>,
}
