use super::*;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingNextAction {
    Validate,
    Suppress,
    Patch,
    Review,
}

impl FindingNextAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Validate => "validate",
            Self::Suppress => "suppress",
            Self::Patch => "patch",
            Self::Review => "review",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProofLadderState {
    pub stage: String,
    pub label: String,
    pub reason: String,
    pub next_step: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FindingDetailReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub finding: Finding,
    pub proof_state: String,
    pub runtime_validation: String,
    pub proof_ladder: ProofLadderState,
    pub next_action: FindingNextAction,
    pub patch_results: Vec<PatchResult>,
    /// Canonical evidence-case projection. Present when the caller loads the
    /// append-only review history in addition to the current finding row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_case: Option<SecurityCaseProjection>,
    /// The operator's durable decision to postpone proof for exactly this
    /// discovery generation. A decision, not evidence: it never moves
    /// `proof_state`, `runtime_validation`, or `proof_ladder`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_deferral: Option<ProofDeferralView>,
}
