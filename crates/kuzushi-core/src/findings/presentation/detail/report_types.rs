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
    pub(in crate::findings) fn as_str(self) -> &'static str {
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
}
