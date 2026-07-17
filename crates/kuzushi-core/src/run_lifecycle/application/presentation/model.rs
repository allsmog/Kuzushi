use super::*;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunPresentationV1 {
    pub run_id: Option<RunId>,
    pub source: RunProjectionSource,
    pub health: RunLifecycleHealth,
    pub summary: Vec<RunPresentationSectionV1>,
    pub timeline: Vec<RunPresentationCellV1>,
    pub terminal_status: Option<RunItemStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunPresentationSectionKindV1 {
    Work,
    Evidence,
    Attention,
    Outcome,
}

impl RunPresentationSectionKindV1 {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Work => "WORK",
            Self::Evidence => "EVIDENCE",
            Self::Attention => "ATTENTION",
            Self::Outcome => "OUTCOME",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunPresentationSectionV1 {
    pub kind: RunPresentationSectionKindV1,
    pub cells: Vec<RunPresentationCellV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case", tag = "source", content = "value")]
pub enum RunCellSourceV1 {
    Item(RunItemId),
    ArtifactDigest(SafeText),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunCellRoleV1 {
    Plan,
    Task,
    ToolCall,
    ModelCall,
    Artifact,
    ResultSummary,
    FindingDelta,
    Question,
    Decision,
    Progress,
    SafeReasoning,
    Diagnostic,
    TerminalOutcome,
    PhaseReceipt,
    ProgressDisclosure,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunCellKey {
    pub source: RunCellSourceV1,
    pub role: RunCellRoleV1,
    pub ordinal: u64,
}

impl RunCellKey {
    pub(super) fn item(item_id: RunItemId, role: RunCellRoleV1, ordinal: u64) -> Self {
        Self {
            source: RunCellSourceV1::Item(item_id),
            role,
            ordinal,
        }
    }

    pub(super) fn artifact(digest: SafeText, ordinal: u64) -> Self {
        Self::artifact_role(digest, RunCellRoleV1::Artifact, ordinal)
    }

    pub(super) fn artifact_role(digest: SafeText, role: RunCellRoleV1, ordinal: u64) -> Self {
        Self {
            source: RunCellSourceV1::ArtifactDigest(digest),
            role,
            ordinal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunCellImportanceV1 {
    Essential,
    Detail,
    Diagnostic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunCellDisclosureV1 {
    pub reason: SafeText,
    pub omitted_count: Option<u64>,
    pub inspect_action: Option<WorkflowContinuation>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunPresentationCellV1 {
    pub key: RunCellKey,
    pub importance: RunCellImportanceV1,
    pub payload: RunPresentationPayloadV1,
    pub disclosure: Option<RunCellDisclosureV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPresentationTextRowV1 {
    pub key: RunCellKey,
    pub section: Option<RunPresentationSectionKindV1>,
    pub importance: RunCellImportanceV1,
    pub status: Option<RunItemStatus>,
    pub diagnostic_level: Option<DiagnosticLevel>,
    pub text: String,
}

pub(super) fn cell(
    key: RunCellKey,
    importance: RunCellImportanceV1,
    payload: RunPresentationPayloadV1,
) -> RunPresentationCellV1 {
    RunPresentationCellV1 {
        key,
        importance,
        payload,
        disclosure: None,
    }
}

pub(super) fn ordinal_key(
    item_id: RunItemId,
    role: RunCellRoleV1,
    ordinals: &mut BTreeMap<(RunItemId, RunCellRoleV1), u64>,
) -> RunCellKey {
    let ordinal = next_ordinal(ordinals, (item_id, role));
    RunCellKey::item(item_id, role, ordinal)
}

pub(super) fn next_ordinal<K: Ord>(counts: &mut BTreeMap<K, u64>, key: K) -> u64 {
    let count = counts.entry(key).or_default();
    let ordinal = *count;
    *count = count.saturating_add(1);
    ordinal
}
