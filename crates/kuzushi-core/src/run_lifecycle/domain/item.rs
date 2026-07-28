use super::{RunId, RunItemId, RunQuestionId, RunTaskId, SafeText};
use crate::runtime::RuntimeCostReport;
use crate::WorkflowPhase;
use serde::{Deserialize, Deserializer, Serialize};

pub const MAX_PREVIEW_LINES: usize = 12;
pub const MAX_WARNING_OR_ERROR_COUNT: usize = 8;
pub const MAX_ARTIFACT_REFERENCES: usize = 16;
pub const MAX_FINDING_ID_SAMPLES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunItemStatus {
    Pending,
    Running,
    Completed,
    Partial,
    Skipped,
    Blocked,
    Failed,
    Canceled,
    Interrupted,
}

impl RunItemStatus {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending | Self::Running)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Partial => "partial",
            Self::Skipped => "skipped",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
            Self::Interrupted => "interrupted",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "pending" => Some(Self::Pending),
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "partial" => Some(Self::Partial),
            "skipped" => Some(Self::Skipped),
            "blocked" => Some(Self::Blocked),
            "failed" => Some(Self::Failed),
            "canceled" => Some(Self::Canceled),
            "interrupted" => Some(Self::Interrupted),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct OperationFingerprint(String);

impl OperationFingerprint {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("blake3:{}", blake3::hash(bytes).to_hex()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_digest(digest: [u8; 32]) -> Self {
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Self(format!("blake3:{hex}"))
    }
}

impl<'de> Deserialize<'de> for OperationFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        validate_fingerprint(&value).map_err(serde::de::Error::custom)?;
        Ok(Self(value))
    }
}

fn validate_fingerprint(value: &str) -> anyhow::Result<()> {
    let digest = value
        .strip_prefix("blake3:")
        .ok_or_else(|| anyhow::anyhow!("operation fingerprint must use blake3"))?;
    anyhow::ensure!(
        digest.len() == 64,
        "operation fingerprint has invalid length"
    );
    anyhow::ensure!(
        digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid digest"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactReference {
    pub path: SafeText,
    pub kind: SafeText,
    pub label: SafeText,
    pub digest: SafeText,
    pub byte_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_count: Option<u64>,
    pub producing_item_id: RunItemId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingDeltaSummary {
    pub added: u64,
    pub updated: u64,
    pub removed: u64,
    pub store_watermark: SafeText,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finding_id_samples: Vec<SafeText>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelUsage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowContinuation {
    OpenPhase { phase: WorkflowPhase },
    OpenReport { reason: SafeText },
    InspectRun { run_id: RunId, reason: SafeText },
    Retry { reason: SafeText },
    AwaitDecision { question_id: RunQuestionId },
    NoFurtherAction { reason: SafeText },
}

impl WorkflowContinuation {
    pub fn operator_label(&self) -> String {
        match self {
            Self::OpenPhase { phase } => format!("open {}", phase.label()),
            Self::OpenReport { reason } => format!("open Report · {reason}"),
            Self::InspectRun { run_id, reason } => format!("inspect {run_id} · {reason}"),
            Self::Retry { reason } => format!("retry · {reason}"),
            Self::AwaitDecision { question_id } => format!("answer question {question_id}"),
            Self::NoFurtherAction { reason } => format!("none · {reason}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperatorChoice {
    pub id: SafeText,
    pub label: SafeText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OperatorDecisionValue {
    Selected { choice_id: SafeText },
    ProvidedFreeform,
    Approved,
    Denied,
    Deferred,
}

impl<'de> Deserialize<'de> for OperatorDecisionValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictOperatorDecisionValue::deserialize(deserializer).map(Into::into)
    }
}

// Serde accepts extra map keys on internally tagged unit variants. Empty
// struct variants keep the public enum API unchanged while closing that wire
// boundary before a persisted decision can be hashed into different semantics.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StrictOperatorDecisionValue {
    Selected { choice_id: SafeText },
    ProvidedFreeform {},
    Approved {},
    Denied {},
    Deferred {},
}

impl From<StrictOperatorDecisionValue> for OperatorDecisionValue {
    fn from(value: StrictOperatorDecisionValue) -> Self {
        match value {
            StrictOperatorDecisionValue::Selected { choice_id } => Self::Selected { choice_id },
            StrictOperatorDecisionValue::ProvidedFreeform {} => Self::ProvidedFreeform,
            StrictOperatorDecisionValue::Approved {} => Self::Approved,
            StrictOperatorDecisionValue::Denied {} => Self::Denied,
            StrictOperatorDecisionValue::Deferred {} => Self::Deferred,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    Info,
    Warning,
    Error,
}

/// Stable v1 diagnostic marker used to distinguish unique-key saturation
/// from ordinary same-key progress coalescing without changing RunItemV1.
pub(crate) const RUN_PROGRESS_SATURATION_MARKER: &str =
    "progress fidelity saturated; unique progress updates were omitted";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunItemV1 {
    PlanUpdated {
        revision: u64,
        title: SafeText,
        status: RunItemStatus,
        task_ids: Vec<RunTaskId>,
    },
    TaskUpdated {
        title: SafeText,
        status: RunItemStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<SafeText>,
    },
    ToolCallRequested {
        tool_name: SafeText,
        operation_fingerprint: OperationFingerprint,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        safe_option_names: Vec<SafeText>,
    },
    ToolCallRejected {
        reason_class: SafeText,
        detail: SafeText,
    },
    ToolCallStarted {
        tool_name: SafeText,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        runtime: Option<SafeText>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<SafeText>,
    },
    ToolCallProgress {
        message: SafeText,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        completed: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        total: Option<u64>,
    },
    ToolCallFinished {
        status: RunItemStatus,
        cost: RuntimeCostReport,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result_artifact: Option<ArtifactReference>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        preview: Vec<SafeText>,
        warning_count: u64,
        error_count: u64,
    },
    ModelCallStarted {
        provider: SafeText,
        model: SafeText,
        operation_fingerprint: OperationFingerprint,
    },
    ModelCallFinished {
        provider: SafeText,
        model: SafeText,
        status: RunItemStatus,
        latency_ms: u64,
        usage: ModelUsage,
        cost: RuntimeCostReport,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_class: Option<SafeText>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure: Option<crate::runtime::RuntimeFailureMetadata>,
    },
    SafeReasoningSummary {
        text: SafeText,
        redaction_policy_version: u16,
    },
    ArtifactProduced {
        artifact: ArtifactReference,
    },
    FindingDelta {
        delta: FindingDeltaSummary,
    },
    OperatorQuestion {
        question_id: RunQuestionId,
        prompt: SafeText,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        choices: Vec<OperatorChoice>,
        authorization_scope: SafeText,
    },
    OperatorDecision {
        question_id: RunQuestionId,
        decision: OperatorDecisionValue,
        authorization_scope: SafeText,
    },
    DiagnosticNotice {
        level: DiagnosticLevel,
        message: SafeText,
    },
    TerminalOutcome {
        status: RunItemStatus,
        summary: SafeText,
        cost: RuntimeCostReport,
        continuation: WorkflowContinuation,
    },
    PhaseReceipt {
        run_ids: Vec<RunId>,
        status: RunItemStatus,
        cost: RuntimeCostReport,
        finding_delta: FindingDeltaSummary,
        artifact_ids: Vec<RunItemId>,
        interaction_count: u64,
        offered_actions: Vec<WorkflowContinuation>,
        continuation: WorkflowContinuation,
    },
    ProgressTruncated {
        progress_item_id: RunItemId,
        omitted_count: u64,
    },
}

impl RunItemV1 {
    pub fn status(&self) -> Option<RunItemStatus> {
        match self {
            Self::PlanUpdated { status, .. }
            | Self::TaskUpdated { status, .. }
            | Self::ToolCallFinished { status, .. }
            | Self::ModelCallFinished { status, .. }
            | Self::TerminalOutcome { status, .. }
            | Self::PhaseReceipt { status, .. } => Some(*status),
            Self::ToolCallRejected { .. } => Some(RunItemStatus::Blocked),
            Self::ToolCallStarted { .. } | Self::ModelCallStarted { .. } => {
                Some(RunItemStatus::Running)
            }
            _ => None,
        }
    }
}
