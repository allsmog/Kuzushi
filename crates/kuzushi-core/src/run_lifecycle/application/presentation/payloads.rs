use super::*;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum RunPresentationPayloadV1 {
    Plan(PlanPresentationV1),
    Task(TaskPresentationV1),
    ToolCall(ToolCallPresentationV1),
    ModelCall(ModelCallPresentationV1),
    Artifact(ArtifactReference),
    ResultSummary(ResultSummaryPresentationV1),
    ResultHydrationIssue(ResultHydrationIssuePresentationV1),
    FindingDelta(FindingDeltaSummary),
    Question(QuestionPresentationV1),
    Decision(DecisionPresentationV1),
    Progress(ProgressPresentationV1),
    SafeReasoning(SafeReasoningPresentationV1),
    Diagnostic(DiagnosticPresentationV1),
    Terminal(TerminalPresentationV1),
    PhaseReceipt(PhaseReceiptPresentationV1),
    ProgressDisclosure(ProgressDisclosurePresentationV1),
    LifecycleEvent(LifecycleEventPresentationV1),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleEventKindV1 {
    Plan,
    Task,
    ToolRequested,
    ToolRejected,
    ToolStarted,
    ToolFinished,
    ModelStarted,
    ModelFinished,
    ArtifactProduced,
    FindingsChanged,
    OperatorQuestion,
    OperatorDecision,
    TerminalOutcome,
    PhaseReceipt,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleEventPresentationV1 {
    pub kind: LifecycleEventKindV1,
    pub occurred_at_ms: u64,
    pub subject: SafeText,
    pub status: Option<RunItemStatus>,
    pub detail: Option<SafeText>,
    pub latency_ms: Option<u64>,
    pub cost: Option<RuntimeCostReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanPresentationV1 {
    pub revision: u64,
    pub title: SafeText,
    pub status: RunItemStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskPresentationV1 {
    pub task_id: RunTaskId,
    pub title: SafeText,
    pub status: RunItemStatus,
    pub detail: Option<SafeText>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallTimingV1 {
    pub requested_at_ms: Option<u64>,
    pub started_at_ms: Option<u64>,
    pub finished_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallPresentationV1 {
    pub call_id: RunCallId,
    pub task_id: Option<RunTaskId>,
    pub parent_item_id: Option<RunItemId>,
    pub label: SafeText,
    pub status: RunItemStatus,
    pub runtime: Option<SafeText>,
    pub model: Option<SafeText>,
    pub safe_option_names: Vec<SafeText>,
    pub cost: RuntimeCostReport,
    pub preview: Vec<SafeText>,
    pub warning_count: u64,
    pub error_count: u64,
    pub result_artifact: Option<ArtifactReference>,
    pub related_artifacts: Vec<ArtifactReference>,
    pub rejection: Option<CallRejectionPresentationV1>,
    pub timing: CallTimingV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallRejectionPresentationV1 {
    pub reason_class: SafeText,
    pub detail: SafeText,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelCallPresentationV1 {
    pub call_id: RunCallId,
    pub task_id: Option<RunTaskId>,
    pub parent_item_id: Option<RunItemId>,
    pub provider: Option<SafeText>,
    pub model: SafeText,
    pub status: RunItemStatus,
    pub latency_ms: Option<u64>,
    pub usage: Option<ModelUsage>,
    pub cost: RuntimeCostReport,
    pub error_class: Option<SafeText>,
    pub timing: CallTimingV1,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuestionPresentationV1 {
    pub question_id: RunQuestionId,
    pub state: QuestionPresentationStateV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<SafeText>,
    pub choices: Vec<OperatorChoice>,
    pub authorization_scope: SafeText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionPresentationStateV1 {
    AwaitingDecision,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionPresentationV1 {
    pub question_id: RunQuestionId,
    pub decision: OperatorDecisionValue,
    pub authorization_scope: SafeText,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultSummaryPresentationV1 {
    pub tool: SafeText,
    pub status: SafeText,
    pub summary: SafeText,
    pub output_lines: Vec<SafeText>,
    pub output_line_count: u64,
    pub warnings: Vec<SafeText>,
    pub warning_count: u64,
    pub errors: Vec<SafeText>,
    pub error_count: u64,
    pub artifacts: Vec<ResultArtifactPresentationV1>,
    pub artifact_count: u64,
}

impl ResultSummaryPresentationV1 {
    pub(super) fn omitted_count(&self) -> u64 {
        omitted(self.output_line_count, self.output_lines.len())
            .saturating_add(omitted(self.warning_count, self.warnings.len()))
            .saturating_add(omitted(self.error_count, self.errors.len()))
            .saturating_add(omitted(self.artifact_count, self.artifacts.len()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultArtifactPresentationV1 {
    pub label: SafeText,
    pub path: SafeText,
    pub kind: SafeText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultHydrationIssuePresentationV1 {
    pub detail: SafeText,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressPresentationV1 {
    pub call_id: Option<RunCallId>,
    pub message: SafeText,
    pub completed: Option<u64>,
    pub total: Option<u64>,
    pub occurred_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeReasoningPresentationV1 {
    pub text: SafeText,
    pub redaction_policy_version: u16,
    pub occurred_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticPresentationV1 {
    pub level: DiagnosticLevel,
    pub message: SafeText,
    pub occurred_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalPresentationV1 {
    pub status: RunItemStatus,
    pub summary: SafeText,
    pub cost: RuntimeCostReport,
    pub continuation: WorkflowContinuation,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhaseReceiptPresentationV1 {
    pub run_ids: Vec<RunId>,
    pub status: RunItemStatus,
    pub cost: RuntimeCostReport,
    pub finding_delta: FindingDeltaSummary,
    pub artifact_ids: Vec<RunItemId>,
    pub interaction_count: u64,
    pub offered_actions: Vec<WorkflowContinuation>,
    pub continuation: WorkflowContinuation,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressDisclosurePresentationV1 {
    pub progress_item_id: RunItemId,
    pub omitted_count: u64,
}

fn omitted(total: u64, retained: usize) -> u64 {
    total.saturating_sub(retained as u64)
}
