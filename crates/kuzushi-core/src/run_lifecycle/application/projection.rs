use crate::run_lifecycle::{
    ArtifactReference, FindingDeltaSummary, ModelUsage, OperatorChoice, OperatorDecisionValue,
    RunCallId, RunId, RunItemEnvelopeV1, RunItemId, RunItemSource, RunItemStatus, RunQuestionId,
    RunTaskId, SafeText, WorkflowContinuation,
};
use crate::runtime::RuntimeCostReport;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum ProjectionHealth {
    Healthy,
    LegacyLossy,
    Degraded {
        valid_through_seq: u64,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum RunDurabilityHealth {
    Durable {
        through_seq: u64,
    },
    Failed {
        last_durable_seq: u64,
        stage: PersistenceFailureStage,
        detail: SafeText,
        execution_may_have_occurred: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceFailureStage {
    Prepare,
    Append,
    Sync,
    Flush,
    Delivery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum RunProgressFidelity {
    Complete,
    Coalesced { omitted: u64 },
    Saturated { omitted_at_least: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum RunDeliveryHealth {
    Current {
        through_seq: u64,
    },
    CatchingUp {
        applied_seq: u64,
        durable_seq: u64,
    },
    Failed {
        applied_seq: u64,
        stage: crate::run_lifecycle::RunItemDeliveryFailureStage,
        detail: SafeText,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum RunDerivativeDeliveryHealth {
    NotObserved,
    Current {
        through_seq: u64,
    },
    CatchingUp {
        applied_seq: u64,
        durable_seq: u64,
    },
    Failed {
        applied_seq: u64,
        durable_seq: u64,
        stage: crate::run_lifecycle::RunItemDeliveryFailureStage,
        detail: SafeText,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunLifecycleHealth {
    pub integrity: ProjectionHealth,
    pub durability: RunDurabilityHealth,
    pub progress: RunProgressFidelity,
    pub delivery: RunDeliveryHealth,
    pub derivative_delivery: RunDerivativeDeliveryHealth,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanProjection {
    pub revision: u64,
    pub item_id: RunItemId,
    pub title: SafeText,
    pub status: RunItemStatus,
    pub task_ids: Vec<RunTaskId>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskProjection {
    pub item_id: RunItemId,
    pub title: SafeText,
    pub status: RunItemStatus,
    pub detail: Option<SafeText>,
    pub first_seen_seq: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Tool,
    Model,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallProjection {
    pub item_id: RunItemId,
    pub task_id: Option<RunTaskId>,
    pub parent_item_id: Option<RunItemId>,
    pub kind: CallKind,
    pub label: SafeText,
    pub status: RunItemStatus,
    pub runtime: Option<SafeText>,
    pub model: Option<SafeText>,
    pub provider: Option<SafeText>,
    pub requested_at_ms: Option<u64>,
    pub started_at_ms: Option<u64>,
    pub completed_at_ms: Option<u64>,
    pub latency_ms: Option<u64>,
    pub usage: ModelUsage,
    pub error_class: Option<SafeText>,
    pub cost: RuntimeCostReport,
    pub preview: Vec<SafeText>,
    pub warning_count: u64,
    pub error_count: u64,
    pub result_artifact: Option<ArtifactReference>,
    pub related_artifact_ids: Vec<RunItemId>,
    pub first_seen_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuestionDecisionProjection {
    pub item_id: RunItemId,
    pub occurred_at_ms: u64,
    pub source: RunItemSource,
    pub authorization_scope: SafeText,
    pub value: OperatorDecisionValue,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuestionProjection {
    pub question_id: RunQuestionId,
    pub item_id: RunItemId,
    pub prompt: SafeText,
    pub choices: Vec<OperatorChoice>,
    pub authorization_scope: SafeText,
    pub source: RunItemSource,
    pub occurred_at_ms: u64,
    pub decision: Option<QuestionDecisionProjection>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhaseReceiptProjection {
    pub item_id: RunItemId,
    pub run_ids: Vec<RunId>,
    pub status: RunItemStatus,
    pub cost: RuntimeCostReport,
    pub finding_delta: FindingDeltaSummary,
    pub artifact_ids: Vec<RunItemId>,
    pub interaction_count: u64,
    pub offered_actions: Vec<WorkflowContinuation>,
    pub continuation: WorkflowContinuation,
    pub occurred_at_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionDelta {
    pub plan_changed: bool,
    pub task_ids: Vec<RunTaskId>,
    pub call_ids: Vec<RunCallId>,
    pub question_ids: Vec<RunQuestionId>,
    pub terminal_changed: bool,
    pub phase_receipt_changed: bool,
    pub timeline_appended: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalProjection {
    pub item_id: RunItemId,
    pub status: RunItemStatus,
    pub summary: SafeText,
    pub cost: RuntimeCostReport,
    pub continuation: WorkflowContinuation,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunProjection {
    pub run_id: Option<RunId>,
    pub health: ProjectionHealth,
    pub last_committed_seq: u64,
    pub last_event_hash: Option<String>,
    pub plan: Option<PlanProjection>,
    pub tasks: BTreeMap<RunTaskId, TaskProjection>,
    pub task_order: Vec<RunTaskId>,
    pub calls: BTreeMap<RunCallId, CallProjection>,
    pub call_order: Vec<RunCallId>,
    pub timeline: Vec<RunItemEnvelopeV1>,
    pub artifacts: BTreeMap<RunItemId, ArtifactReference>,
    pub finding_deltas: Vec<FindingDeltaSummary>,
    pub observed_model_cost: RuntimeCostReport,
    pub questions: BTreeMap<RunQuestionId, QuestionProjection>,
    pub terminal: Option<TerminalProjection>,
    pub phase_receipt: Option<PhaseReceiptProjection>,
    pub continuation: Option<WorkflowContinuation>,
    pub omitted_progress_count: u64,
    #[serde(skip)]
    pub(crate) progress_saturated: bool,
    #[serde(skip)]
    pub(crate) committed_event_hashes: BTreeMap<u64, String>,
}

impl Default for RunProjection {
    fn default() -> Self {
        Self {
            run_id: None,
            health: ProjectionHealth::Healthy,
            last_committed_seq: 0,
            last_event_hash: None,
            plan: None,
            tasks: BTreeMap::new(),
            task_order: Vec::new(),
            calls: BTreeMap::new(),
            call_order: Vec::new(),
            timeline: Vec::new(),
            artifacts: BTreeMap::new(),
            finding_deltas: Vec::new(),
            observed_model_cost: RuntimeCostReport::UNAVAILABLE,
            questions: BTreeMap::new(),
            terminal: None,
            phase_receipt: None,
            continuation: None,
            omitted_progress_count: 0,
            progress_saturated: false,
            committed_event_hashes: BTreeMap::new(),
        }
    }
}

impl RunProjection {
    pub fn apply_committed(
        &mut self,
        envelope: RunItemEnvelopeV1,
    ) -> anyhow::Result<ProjectionDelta> {
        anyhow::ensure!(
            self.health == ProjectionHealth::Healthy,
            "degraded projection cannot advance beyond its last valid prefix"
        );
        super::apply_envelope(self, envelope).inspect_err(|error| {
            self.degrade(error.to_string());
        })
    }

    pub fn effective_cost(&self) -> RuntimeCostReport {
        self.terminal
            .as_ref()
            .map_or(self.observed_model_cost, |terminal| terminal.cost)
    }

    pub fn outstanding_questions(&self) -> Vec<RunQuestionId> {
        self.questions
            .iter()
            .filter_map(|(question_id, question)| {
                question.decision.is_none().then_some(*question_id)
            })
            .collect()
    }

    pub fn lifecycle_health(&self) -> RunLifecycleHealth {
        let progress = if self.progress_saturated {
            RunProgressFidelity::Saturated {
                omitted_at_least: self.omitted_progress_count,
            }
        } else if self.omitted_progress_count == 0 {
            RunProgressFidelity::Complete
        } else {
            RunProgressFidelity::Coalesced {
                omitted: self.omitted_progress_count,
            }
        };
        RunLifecycleHealth {
            integrity: self.health.clone(),
            durability: RunDurabilityHealth::Durable {
                through_seq: self.last_committed_seq,
            },
            progress,
            delivery: RunDeliveryHealth::Current {
                through_seq: self.last_committed_seq,
            },
            derivative_delivery: RunDerivativeDeliveryHealth::NotObserved,
        }
    }

    pub(crate) fn degrade(&mut self, reason: impl Into<String>) {
        self.health = ProjectionHealth::Degraded {
            valid_through_seq: self.last_committed_seq,
            reason: reason.into(),
        };
    }
}
