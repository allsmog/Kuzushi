//! Failure bookkeeping for the phase walker: which planning tasks failed and
//! why. Populated by the tool-failure path and consumed by the
//! dependency-aware skip logic and the end-of-run retry gate.

use super::task_id::PlanningTaskId;

/// A planning task that failed during the engagement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedPlanningTask {
    pub task: PlanningTaskId,
    /// Operator-facing failure summary (the tool's error text).
    pub error: String,
    /// Same-phase tasks that were skipped because they depended on this one;
    /// re-queued alongside it when the operator accepts the retry.
    pub blocked: Vec<PlanningTaskId>,
}

/// The end-of-engagement retry prompt: a yes/no gate offering to re-run the
/// tasks that failed and their blocked dependents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRetry {
    pub tasks: Vec<FailedPlanningTask>,
}

