//! Failure bookkeeping for the phase walker: which planning tasks failed, why,
//! and (Phase 5) how to auto-adjust them on retry. Populated by the
//! tool-failure path and consumed by the dependency-aware skip logic and the
//! end-of-run retry gate.

use super::task_id::PlanningTaskId;

/// A planning task that failed during the engagement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedPlanningTask {
    pub task: PlanningTaskId,
    /// Operator-facing failure summary (the tool's error text).
    pub error: String,
    /// An automatic remediation to apply on retry, when the cause is known
    /// (e.g. a joern heap OOM → re-run with a larger `-J-Xmx`).
    pub adjustment: Option<RetryAdjustment>,
    /// Same-phase tasks that were skipped because they depended on this one;
    /// re-queued alongside it when the operator accepts the retry.
    pub blocked: Vec<PlanningTaskId>,
}

/// The end-of-engagement retry prompt: a yes/no gate offering to re-run the
/// tasks that failed (with any auto-adjustment) and their blocked dependents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRetry {
    pub tasks: Vec<FailedPlanningTask>,
}

/// A parameter change to apply when retrying a failed task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryAdjustment {
    /// Re-run with a larger JVM heap (MB), e.g. for a joern/CodeQL OOM.
    RaiseHeap { heap_mb: u64 },
}

impl RetryAdjustment {
    /// Short human label for the retry card ("retry with heap 12 GB").
    pub fn label(&self) -> String {
        match self {
            RetryAdjustment::RaiseHeap { heap_mb } => {
                format!("retry with heap {} MB", heap_mb)
            }
        }
    }
}
