//! View model for the end-of-engagement retry gate: the failed tasks, their
//! one-line errors, and any auto-adjustment that will be applied on retry.

use crate::ShellApp;

const MAX_RETRY_ROWS: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetryCardModel {
    pub(crate) failed_count: usize,
    pub(crate) rows: Vec<RetryCardRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetryCardRow {
    pub(crate) tool: String,
    pub(crate) error: String,
    /// Human label for the auto-adjustment (e.g. "retry with heap 12288 MB"),
    /// or `None` when the task will be retried as-is.
    pub(crate) adjustment: Option<String>,
}

pub(crate) fn retry_card_model(app: &ShellApp) -> Option<RetryCardModel> {
    let pending = app.advisory.pending_retry.as_ref()?;
    let rows = pending
        .tasks
        .iter()
        .take(MAX_RETRY_ROWS)
        .map(|item| RetryCardRow {
            tool: item.task.tool_name().to_string(),
            error: item.error.clone(),
            adjustment: item.adjustment.as_ref().map(|adj| adj.label()),
        })
        .collect();
    Some(RetryCardModel {
        failed_count: pending.tasks.len(),
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{FailedPlanningTask, PendingRetry, PlanningTaskId, RetryAdjustment};
    use kuzushi_core::V2Config;

    #[test]
    fn retry_card_model_summarizes_failures_with_adjustments() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.advisory.pending_retry = Some(PendingRetry {
            tasks: vec![FailedPlanningTask {
                task: PlanningTaskId::BuildCodePropertyGraph,
                error: "java heap OOM".to_string(),
                adjustment: Some(RetryAdjustment::RaiseHeap { heap_mb: 12288 }),
                blocked: vec![PlanningTaskId::HuntTaint],
            }],
        });

        let model = retry_card_model(&app).expect("retry card");
        assert_eq!(model.failed_count, 1);
        assert_eq!(model.rows[0].tool, "cpg:build");
        assert!(model.rows[0]
            .adjustment
            .as_deref()
            .unwrap()
            .contains("12288"));
    }

    #[test]
    fn retry_card_model_absent_without_pending_retry() {
        let app = ShellApp::new(V2Config::default(), None);
        assert!(retry_card_model(&app).is_none());
    }
}
