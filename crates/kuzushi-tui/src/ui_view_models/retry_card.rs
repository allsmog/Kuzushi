//! View model for the end-of-engagement retry gate: the failed tasks, their
//! and their one-line errors.

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
}

pub(crate) fn retry_card_model(app: &ShellApp) -> Option<RetryCardModel> {
    let pending = app.advisory().pending_retry.as_ref()?;
    let rows = pending
        .tasks
        .iter()
        .take(MAX_RETRY_ROWS)
        .map(|item| RetryCardRow {
            tool: item.task.tool_name().to_string(),
            error: item.error.clone(),
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
    use crate::app::{FailedPlanningTask, PendingRetry, PlanningTaskId};
    use kuzushi_core::V2Config;

    #[test]
    fn retry_card_model_summarizes_failures() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.advisory_mut().pending_retry = Some(PendingRetry {
            tasks: vec![FailedPlanningTask {
                task: PlanningTaskId::BuildCodePropertyGraph,
                error: "graph build failed".to_string(),
                blocked: vec![PlanningTaskId::HuntTaint],
            }],
        });

        let model = retry_card_model(&app).expect("retry card");
        assert_eq!(model.failed_count, 1);
        assert_eq!(model.rows[0].tool, "cpg:build");
        assert!(model.rows[0].error.contains("graph build failed"));
    }

    #[test]
    fn retry_card_model_absent_without_pending_retry() {
        let app = ShellApp::new(V2Config::default(), None);
        assert!(retry_card_model(&app).is_none());
    }
}
