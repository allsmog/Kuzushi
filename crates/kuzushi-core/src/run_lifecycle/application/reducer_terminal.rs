use super::super::super::{RunProjection, TerminalProjection};
use crate::run_lifecycle::{RunItemEnvelopeV1, RunItemStatus, RunItemV1};
use anyhow::Result;

pub(super) fn apply_terminal_item(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Result<()> {
    let RunItemV1::TerminalOutcome {
        status,
        summary,
        cost,
        continuation,
    } = &envelope.item
    else {
        unreachable!("caller classified a terminal outcome")
    };
    anyhow::ensure!(
        projection.terminal.is_none(),
        "terminal outcome already exists"
    );
    validate_terminal_calls(projection)?;
    validate_terminal_tasks(projection, *status)?;
    close_open_plan(projection, *status)?;
    projection.terminal = Some(TerminalProjection {
        item_id: envelope.item_id,
        status: *status,
        summary: summary.clone(),
        cost: *cost,
        continuation: continuation.clone(),
    });
    projection.continuation = Some(continuation.clone());
    Ok(())
}

fn validate_terminal_calls(projection: &RunProjection) -> Result<()> {
    anyhow::ensure!(
        projection
            .calls
            .values()
            .all(|call| call.status.is_terminal()),
        "terminal outcome was emitted while calls were still open"
    );
    Ok(())
}

fn validate_terminal_tasks(projection: &RunProjection, status: RunItemStatus) -> Result<()> {
    if projection.tasks.is_empty() {
        return Ok(());
    }
    anyhow::ensure!(
        projection
            .tasks
            .values()
            .all(|task| task.status.is_terminal()),
        "terminal outcome was emitted while semantic tasks were still open"
    );
    anyhow::ensure!(status.is_terminal(), "terminal outcome is not terminal");
    validate_completed_tasks(projection, status)?;
    validate_skipped_tasks(projection, status)
}

fn validate_completed_tasks(projection: &RunProjection, status: RunItemStatus) -> Result<()> {
    let truthful = status != RunItemStatus::Completed
        || projection.tasks.values().all(|task| {
            matches!(
                task.status,
                RunItemStatus::Completed | RunItemStatus::Skipped
            )
        });
    anyhow::ensure!(truthful, "completed outcome contradicts a non-success task");
    Ok(())
}

fn validate_skipped_tasks(projection: &RunProjection, status: RunItemStatus) -> Result<()> {
    let truthful = status != RunItemStatus::Skipped
        || projection
            .tasks
            .values()
            .all(|task| task.status == RunItemStatus::Skipped);
    anyhow::ensure!(truthful, "skipped outcome contradicts a non-skipped task");
    Ok(())
}

fn close_open_plan(projection: &mut RunProjection, status: RunItemStatus) -> Result<()> {
    let Some(plan) = projection.plan.as_mut() else {
        return Ok(());
    };
    if plan.status.is_terminal() {
        anyhow::ensure!(
            plan.status == status,
            "terminal outcome contradicts plan status"
        );
    } else {
        plan.status = status;
    }
    Ok(())
}
