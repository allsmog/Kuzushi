use super::super::super::{PlanProjection, RunProjection, TaskProjection};
use crate::run_lifecycle::{RunItemEnvelopeV1, RunItemSource, RunItemStatus, RunTaskId, SafeText};
use anyhow::Result;

pub(super) fn apply_plan(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
    revision: u64,
    title: &SafeText,
    status: RunItemStatus,
    task_ids: &[RunTaskId],
) -> Result<()> {
    ensure_unique_task_ids(task_ids)?;
    if let Some(plan) = projection.plan.as_ref() {
        anyhow::ensure!(revision > plan.revision, "plan revision did not advance");
        ensure_no_terminal_regression(plan.status, status, "plan")?;
        anyhow::ensure!(plan.item_id == envelope.item_id, "plan item ID changed");
        anyhow::ensure!(&plan.title == title, "plan title changed");
        anyhow::ensure!(
            task_ids.starts_with(&plan.task_ids),
            "plan update removed or reordered semantic tasks"
        );
    }
    projection.plan = Some(PlanProjection {
        revision,
        item_id: envelope.item_id,
        title: title.clone(),
        status,
        task_ids: task_ids.to_vec(),
    });
    Ok(())
}

fn ensure_unique_task_ids(task_ids: &[RunTaskId]) -> Result<()> {
    let unique = task_ids.iter().copied().collect::<std::collections::HashSet<_>>();
    anyhow::ensure!(unique.len() == task_ids.len(), "plan repeats a semantic task");
    Ok(())
}

pub(super) fn apply_task(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
    title: &SafeText,
    status: RunItemStatus,
    detail: &Option<SafeText>,
) -> Result<()> {
    let task_id = required_task_id(envelope)?;
    validate_existing_task(projection, envelope, task_id, title, status)?;
    let first_seen_seq = projection
        .tasks
        .get(&task_id)
        .map_or(envelope.seq, |task| task.first_seen_seq);
    projection.tasks.insert(
        task_id,
        TaskProjection {
            item_id: envelope.item_id,
            title: title.clone(),
            status,
            detail: detail.clone(),
            first_seen_seq,
            updated_at_ms: envelope.occurred_at_ms,
        },
    );
    Ok(())
}

fn validate_existing_task(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
    task_id: RunTaskId,
    title: &SafeText,
    status: RunItemStatus,
) -> Result<()> {
    if let Some(task) = projection.tasks.get(&task_id) {
        ensure_no_terminal_regression(task.status, status, "task")?;
        anyhow::ensure!(task.item_id == envelope.item_id, "task item ID changed");
        anyhow::ensure!(&task.title == title, "task title changed");
    } else {
        ensure_initial_state(envelope.source, status, "task")?;
        projection.task_order.push(task_id);
    }
    Ok(())
}

fn required_task_id(envelope: &RunItemEnvelopeV1) -> Result<RunTaskId> {
    envelope
        .task_id
        .ok_or_else(|| anyhow::anyhow!("task update lacks task ID"))
}

fn ensure_initial_state(source: RunItemSource, status: RunItemStatus, context: &str) -> Result<()> {
    if !status.is_terminal() || source == RunItemSource::LegacyReconstruction {
        return Ok(());
    }
    anyhow::bail!("{context} first appeared terminal without legacy reconstruction")
}

fn ensure_no_terminal_regression(
    previous: RunItemStatus,
    next: RunItemStatus,
    context: &str,
) -> Result<()> {
    anyhow::ensure!(
        !previous.is_terminal(),
        "{context} changed after terminal state"
    );
    anyhow::ensure!(
        previous != RunItemStatus::Running || next != RunItemStatus::Pending,
        "{context} regressed to pending"
    );
    Ok(())
}
