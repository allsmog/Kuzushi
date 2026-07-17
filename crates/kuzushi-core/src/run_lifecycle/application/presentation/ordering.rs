use super::*;

pub(super) fn ordered_task_ids(projection: &RunProjection) -> Vec<RunTaskId> {
    let mut order = projection
        .plan
        .iter()
        .flat_map(|plan| plan.task_ids.iter().copied())
        .filter(|task_id| projection.tasks.contains_key(task_id))
        .collect::<Vec<_>>();
    append_first_seen_tasks(&mut order, projection);
    for task_id in projection.tasks.keys().copied() {
        push_unique(&mut order, task_id);
    }
    order
}

fn append_first_seen_tasks(order: &mut Vec<RunTaskId>, projection: &RunProjection) {
    for envelope in &projection.timeline {
        if matches!(envelope.item, RunItemV1::TaskUpdated { .. }) {
            if let Some(task_id) = envelope.task_id {
                push_unique(order, task_id);
            }
        }
    }
}

pub(super) fn first_seen_calls(projection: &RunProjection) -> Vec<RunCallId> {
    let mut order = Vec::new();
    for envelope in &projection.timeline {
        if let Some(call_id) = envelope.call_id {
            push_unique(&mut order, call_id);
        }
    }
    for call_id in projection.calls.keys().copied() {
        push_unique(&mut order, call_id);
    }
    order
}

fn push_unique<T: Copy + PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}
