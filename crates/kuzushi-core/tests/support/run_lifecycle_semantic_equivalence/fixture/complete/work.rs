//! Plan and task records for the complete fixture.

use super::super::*;
use kuzushi_core::run_lifecycle::DiagnosticLevel;

pub(super) fn starting_records(ids: FixtureIds) -> Vec<RunItemRecord> {
    vec![
        record(
            ids.plan_item,
            RunItemSource::Workflow,
            RunItemV1::PlanUpdated {
                revision: 1,
                title: text("verify one finding"),
                status: RunItemStatus::Pending,
                task_ids: vec![ids.task],
            },
        ),
        task_record(ids, RunItemStatus::Pending, None),
        task_record(ids, RunItemStatus::Running, Some("dispatching verifier")),
    ]
}

pub(super) fn closing_records(ids: FixtureIds) -> Vec<RunItemRecord> {
    vec![
        task_record(ids, RunItemStatus::Completed, Some("proof persisted")),
        record(
            ids.plan_item,
            RunItemSource::Workflow,
            RunItemV1::PlanUpdated {
                revision: 2,
                title: text("verify one finding"),
                status: RunItemStatus::Completed,
                task_ids: vec![ids.task],
            },
        ),
        record(
            ids.diagnostic_item,
            RunItemSource::Workflow,
            RunItemV1::DiagnosticNotice {
                level: DiagnosticLevel::Info,
                message: text("receipt ready"),
            },
        ),
    ]
}
