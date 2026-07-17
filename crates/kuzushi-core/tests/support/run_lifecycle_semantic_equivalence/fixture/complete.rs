//! Complete typed-run fixture assembly.

use super::*;
use kuzushi_core::run_lifecycle::{ArtifactReference, RunId, WorkflowContinuation};

#[path = "complete/calls.rs"]
mod calls;
#[path = "complete/outcome.rs"]
mod outcome;
#[path = "complete/work.rs"]
mod work;

pub(super) fn records(
    run_id: &str,
    ids: FixtureIds,
    result_reference: ArtifactReference,
) -> Vec<RunItemRecord> {
    let exact = exact_cost(0.0125);
    let delta = finding_delta();
    let report = WorkflowContinuation::OpenReport {
        reason: text("review typed evidence"),
    };
    let mut records = work::starting_records(ids);
    records.extend(calls::outer_start_records(ids));
    records.extend(calls::child_start_records(ids));
    records.extend(calls::unavailable_model_records(ids));
    records.extend(calls::child_finish_records(ids));
    records.extend(calls::outer_execution_records(ids, exact));
    records.push(calls::outer_finish(ids, exact, result_reference));
    records.extend(outcome::evidence_records(ids, delta.clone()));
    records.extend(outcome::decision_records(ids));
    records.extend(work::closing_records(ids));
    records.extend(outcome::terminal_records(
        RunId::parse(run_id).unwrap(),
        ids,
        exact,
        delta,
        report,
    ));
    records
}
