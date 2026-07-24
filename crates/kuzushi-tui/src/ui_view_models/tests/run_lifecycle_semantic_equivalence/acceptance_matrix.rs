use super::fixture::{outstanding_decision_records, terminal_status_records};
use super::*;
use kuzushi_core::run_lifecycle::{RunCellRoleV1, RunItemStatus, RunProgressFidelity};
use std::collections::BTreeSet;

#[test]
fn terminal_status_matrix_keeps_typed_truth_across_surfaces() {
    for status in terminal_statuses() {
        let target = tempfile::tempdir().unwrap();
        let run_id = format!("semantic-equivalence-{}", status.label());
        let fixture = persist_records(
            target.path(),
            &run_id,
            terminal_status_records(&run_id, status),
        );

        assert_eq!(
            fixture.read.projection.terminal.as_ref().unwrap().status,
            status
        );
        let presentation = kuzushi_core::run_lifecycle::present_run(&fixture.read);
        assert_eq!(
            presentation.terminal_status,
            Some(status),
            "{run_id}: canonical terminal status"
        );
        assert_terminal_status_rendering(&presentation, status, &run_id);
        assert_terminal_json_status(&presentation, status, &run_id);
        assert_surface_equivalence(target.path(), &run_id, fixture);
    }
}

#[test]
fn outstanding_decision_is_source_backed_and_equivalent_across_surfaces() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "semantic-equivalence-outstanding-decision";
    let ids = FixtureIds::fixed();
    let fixture = persist_records(
        target.path(),
        run_id,
        outstanding_decision_records(run_id, ids),
    );
    assert_eq!(
        fixture.read.projection.outstanding_questions(),
        vec![ids.question]
    );
    let presentation = kuzushi_core::run_lifecycle::present_run(&fixture.read);
    let roles = presentation
        .semantic_keys()
        .into_iter()
        .map(|key| key.role)
        .collect::<BTreeSet<_>>();
    assert!(roles.contains(&RunCellRoleV1::Question));
    assert!(!roles.contains(&RunCellRoleV1::Decision));
    assert_surface_equivalence(target.path(), run_id, fixture);
}

#[test]
fn acceptance_fixture_discloses_loss_and_preserves_cost_usage_and_result_identity() {
    let target = tempfile::tempdir().unwrap();
    let ids = FixtureIds::fixed();
    let complete = persist_complete_fixture(target.path(), COMPLETE_RUN_ID, ids);
    let presentation = kuzushi_core::run_lifecycle::present_run(&complete.read);
    assert_eq!(
        presentation.health.progress,
        RunProgressFidelity::Coalesced { omitted: 7 }
    );
    assert_complete_contract(&presentation, ids);

    let partial_target = tempfile::tempdir().unwrap();
    let partial = persist_records(
        partial_target.path(),
        PARTIAL_RUN_ID,
        partial_records(PARTIAL_RUN_ID, ids),
    );
    assert_partial_contract(&kuzushi_core::run_lifecycle::present_run(&partial.read));
}

fn terminal_statuses() -> [RunItemStatus; 7] {
    [
        RunItemStatus::Completed,
        RunItemStatus::Partial,
        RunItemStatus::Blocked,
        RunItemStatus::Failed,
        RunItemStatus::Canceled,
        RunItemStatus::Interrupted,
        RunItemStatus::Skipped,
    ]
}

fn assert_terminal_status_rendering(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    status: RunItemStatus,
    run_id: &str,
) {
    let expected_outcome = format!(
        "Outcome · {} · {} status fixture",
        status.label(),
        status.label()
    );
    assert!(
        presentation
            .summary_text_rows()
            .iter()
            .any(|row| row.key.role == RunCellRoleV1::TerminalOutcome
                && row.text == expected_outcome),
        "{run_id}: missing exact outcome text {expected_outcome:?}"
    );
    assert_terminal_timeline_rendering(presentation, status, run_id);
}

fn assert_terminal_timeline_rendering(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    status: RunItemStatus,
    run_id: &str,
) {
    let (_, _, glyph) = terminal_expectation(status);
    let expected = format!(
        "  {glyph} Run {} · {} status fixture",
        status.label(),
        status.label()
    );
    let row = presentation
        .timeline_text_rows()
        .into_iter()
        .find(|row| row.key.role == RunCellRoleV1::LifecycleEvent)
        .expect("terminal fixture must include a lifecycle event");
    assert!(
        row.text.contains(&expected),
        "{run_id}: expected {expected:?}, got {:?}",
        row.text
    );
}

fn assert_terminal_json_status(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    status: RunItemStatus,
    run_id: &str,
) {
    let expected = serde_json::Value::String(status.label().to_string());
    let cells = encoded_semantic_cells(presentation);
    let terminal = cells
        .iter()
        .find(|cell| cell["payload"]["type"] == "terminal")
        .expect("terminal fixture must encode a terminal payload");
    assert_eq!(
        terminal["payload"]["value"]["status"], expected,
        "{run_id}: rich JSON terminal status"
    );
}
