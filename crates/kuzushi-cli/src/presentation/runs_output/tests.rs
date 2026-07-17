use super::*;
use kuzushi_core::run_lifecycle::{
    RunId, RunItemEnvelopeV1, RunItemId, RunItemSource, RunItemStatus, RunItemV1,
    RunProjectionRead, RunProjectionSource, SafeText, WorkflowContinuation,
};
use kuzushi_core::runtime::RuntimeCostReport;
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[allow(dead_code)]
#[path = "../../../../kuzushi-core/tests/support/run_lifecycle_semantic_equivalence/fixture.rs"]
mod semantic_fixture;

#[test]
fn cli_plain_replay_preserves_the_shared_rich_fixture() {
    let ids = semantic_fixture::FixtureIds::fixed();
    let complete_target = tempfile::tempdir().unwrap();
    let complete = complete_fixture_read(
        complete_target.path(),
        semantic_fixture::COMPLETE_RUN_ID,
        ids,
    );
    assert_cli_fixture_equivalence("complete", &complete);

    let partial_target = tempfile::tempdir().unwrap();
    let partial = persist_fixture_records(
        partial_target.path(),
        semantic_fixture::PARTIAL_RUN_ID,
        semantic_fixture::partial_records(semantic_fixture::PARTIAL_RUN_ID, ids),
    );
    assert_cli_fixture_equivalence("partial", &partial);

    let degraded_target = tempfile::tempdir().unwrap();
    let _ = complete_fixture_read(
        degraded_target.path(),
        semantic_fixture::DEGRADED_RUN_ID,
        ids,
    );
    append_corrupt_tail(degraded_target.path(), semantic_fixture::DEGRADED_RUN_ID);
    let degraded = kuzushi_core::run_lifecycle::load_run_projection(
        degraded_target.path(),
        semantic_fixture::DEGRADED_RUN_ID,
    )
    .unwrap();
    assert!(matches!(
        &degraded.projection.health,
        kuzushi_core::run_lifecycle::ProjectionHealth::Degraded { .. }
    ));
    assert_cli_completion_quarantined(&degraded);
    assert_cli_fixture_equivalence("degraded", &degraded);
}

#[test]
fn cli_rows_quarantine_completion_when_durability_failed() {
    use kuzushi_core::run_lifecycle::{
        present_projection_with_hydration_and_health, PersistenceFailureStage, RunDurabilityHealth,
    };
    let read = terminal_read(RunItemStatus::Completed);
    let mut health = read.projection.lifecycle_health();
    health.durability = RunDurabilityHealth::Failed {
        last_durable_seq: read.projection.last_committed_seq,
        stage: PersistenceFailureStage::Flush,
        detail: SafeText::operator_visible("fixture flush failure"),
        execution_may_have_occurred: true,
    };
    let presentation = present_projection_with_hydration_and_health(
        &read.projection,
        RunProjectionSource::TypedV1,
        &read.presentation_hydration,
        health,
    );

    assert_eq!(
        read.projection.terminal.as_ref().unwrap().status,
        RunItemStatus::Completed
    );
    assert_eq!(presentation.terminal_status, Some(RunItemStatus::Partial));
    assert_quarantined_cli_rows(&presentation);
    assert_cli_keys(&presentation);
}

#[test]
fn cli_json_replay_keeps_the_projection_compatibility_shape() {
    let read = terminal_read(RunItemStatus::Completed);
    let value: serde_json::Value = serde_json::from_str(&runs_replay_json(&read).unwrap()).unwrap();

    assert_eq!(value["source"], "typed_v1");
    assert!(value.get("projection").is_some());
    assert!(value["projection"].get("terminal").is_some());
    assert!(value.get("presentation").is_none());
    assert!(value.get("presentationHydration").is_none());
}

fn complete_fixture_read(
    target: &Path,
    run_id: &str,
    ids: semantic_fixture::FixtureIds,
) -> RunProjectionRead {
    let result = semantic_fixture::write_bounded_result(target, run_id, ids.tool_item);
    persist_fixture_records(
        target,
        run_id,
        semantic_fixture::complete_records(run_id, ids, result),
    )
}

fn persist_fixture_records(
    target: &Path,
    run_id: &str,
    records: Vec<kuzushi_core::run_lifecycle::RunItemRecord>,
) -> RunProjectionRead {
    let writer = kuzushi_core::run_lifecycle::RunItemWriter::open(target, run_id, None).unwrap();
    for record in records {
        writer.emit_and_flush(record).unwrap();
    }
    writer.shutdown().unwrap();
    kuzushi_core::run_lifecycle::load_run_projection(target, run_id).unwrap()
}

fn append_corrupt_tail(target: &Path, run_id: &str) {
    let path = kuzushi_core::run_artifacts::run_artifact_path(target, run_id, "items.jsonl");
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    writeln!(file, "{{not-valid-json").unwrap();
    file.sync_all().unwrap();
}

fn assert_cli_fixture_equivalence(label: &str, read: &RunProjectionRead) {
    let presentation = kuzushi_core::run_lifecycle::present_run(read);
    let expected = presentation
        .summary_text_rows()
        .into_iter()
        .chain(presentation.timeline_text_rows())
        .map(|row| (row.key, row.text))
        .collect::<Vec<_>>();
    let actual = runs_replay_rows(&presentation)
        .into_iter()
        .filter_map(|row| row.key.map(|key| (key, row.text)))
        .collect::<Vec<_>>();
    assert_eq!(actual, expected, "{label} CLI semantic rows");
    let plain = runs_replay_plain(read);
    for row in presentation.overview_lines() {
        assert!(plain.contains(&row), "{label} CLI omitted health {row:?}");
    }
    for (_, row) in expected {
        assert!(plain.contains(&row), "{label} CLI omitted {row:?}");
    }
}

fn assert_cli_completion_quarantined(read: &RunProjectionRead) {
    assert_eq!(
        read.projection
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(RunItemStatus::Completed)
    );
    let presentation = kuzushi_core::run_lifecycle::present_run(read);
    assert_eq!(presentation.terminal_status, Some(RunItemStatus::Partial));
    assert_quarantined_cli_rows(&presentation);
    assert_cli_keys(&presentation);
    let plain = runs_replay_plain(read);
    assert!(!plain.contains("Outcome · completed"));
    assert!(!plain.contains("Receipt · completed"));
    assert!(!plain.contains("NEXT · open Report"));
}

fn assert_quarantined_cli_rows(presentation: &kuzushi_core::run_lifecycle::RunPresentationV1) {
    let rows = runs_replay_rows(presentation);
    for forbidden in [
        "Plan r1 · completed",
        "Outcome · completed",
        "Receipt · completed",
        "NEXT · open Report",
    ] {
        assert!(!rows.iter().any(|row| row.text.contains(forbidden)));
    }
    assert!(rows.iter().any(|row| row.text.contains("quarantined")));
    assert!(rows.iter().any(|row| row.text.contains("NEXT · inspect")));
}

fn assert_cli_keys(presentation: &kuzushi_core::run_lifecycle::RunPresentationV1) {
    let actual = runs_replay_rows(presentation)
        .into_iter()
        .filter_map(|row| row.key)
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, presentation.semantic_keys());
}

#[test]
fn cli_plain_replay_retains_every_canonical_key_until_string_rendering() {
    for status in terminal_statuses() {
        let read = terminal_read(status);
        let presentation = kuzushi_core::run_lifecycle::present_run(&read);
        let expected = presentation.semantic_keys();
        let actual_rows = runs_replay_rows(&presentation);
        let actual = actual_rows
            .iter()
            .filter_map(|row| row.key.clone())
            .collect::<BTreeSet<_>>();
        let expected_rows = presentation
            .summary_text_rows()
            .into_iter()
            .chain(presentation.timeline_text_rows())
            .map(|row| (row.key, row.text))
            .collect::<Vec<_>>();
        let keyed_rows = actual_rows
            .into_iter()
            .filter_map(|row| row.key.map(|key| (key, row.text)))
            .collect::<Vec<_>>();

        assert_eq!(actual, expected, "{} replay key set", status.label());
        assert_eq!(
            keyed_rows,
            expected_rows,
            "{} replay semantic rows",
            status.label()
        );
        let output = runs_replay_plain(&read);
        assert!(
            output.contains(status.label()),
            "{} terminal status was not rendered",
            status.label()
        );
        for health_line in presentation.overview_lines().into_iter().skip(1) {
            assert!(
                output.contains(&health_line),
                "{} replay omitted health row {health_line:?}",
                status.label()
            );
        }
    }
}

fn terminal_statuses() -> [RunItemStatus; 6] {
    [
        RunItemStatus::Completed,
        RunItemStatus::Partial,
        RunItemStatus::Failed,
        RunItemStatus::Canceled,
        RunItemStatus::Interrupted,
        RunItemStatus::Skipped,
    ]
}

fn terminal_read(status: RunItemStatus) -> RunProjectionRead {
    let run_id = RunId::parse(&format!("cli-replay-{}", status.label())).unwrap();
    let terminal = RunItemEnvelopeV1::new(
        1,
        run_id,
        RunItemId::new(),
        RunItemSource::Workflow,
        RunItemV1::TerminalOutcome {
            status,
            summary: SafeText::operator_visible(format!("{} fixture", status.label())),
            cost: RuntimeCostReport::INCOMPLETE_ZERO,
            continuation: WorkflowContinuation::NoFurtherAction {
                reason: SafeText::operator_visible("status-matrix fixture"),
            },
        },
        None,
    )
    .unwrap();
    RunProjectionRead {
        projection: kuzushi_core::run_lifecycle::reduce_run_items([terminal]),
        source: RunProjectionSource::TypedV1,
        presentation_hydration: Default::default(),
    }
}
