//! Cross-surface characterization fixture for the typed run lifecycle.

#[path = "run_lifecycle_semantic_equivalence/acceptance_matrix.rs"]
mod acceptance_matrix;
#[path = "run_lifecycle_semantic_equivalence/contract.rs"]
mod contract;
#[path = "../../../../kuzushi-core/tests/support/run_lifecycle_semantic_equivalence/fixture.rs"]
mod fixture;

use self::contract::{assert_complete_contract, assert_partial_contract};
use self::fixture::{
    complete_records, partial_records, write_bounded_result, FixtureIds, COMPLETE_RUN_ID,
    DEGRADED_RUN_ID, LEGACY_RUN_ID, PARTIAL_RUN_ID,
};
use crate::app::{ViewHydrationKey, ViewHydrationResult, ViewHydrationValue};
use crate::ui_view_models::{
    activity_view_model, plain_run_projection_model, replay_model, ActivityViewModel,
};
use crate::{ActivitySession, ShellApp};
use kuzushi_core::run_lifecycle::{
    ProjectionHealth, RunCellKey, RunItemRead, RunItemRecord, RunProjection, RunProjectionRead,
    RunProjectionSource,
};
use kuzushi_core::workspace::WorkspaceTarget;
use kuzushi_core::V2Config;
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[derive(Debug)]
struct PersistedFixture {
    read: RunProjectionRead,
    item_read: Option<RunItemRead>,
}

#[derive(Debug)]
struct SurfaceSemantics {
    expected_rows: Vec<(RunCellKey, String)>,
    live_run_focus_rows: Vec<(RunCellKey, String)>,
    replay_rows: Vec<(RunCellKey, String)>,
    plain_rows: Vec<(RunCellKey, String)>,
    rich_json: BTreeSet<String>,
}

#[test]
fn deterministic_fixture_covers_the_typed_lifecycle_contract() {
    let ids = FixtureIds::fixed();
    let target = tempfile::tempdir().unwrap();
    let result_reference = write_bounded_result(target.path(), COMPLETE_RUN_ID, ids.tool_item);
    let first = complete_records(COMPLETE_RUN_ID, ids, result_reference.clone());
    let second = complete_records(COMPLETE_RUN_ID, ids, result_reference);
    assert_eq!(
        first, second,
        "fixture records must not mint semantic identity"
    );

    let fixture = persist_records(target.path(), COMPLETE_RUN_ID, first);
    let presentation = kuzushi_core::run_lifecycle::present_run(&fixture.read);
    assert_complete_contract(&presentation, ids);

    let partial_target = tempfile::tempdir().unwrap();
    let partial = persist_records(
        partial_target.path(),
        PARTIAL_RUN_ID,
        partial_records(PARTIAL_RUN_ID, ids),
    );
    assert_partial_contract(&kuzushi_core::run_lifecycle::present_run(&partial.read));
}

#[test]
fn complete_and_partial_runs_keep_semantic_keys_across_surfaces() {
    let ids = FixtureIds::fixed();
    let complete_target = tempfile::tempdir().unwrap();
    let complete = persist_complete_fixture(complete_target.path(), COMPLETE_RUN_ID, ids);
    assert_surface_equivalence(complete_target.path(), COMPLETE_RUN_ID, complete);

    let partial_target = tempfile::tempdir().unwrap();
    let partial = persist_records(
        partial_target.path(),
        PARTIAL_RUN_ID,
        partial_records(PARTIAL_RUN_ID, ids),
    );
    assert_surface_equivalence(partial_target.path(), PARTIAL_RUN_ID, partial);
}

#[test]
fn degraded_and_legacy_runs_keep_available_semantic_keys_across_surfaces() {
    let ids = FixtureIds::fixed();
    let degraded_target = tempfile::tempdir().unwrap();
    let mut degraded = persist_complete_fixture(degraded_target.path(), DEGRADED_RUN_ID, ids);
    append_corrupt_tail(degraded_target.path(), DEGRADED_RUN_ID);
    degraded.read =
        kuzushi_core::run_lifecycle::load_run_projection(degraded_target.path(), DEGRADED_RUN_ID)
            .unwrap();
    degraded.item_read =
        kuzushi_core::run_lifecycle::read_run_items(degraded_target.path(), DEGRADED_RUN_ID)
            .unwrap();
    assert!(matches!(
        degraded.read.projection.health,
        ProjectionHealth::Degraded { .. }
    ));
    assert_degraded_completion_is_quarantined(&degraded.read);
    assert_surface_equivalence(degraded_target.path(), DEGRADED_RUN_ID, degraded);

    let legacy_target = tempfile::tempdir().unwrap();
    write_legacy_event_artifact(legacy_target.path(), LEGACY_RUN_ID);
    let legacy = legacy_fixture(legacy_target.path());
    assert_eq!(legacy.read.source, RunProjectionSource::Legacy);
    assert_eq!(legacy.read.projection.health, ProjectionHealth::LegacyLossy);
    assert_surface_equivalence(legacy_target.path(), LEGACY_RUN_ID, legacy);
}

fn assert_degraded_completion_is_quarantined(read: &RunProjectionRead) {
    use kuzushi_core::run_lifecycle::{RunItemStatus, RunPresentationPayloadV1};
    assert_eq!(
        read.projection
            .terminal
            .as_ref()
            .map(|terminal| terminal.status),
        Some(RunItemStatus::Completed)
    );
    let presentation = kuzushi_core::run_lifecycle::present_run(read);
    assert_eq!(presentation.terminal_status, Some(RunItemStatus::Partial));
    let rows = presentation.summary_text_rows();
    for forbidden in [
        "Plan r1 · completed",
        "Outcome · completed",
        "Receipt · completed",
        "NEXT · open Report",
    ] {
        assert!(!rows.iter().any(|row| row.text.contains(forbidden)));
    }
    assert!(rows.iter().any(|row| row.text.contains("quarantined")));
    assert!(presentation
        .summary
        .iter()
        .any(|section| section.cells.iter().any(|cell| {
            matches!(
                &cell.payload,
                RunPresentationPayloadV1::PhaseReceipt(receipt)
                    if receipt.status == RunItemStatus::Partial
                        && receipt.offered_actions.iter().all(|action| matches!(
                            action,
                            kuzushi_core::run_lifecycle::WorkflowContinuation::InspectRun { .. }
                        ))
            )
        })));
}

fn legacy_fixture(target: &Path) -> PersistedFixture {
    PersistedFixture {
        read: kuzushi_core::run_lifecycle::load_run_projection(target, LEGACY_RUN_ID).unwrap(),
        item_read: None,
    }
}

fn assert_surface_equivalence(target: &Path, run_id: &str, fixture: PersistedFixture) {
    let surfaces = collect_surface_semantics(target, run_id, fixture);
    assert_eq!(
        surfaces.live_run_focus_rows, surfaces.expected_rows,
        "{run_id}: Run Focus"
    );
    assert_eq!(
        surfaces.replay_rows, surfaces.expected_rows,
        "{run_id}: replay"
    );
    assert_eq!(
        surfaces.plain_rows, surfaces.expected_rows,
        "{run_id}: plain"
    );
    let expected_keys = surfaces
        .expected_rows
        .iter()
        .map(|(key, _)| key.clone())
        .collect();
    assert_eq!(
        surfaces.rich_json,
        encoded_keys(&expected_keys),
        "{run_id}: rich JSON"
    );
}

fn collect_surface_semantics(
    target: &Path,
    run_id: &str,
    fixture: PersistedFixture,
) -> SurfaceSemantics {
    let session = live_session(run_id, &fixture);
    assert_eq!(session.run_projection, fixture.read.projection);
    assert_eq!(
        session.effective_run_lifecycle_health(),
        fixture.read.projection.lifecycle_health(),
        "{run_id}: live and replay lifecycle health"
    );
    let workspace = WorkspaceTarget::new(target).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_activity(Some(session));
    let canonical_target = app.target().expect("fixture target").to_path_buf();
    seed_replay_projection(&app, &canonical_target, run_id, fixture.read.clone());
    surface_semantics(&app, run_id, &fixture.read)
}

fn surface_semantics(app: &ShellApp, run_id: &str, read: &RunProjectionRead) -> SurfaceSemantics {
    let expected_presentation = kuzushi_core::run_lifecycle::present_run(read);
    let expected_rows = semantic_text_rows(&expected_presentation);
    let ActivityViewModel::Active(run_focus) = activity_view_model(app) else {
        panic!("fixture Run Focus must be active");
    };
    let feed_rows = run_focus.feed_pane_rows(8_192);
    let health_lines = expected_presentation
        .overview_lines()
        .into_iter()
        .skip(1)
        .collect::<Vec<_>>();
    if read.source == RunProjectionSource::TypedV1 {
        for health_line in &health_lines {
            assert!(
                feed_rows.iter().any(|row| {
                    row.text.strip_prefix(' ').unwrap_or(&row.text) == health_line.as_str()
                }),
                "{run_id}: Run Focus omitted health row {health_line:?}"
            );
        }
    }
    let live_run_focus_rows = feed_rows
        .into_iter()
        .filter_map(|row| row.key.map(|key| (key, semantic_payload_text(&row.text))))
        .collect();
    let plain_model_rows = plain_run_projection_model(app)
        .into_iter()
        .flat_map(|model| model.rows)
        .collect::<Vec<_>>();
    let plain_rows = plain_model_rows
        .iter()
        .filter_map(|row| {
            row.key
                .clone()
                .map(|key| (key, semantic_payload_text(&row.text)))
        })
        .collect();
    let replay_presentation = replay_model(app, run_id)
        .presentation
        .expect("hydrated replay presentation");
    assert_eq!(
        replay_presentation.overview_lines(),
        expected_presentation.overview_lines(),
        "{run_id}: replay lifecycle health"
    );
    if read.source == RunProjectionSource::TypedV1 {
        for health_line in health_lines {
            assert!(
                plain_model_rows
                    .iter()
                    .any(|row| row.text.as_str() == health_line.as_str()),
                "{run_id}: plain output omitted health row {health_line:?}"
            );
        }
    }
    SurfaceSemantics {
        expected_rows,
        live_run_focus_rows,
        replay_rows: semantic_text_rows(&replay_presentation),
        plain_rows,
        rich_json: json_semantic_keys(&replay_presentation),
    }
}

fn semantic_text_rows(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) -> Vec<(RunCellKey, String)> {
    presentation
        .summary_text_rows()
        .into_iter()
        .chain(presentation.timeline_text_rows())
        .map(|row| (row.key, semantic_payload_text(&row.text)))
        .collect()
}

fn semantic_payload_text(text: &str) -> String {
    text.trim_start().to_string()
}

fn live_session(run_id: &str, fixture: &PersistedFixture) -> ActivitySession {
    let mut session = ActivitySession::new(run_id);
    session.run_presentation_hydration = fixture.read.presentation_hydration.clone();
    let Some(item_read) = fixture.item_read.as_ref() else {
        session.run_projection = fixture.read.projection.clone();
        return session;
    };
    for item in &item_read.items {
        session.apply_run_item(item.clone()).unwrap();
    }
    session.run_projection.health = item_read.health.clone();
    session
}

fn seed_replay_projection(app: &ShellApp, target: &Path, run_id: &str, read: RunProjectionRead) {
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: target.to_path_buf(),
            key: ViewHydrationKey::RunProjection {
                run_id: run_id.to_string(),
            },
            value: ViewHydrationValue::RunProjection(Ok(read)),
        });
}

fn persist_records(target: &Path, run_id: &str, records: Vec<RunItemRecord>) -> PersistedFixture {
    let writer = kuzushi_core::run_lifecycle::RunItemWriter::open(target, run_id, None).unwrap();
    let mut live = RunProjection::default();
    for record in records {
        let envelope = writer.emit_and_flush(record).unwrap();
        live.apply_committed(envelope).unwrap();
        let replay = kuzushi_core::run_lifecycle::load_run_projection(target, run_id).unwrap();
        assert_eq!(
            live, replay.projection,
            "{run_id}: live projection diverged from durable replay at committed prefix"
        );
    }
    writer.shutdown().unwrap();
    PersistedFixture {
        read: kuzushi_core::run_lifecycle::load_run_projection(target, run_id).unwrap(),
        item_read: kuzushi_core::run_lifecycle::read_run_items(target, run_id).unwrap(),
    }
}

fn persist_complete_fixture(target: &Path, run_id: &str, ids: FixtureIds) -> PersistedFixture {
    let result_reference = write_bounded_result(target, run_id, ids.tool_item);
    persist_records(
        target,
        run_id,
        complete_records(run_id, ids, result_reference),
    )
}

fn append_corrupt_tail(target: &Path, run_id: &str) {
    let path = kuzushi_core::run_artifacts::run_artifact_path(target, run_id, "items.jsonl");
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    writeln!(file, "{{not-valid-json").unwrap();
    file.sync_all().unwrap();
}

fn write_legacy_event_artifact(target: &Path, run_id: &str) {
    let directory = kuzushi_core::run_artifacts::run_dir(target, run_id);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("events.jsonl"),
        "{\"atMs\":1,\"kind\":\"run_started\",\"detail\":\"legacy string event\"}\n",
    )
    .unwrap();
}

fn json_semantic_keys(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) -> BTreeSet<String> {
    let value = serde_json::to_value(presentation).unwrap();
    let summary_cells = value["summary"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|section| section["cells"].as_array().into_iter().flatten());
    let timeline_cells = value["timeline"].as_array().into_iter().flatten();
    summary_cells
        .chain(timeline_cells)
        .map(|cell| serde_json::to_string(&cell["key"]).unwrap())
        .collect()
}

fn encoded_keys(keys: &BTreeSet<RunCellKey>) -> BTreeSet<String> {
    keys.iter()
        .map(|key| serde_json::to_string(&serde_json::to_value(key).unwrap()).unwrap())
        .collect()
}
