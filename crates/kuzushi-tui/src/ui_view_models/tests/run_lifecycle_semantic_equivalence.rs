//! Cross-surface characterization fixture for the typed run lifecycle.

#[path = "run_lifecycle_semantic_equivalence/acceptance_matrix.rs"]
mod acceptance_matrix;
#[path = "run_lifecycle_semantic_equivalence/contract.rs"]
mod contract;
#[path = "../../../../kuzushi-core/tests/support/run_lifecycle_semantic_equivalence/fixture.rs"]
#[allow(dead_code)]
mod fixture;

use self::contract::{assert_complete_contract, assert_partial_contract};
use self::fixture::{
    complete_records, partial_records, write_bounded_result, FixtureIds, COMPLETE_RUN_ID,
    DEGRADED_RUN_ID, PARTIAL_RUN_ID,
};
use crate::app::{ViewHydrationKey, ViewHydrationResult, ViewHydrationValue};
use crate::ui_view_models::{
    activity_view_model, plain_run_projection_model, replay_model, ActivityViewModel,
};
use crate::{ActivitySession, ShellApp};
use kuzushi_core::run_lifecycle::{
    ProjectionHealth, RunCellKey, RunItemRead, RunItemRecord, RunItemStatus,
    RunPresentationPayloadV1, RunProjection, RunProjectionRead, RunProjectionSource,
};
use kuzushi_core::runtime::RuntimeCostReport;
use kuzushi_core::workspace::WorkspaceTarget;
use kuzushi_core::V2Config;
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

#[derive(Debug)]
struct PersistedFixture {
    read: RunProjectionRead,
    item_read: RunItemRead,
}

#[derive(Debug)]
struct SurfaceSemantics {
    expected_rows: Vec<(RunCellKey, String)>,
    run_focus_expected_rows: Vec<(RunCellKey, String)>,
    live_run_focus_rows: Vec<(RunCellKey, String)>,
    replay_rows: Vec<(RunCellKey, String)>,
    plain_rows: Vec<(RunCellKey, String)>,
    expected_rich_json: Vec<serde_json::Value>,
    rich_json: Vec<serde_json::Value>,
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
    assert_complete_contract(
        &kuzushi_core::run_lifecycle::present_run(&fixture.read),
        ids,
    );

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
fn degraded_runs_quarantine_completion_across_surfaces() {
    let ids = FixtureIds::fixed();
    let target = tempfile::tempdir().unwrap();
    let mut degraded = persist_complete_fixture(target.path(), DEGRADED_RUN_ID, ids);
    append_corrupt_tail(target.path(), DEGRADED_RUN_ID);
    degraded.read =
        kuzushi_core::run_lifecycle::load_run_projection(target.path(), DEGRADED_RUN_ID).unwrap();
    degraded.item_read =
        kuzushi_core::run_lifecycle::read_run_items(target.path(), DEGRADED_RUN_ID)
            .unwrap()
            .unwrap();

    assert!(matches!(
        degraded.read.projection.health,
        ProjectionHealth::Degraded { .. }
    ));
    assert_degraded_completion_is_quarantined(&degraded.read);
    assert_surface_equivalence(target.path(), DEGRADED_RUN_ID, degraded);
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
    assert!(presentation.summary.iter().any(|section| {
        section.cells.iter().any(|cell| {
            matches!(
                &cell.payload,
                RunPresentationPayloadV1::PhaseReceipt(receipt)
                    if receipt.status == RunItemStatus::Partial
                        && receipt.offered_actions.iter().all(|action| matches!(
                            action,
                            kuzushi_core::run_lifecycle::WorkflowContinuation::InspectRun { .. }
                        ))
            )
        })
    }));
}

fn assert_surface_equivalence(target: &Path, run_id: &str, fixture: PersistedFixture) {
    let surfaces = collect_surface_semantics(target, run_id, fixture);
    assert_eq!(
        surfaces.live_run_focus_rows, surfaces.run_focus_expected_rows,
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
    assert_eq!(
        surfaces.rich_json, surfaces.expected_rich_json,
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
    // Run Focus intentionally keeps detail cells behind its explicit verbose
    // disclosure. Exercise that expanded projection when comparing every
    // durable semantic key with replay and headless output.
    app.activity_route_mut().verbose_subsystems = true;
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
    let header = run_focus.header();
    let heartbeat = run_focus.heartbeat(Instant::now());
    assert_run_focus_terminal_chrome(
        &header.detailed_title,
        &heartbeat.text,
        &expected_presentation,
        run_id,
    );
    let feed_rows = run_focus.feed_pane_rows(8_192);
    let health_lines = expected_presentation
        .overview_lines()
        .into_iter()
        .skip(1)
        .collect::<Vec<_>>();
    assert_eq!(read.source, RunProjectionSource::TypedV1);
    for health_line in &health_lines {
        assert!(
            feed_rows.iter().any(|row| {
                row.text.strip_prefix(' ').unwrap_or(&row.text) == health_line.as_str()
            }),
            "{run_id}: Run Focus omitted health row {health_line:?}"
        );
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
    for health_line in health_lines {
        assert!(
            plain_model_rows
                .iter()
                .any(|row| row.text.as_str() == health_line.as_str()),
            "{run_id}: plain output omitted health row {health_line:?}"
        );
    }
    SurfaceSemantics {
        expected_rows,
        run_focus_expected_rows: run_focus_expected_rows(&expected_presentation),
        live_run_focus_rows,
        replay_rows: semantic_text_rows(&replay_presentation),
        plain_rows,
        expected_rich_json: encoded_semantic_cells(&expected_presentation),
        rich_json: json_semantic_cells(&replay_presentation),
    }
}

fn run_focus_expected_rows(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) -> Vec<(RunCellKey, String)> {
    let header_owned_cost_rows = run_focus_header_owned_cost_rows(presentation);
    presentation
        .summary_text_rows()
        .into_iter()
        .chain(presentation.timeline_text_rows())
        .filter(|row| !header_owned_cost_rows.contains(&(row.key.clone(), row.text.clone())))
        .map(|row| (row.key, semantic_payload_text(&row.text)))
        .collect()
}

fn run_focus_header_owned_cost_rows(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) -> BTreeSet<(RunCellKey, String)> {
    presentation
        .summary
        .iter()
        .flat_map(|section| section.cells.iter())
        .filter_map(|cell| {
            let RunPresentationPayloadV1::Terminal(terminal) = &cell.payload else {
                return None;
            };
            Some((
                cell.key.clone(),
                format!(
                    "Cost · {}",
                    kuzushi_core::run_lifecycle::cost_label(terminal.cost)
                ),
            ))
        })
        .collect()
}

const TERMINAL_EXPECTATIONS: [(RunItemStatus, &str, &str, &str); 7] = [
    (
        RunItemStatus::Completed,
        "✓ run completed",
        "✓ COMPLETE",
        "✓",
    ),
    (RunItemStatus::Partial, "⚠ run partial", "⚠ PARTIAL", "⚠"),
    (RunItemStatus::Blocked, "▣ run blocked", "▣ BLOCKED", "▣"),
    (RunItemStatus::Failed, "✗ run failed", "✗ FAILED", "✗"),
    (RunItemStatus::Canceled, "× run canceled", "× CANCELED", "×"),
    (
        RunItemStatus::Interrupted,
        "× run interrupted",
        "✗ FAILED",
        "✗",
    ),
    (RunItemStatus::Skipped, "⊘ run skipped", "⊘ SKIPPED", "⊘"),
];

fn assert_run_focus_terminal_chrome(
    header: &str,
    heartbeat: &str,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    run_id: &str,
) {
    let Some(status) = presentation.terminal_status else {
        return;
    };
    let (header_status, heartbeat_status, _) = terminal_expectation(status);
    assert!(
        header.contains(header_status),
        "{run_id}: header was {header:?}"
    );
    assert!(
        heartbeat.contains(heartbeat_status),
        "{run_id}: heartbeat was {heartbeat:?}"
    );
    assert_non_complete_heartbeat(status, heartbeat, run_id);
    assert_header_cost_matches_terminal(header, presentation, run_id);
}

fn terminal_expectation(status: RunItemStatus) -> (&'static str, &'static str, &'static str) {
    TERMINAL_EXPECTATIONS
        .iter()
        .find(|(candidate, _, _, _)| *candidate == status)
        .map(|(_, header, heartbeat, glyph)| (*header, *heartbeat, *glyph))
        .expect("terminal status must have a rendering expectation")
}

fn assert_non_complete_heartbeat(status: RunItemStatus, heartbeat: &str, run_id: &str) {
    if status != RunItemStatus::Completed {
        assert!(
            !heartbeat.contains("✓ COMPLETE"),
            "{run_id}: non-completed run rendered complete: {heartbeat:?}"
        );
    }
}

fn assert_header_cost_matches_terminal(
    header: &str,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    run_id: &str,
) {
    let Some(cost) = terminal_presentation_cost(presentation) else {
        return;
    };
    let expected = run_focus_header_cost_label(cost);
    assert!(
        header.split("  ·  ").any(|segment| segment == expected),
        "{run_id}: header cost did not match terminal cost: {header:?}"
    );
}

fn terminal_presentation_cost(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) -> Option<RuntimeCostReport> {
    presentation
        .summary
        .iter()
        .flat_map(|section| section.cells.iter())
        .find_map(|cell| match &cell.payload {
            RunPresentationPayloadV1::Terminal(terminal) => Some(terminal.cost),
            _ => None,
        })
}

fn run_focus_header_cost_label(cost: RuntimeCostReport) -> String {
    if cost.is_unavailable() {
        return "cost not recorded".to_string();
    }
    if cost.is_complete() {
        return format!("cost ${:.4}", cost.observed_usd());
    }
    format!("cost >=${:.4} (incomplete)", cost.observed_usd())
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
    for item in &fixture.item_read.items {
        session.apply_run_item(item.clone()).unwrap();
    }
    session.run_projection.health = fixture.item_read.health.clone();
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
        item_read: kuzushi_core::run_lifecycle::read_run_items(target, run_id)
            .unwrap()
            .unwrap(),
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

fn json_semantic_cells(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) -> Vec<serde_json::Value> {
    let value = serde_json::to_value(presentation).unwrap();
    let summary_cells = value["summary"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|section| section["cells"].as_array().into_iter().flatten());
    let timeline_cells = value["timeline"].as_array().into_iter().flatten();
    summary_cells.chain(timeline_cells).cloned().collect()
}

fn encoded_semantic_cells(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) -> Vec<serde_json::Value> {
    presentation
        .summary
        .iter()
        .flat_map(|section| section.cells.iter())
        .chain(presentation.timeline.iter())
        .map(|cell| serde_json::to_value(cell).unwrap())
        .collect()
}
