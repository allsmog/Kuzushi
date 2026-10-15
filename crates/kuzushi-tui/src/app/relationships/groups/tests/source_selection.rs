use super::*;
use kuzushi_core::run_artifacts::*;
use kuzushi_core::workflow_attempts::{PhaseAttemptOutcome, PhaseTargetSnapshot};
use std::path::Path;

fn prepare(target: &Path) -> (kuzushi_core::WorkspaceTarget, i64) {
    std::fs::create_dir_all(target).unwrap();
    std::fs::write(
        target.join("hello.txt"),
        "Owned greeting. Never executed.\n",
    )
    .unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(target).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = Finding::new_tool(
        "owned-fixture",
        "same-greeting",
        "hello.txt",
        1,
        None,
        Severity::Info,
        "Labeled repeated greeting observation",
    );
    let mut latest_id = 0;
    for run in [
        "first-observation",
        "middle-observation",
        "latest-observation",
    ] {
        store.record_run_started(run, target, "completed").unwrap();
        latest_id = store.insert_finding(run, &finding).unwrap();
    }
    crate::test_support::record_imported_test_map(target, "map-parent");
    select(target, WorkflowPhase::Map, "map-parent");
    crate::test_support::record_indexed_run(
        target,
        "scan-parent",
        "sast:scan",
        serde_json::json!({"ok":true,"data":{"phaseStages":[receipt(target)]}}),
    );
    select(target, WorkflowPhase::Scan, "scan-parent");
    (workspace, latest_id)
}

fn select(target: &Path, phase: WorkflowPhase, run: &str) {
    let completed = crate::test_support::append_typed_attempt(
        target,
        phase,
        run,
        PhaseAttemptOutcome::Completed,
    );
    crate::test_support::select_typed_attempt(target, &completed);
}

fn receipt(target: &Path) -> PhaseStageReceipt {
    PhaseStageReceipt {
        phase: WorkflowPhase::Scan,
        outcome: PhaseStageOutcome::Completed,
        run_refs: vec!["middle-observation".into()],
        scan: Some(ScanStageData {
            scope: ScanStageScope {
                target: target.display().to_string(),
                paths: Vec::new(),
            },
            plan: ScanStagePlan {
                selection: "manual".into(),
                engines: vec!["owned-fixture".into()],
            },
            engines: Vec::new(),
            finding_delta: ScanFindingDelta {
                added: 1,
                updated: 0,
            },
            severity_counts: Vec::new(),
            artifact_delta: Vec::new(),
            duration_ms: 1,
            cost: None,
            target_snapshot: PhaseTargetSnapshot::capture(target),
        }),
    }
}

#[test]
fn selected_scan_members_disclose_history_and_the_current_observation_run() {
    let root = tempfile::tempdir().unwrap();
    let (workspace, latest_id) = prepare(root.path());
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.refresh_phase_attempt_projection();
    app.open_finding_groups();
    hydrate(&mut app);
    app.open_group_selection();
    hydrate(&mut app);
    let ViewDataState::Ready(Ok(page)) = app.finding_groups_page() else {
        panic!("loaded")
    };
    assert_eq!(
        page.selected_run_ids,
        vec!["middle-observation", "scan-parent"]
    );
    assert_eq!(page.members[0].finding_id, latest_id);
    assert_eq!(page.members[0].matching_run_ids, vec!["middle-observation"]);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 36)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, &app))
        .unwrap();
    let text = format!("{:?}", terminal.backend().buffer());
    assert!(
        text.contains("observed in 1 selected run · latest observations"),
        "{text}"
    );
    assert!(
        text.contains("Observation run: latest-observation"),
        "{text}"
    );
    assert!(
        text.contains("Observed in selected runs: middle-observation"),
        "{text}"
    );
    assert!(text.contains("Compare source revisions"), "{text}");
}

#[test]
fn prepare_native_group_run_fixture() {
    let Some(root) = std::env::var_os("KUZUSHI_GROUP_RUN_FIXTURE_OUT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let (workspace, latest_id) = prepare(&root);
    let receipt = serde_json::json!({
        "latestFindingId": latest_id,
        "findingsAreSynthetic": true,
        "providerRequests": 0,
        "sourceExecuted": false
    });
    std::fs::write(
        workspace.root().join(".kuzushi/group-run-fixture.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
}
