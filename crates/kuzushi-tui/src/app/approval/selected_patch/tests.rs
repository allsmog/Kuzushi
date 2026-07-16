use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::workflow_attempts::{
    append_phase_attempt_completed, append_phase_attempt_disposition, PhaseAttemptCompleted,
    PhaseAttemptDispositionRecorded,
};
use kuzushi_core::{Finding, FindingStore, PatchProvenance, Severity};

struct PatchFixture {
    _temp: tempfile::TempDir,
    workspace: WorkspaceTarget,
    patch: PatchResult,
    completed: PhaseAttemptCompleted,
}

#[test]
fn restart_reconstructs_only_the_durable_selected_patch() {
    let fixture = patch_fixture(true, PatchStatus::Sound);
    let mut app = ShellApp::new(V2Config::default(), Some(&fixture.workspace));

    let effects = app.reduce_patch_apply();

    assert!(matches!(
        effects.as_slice(),
        [ShellEffect::ApplyReviewedPatch(apply)]
            if apply.selected_attempt_id == fixture.completed.attempt_id
                && apply.patch_run_id == fixture.patch.patch_run_id
    ));
    assert_eq!(
        app.engagement
            .pending_patch()
            .map(|patch| patch.patch_run_id.as_str()),
        Some(fixture.patch.patch_run_id.as_str())
    );
    assert_demo_file_unchanged(&fixture);
}

#[test]
fn selecting_fix_hydrates_review_state_without_applying() {
    let fixture = patch_fixture(false, PatchStatus::Sound);
    let mut app = ShellApp::new(V2Config::default(), Some(&fixture.workspace));
    app.refresh_phase_attempt_projection();
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Fix));
    app.set_input_mode(InputMode::Navigate);

    app.reduce_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::empty()));

    assert!(load_durable_fix_selection(fixture.workspace.root()).is_ok());
    assert_eq!(
        app.engagement
            .pending_patch()
            .map(|patch| patch.patch_run_id.as_str()),
        Some(fixture.patch.patch_run_id.as_str())
    );
    assert_demo_file_unchanged(&fixture);
    let store = FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    assert!(store
        .latest_patch_lifecycle_for_finding(&fixture.patch.fingerprint)
        .unwrap()
        .is_none());
}

#[test]
fn durable_selection_rejects_non_sound_patch_results() {
    let fixture = patch_fixture(true, PatchStatus::TestsFailed);
    let mut app = ShellApp::new(V2Config::default(), Some(&fixture.workspace));

    let effects = app.reduce_patch_apply();

    assert!(effects.is_empty());
    assert!(app.engagement.pending_patch().is_none());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("only SOUND candidates can be applied")));
    assert_demo_file_unchanged(&fixture);
}

#[test]
fn durable_selection_rejects_incomplete_detector_provenance() {
    let fixture = patch_fixture_with(true, PatchStatus::Sound, |patch| {
        patch
            .provenance
            .as_mut()
            .expect("provenance")
            .detector_input_digest = None;
    });

    let error = load_durable_fix_selection(fixture.workspace.root())
        .unwrap_err()
        .to_string();

    assert!(error.contains("detector input digest"), "{error}");
    assert!(error.contains("regenerate"), "{error}");
    assert_demo_file_unchanged(&fixture);
}

#[test]
fn incomplete_provenance_cannot_cross_the_select_action() {
    let fixture = patch_fixture_with(false, PatchStatus::Sound, |patch| {
        patch.provenance.as_mut().expect("provenance").detector_tool = None;
    });
    let mut app = ShellApp::new(V2Config::default(), Some(&fixture.workspace));
    app.refresh_phase_attempt_projection();
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Fix));
    app.set_input_mode(InputMode::Navigate);

    app.reduce_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::empty()));

    let snapshot = PhaseTargetSnapshot::capture(fixture.workspace.root());
    let ledger =
        kuzushi_core::workflow_attempts::load_phase_attempt_ledger(fixture.workspace.root())
            .unwrap();
    assert!(ledger
        .unresolved_for(WorkflowPhase::Fix, &snapshot)
        .is_some());
    assert!(ledger.selected_for(WorkflowPhase::Fix, &snapshot).is_none());
    assert!(app.log_lines().iter().any(
        |line| line.body.contains("Fix selection blocked") && line.body.contains("regenerate")
    ));
    assert_demo_file_unchanged(&fixture);
}

#[test]
fn durable_selection_rejects_a_patch_from_an_earlier_finding_generation() {
    let fixture = patch_fixture(true, PatchStatus::Sound);
    let store = FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    store
        .record_run_started("finding-run-2", fixture.workspace.root(), "completed")
        .unwrap();
    let mut finding = store
        .get_finding_by_fingerprint(&fixture.patch.fingerprint)
        .unwrap()
        .expect("finding");
    finding.scan_id = Some("finding-run-2".to_string());
    store.insert_finding("finding-run-2", &finding).unwrap();

    let error = load_durable_fix_selection(fixture.workspace.root())
        .unwrap_err()
        .to_string();

    assert!(error.contains("earlier finding generation"), "{error}");
    assert!(error.contains("regenerate"), "{error}");
    assert_demo_file_unchanged(&fixture);
}

fn assert_demo_file_unchanged(fixture: &PatchFixture) {
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.root().join("demo.txt")).unwrap(),
        "before\n"
    );
}

fn patch_fixture(selected: bool, status: PatchStatus) -> PatchFixture {
    patch_fixture_with(selected, status, |_| {})
}

fn patch_fixture_with(
    selected: bool,
    status: PatchStatus,
    mutate: impl FnOnce(&mut PatchResult),
) -> PatchFixture {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("demo.txt"), "before\n").unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let (store, finding) = persisted_finding(&workspace);
    let mut patch = persisted_patch(&workspace, &store, &finding, status);
    mutate(&mut patch);
    store.insert_patch_result(&patch).unwrap();
    let completed = persisted_fix_attempt(&workspace, &patch, selected);
    PatchFixture {
        _temp: temp,
        workspace,
        patch,
        completed,
    }
}

fn persisted_finding(workspace: &WorkspaceTarget) -> (FindingStore, Finding) {
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("finding-run", workspace.root(), "completed")
        .unwrap();
    let finding = Finding::new_tool(
        "semgrep",
        "demo.patch",
        "demo.txt",
        1,
        Some(1),
        Severity::High,
        "patch the demo",
    );
    store.insert_finding("finding-run", &finding).unwrap();
    (store, finding)
}

fn persisted_patch(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    finding: &Finding,
    status: PatchStatus,
) -> PatchResult {
    let patch = PatchResult {
        patch_run_id: "patch-candidate".to_string(),
        fingerprint: finding.fingerprint.clone(),
        repo: "fixture".to_string(),
        diff: Some(patch_diff().to_string()),
        status,
        iterations: 1,
        build_command: None,
        test_command: None,
        worktree_path: None,
        cost_usd: Some(0.0),
        provider_spend_unresolved: false,
        validator_log: Some("validated".to_string()),
        history: Vec::new(),
        provenance: Some(patch_provenance(workspace)),
        created_at: None,
        updated_at: None,
    };
    store.insert_patch_result(&patch).unwrap();
    patch
}

fn patch_provenance(workspace: &WorkspaceTarget) -> PatchProvenance {
    PatchProvenance {
        source_commit: "source-commit".to_string(),
        target: workspace.root().display().to_string(),
        originating_run_id: Some("patch-tool-run".to_string()),
        detector_tool: Some("semgrep:scan".to_string()),
        detector_run_id: Some("finding-run".to_string()),
        detector_input_digest: Some("digest".to_string()),
    }
}

fn persisted_fix_attempt(
    workspace: &WorkspaceTarget,
    patch: &PatchResult,
    selected: bool,
) -> PhaseAttemptCompleted {
    persist_patch_run(workspace, patch);
    let completed = crate::test_support::append_typed_attempt(
        workspace.root(),
        WorkflowPhase::Fix,
        "patch-tool-run",
        PhaseAttemptOutcome::Completed,
    );
    if selected {
        select_attempt(workspace, &completed);
    }
    completed
}

fn persist_patch_run(workspace: &WorkspaceTarget, patch: &PatchResult) {
    crate::test_support::record_indexed_run(
        workspace.root(),
        "patch-tool-run",
        "patch:finding",
        patch_output(patch),
    );
}

fn select_attempt(workspace: &WorkspaceTarget, completed: &PhaseAttemptCompleted) {
    let disposition = PhaseAttemptDispositionRecorded::new(
        &completed.attempt_id,
        PhaseAttemptDisposition::Selected {
            acknowledged_partial: false,
        },
    );
    append_phase_attempt_disposition(workspace.root(), disposition).unwrap();
}

fn patch_output(patch: &PatchResult) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "status": "completed",
        "summary": "patch:finding SOUND",
        "output": "validated patch",
        "artifacts": [],
        "warnings": [],
        "errors": [],
        "data": {"patchResult": patch, "explanation": "guard the sink"}
    })
}

fn patch_diff() -> &'static str {
    "--- a/demo.txt\n+++ b/demo.txt\n@@ -1 +1 @@\n-before\n+after\n"
}
