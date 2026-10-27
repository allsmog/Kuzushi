use super::requests::active_view_hydration_keys;
use super::runtime::MAX_VIEW_HYDRATION_WORKERS;
use super::*;
use crate::renderer::render_app;
use crate::ui_view_models::{jobs_registry_model, JobHistoryState};
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

fn run_entry_with_git(sha: &str, dirty: bool) -> kuzushi_core::RunSummaryEntry {
    let mut summary = kuzushi_core::RunSummary::default();
    summary.run_id = "run-history".to_string();
    summary.target_git = Some(RunTargetGitMetadata {
        sha: sha.to_string(),
        branch: Some("main".to_string()),
        dirty,
    });
    kuzushi_core::RunSummaryEntry {
        run_id: summary.run_id.clone(),
        path: PathBuf::from("run.json"),
        state: kuzushi_core::RunSummaryEntryState::Ready(summary),
    }
}

#[test]
fn returning_workspace_drift_requires_observed_revision_change() {
    let clean_current = RunTargetGitMetadata {
        sha: "bbbbbbbbbbbb".to_string(),
        branch: Some("main".to_string()),
        dirty: false,
    };
    let revision_drift =
        returning_workspace_drift(&clean_current, &[run_entry_with_git("aaaaaaaaaaaa", false)])
            .expect("revision drift");
    assert_eq!(
        revision_drift.0,
        kuzushi_core::incremental_index::WorkspaceChange::GitHeadChanged
    );
    assert!(revision_drift.1.contains("aaaaaaaa → bbbbbbbb"));

    let dirty_current = RunTargetGitMetadata {
        dirty: true,
        ..clean_current.clone()
    };
    for prior_dirty in [false, true] {
        let history = [run_entry_with_git("bbbbbbbbbbbb", prior_dirty)];
        assert!(returning_workspace_drift(&dirty_current, &history).is_none());
        assert!(returning_source_unverified(&dirty_current, &history));
    }
    assert!(returning_source_unverified(
        &clean_current,
        &[run_entry_with_git("bbbbbbbbbbbb", true)]
    ));
}

#[test]
fn returning_workspace_drift_stays_clear_for_the_same_clean_revision() {
    let current = RunTargetGitMetadata {
        sha: "aaaaaaaaaaaa".to_string(),
        branch: Some("main".to_string()),
        dirty: false,
    };
    assert!(
        returning_workspace_drift(&current, &[run_entry_with_git("aaaaaaaaaaaa", false)]).is_none()
    );
    assert!(!returning_source_unverified(
        &current,
        &[run_entry_with_git("aaaaaaaaaaaa", false)]
    ));
    assert!(!returning_source_unverified(&current, &[]));
}

#[derive(Debug, Default)]
struct CountingReader {
    reads: AtomicUsize,
}

#[derive(Debug, Default)]
struct FailingRunHistoryReader;

impl ViewArtifactReader for FailingRunHistoryReader {
    fn read(&self, _target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        if key == &ViewHydrationKey::RunSummaryEntries {
            return ViewHydrationValue::RunSummaryEntries(
                RunSummaryEntriesHydration::without_recoveries(RunSummaryEntriesState::Failed(
                    "fixture run-history failure".to_string(),
                )),
            );
        }
        missing_value(key)
    }
}

impl ViewArtifactReader for CountingReader {
    fn read(&self, _target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        self.reads.fetch_add(1, Ordering::SeqCst);
        missing_value(key)
    }
}

pub(super) fn missing_value(key: &ViewHydrationKey) -> ViewHydrationValue {
    match key {
        ViewHydrationKey::CampaignHistory(_) => ViewHydrationValue::CampaignHistory(Arc::new(
            super::super::campaign::history_refresh::CampaignHistoryReadSnapshot {
                history: Default::default(),
                phase: None,
                trend_history: Vec::new(),
            },
        )),
        ViewHydrationKey::ScanStudyProgress { .. } => {
            ViewHydrationValue::ScanStudyProgress(Err("missing fixture study".into()))
        }
        ViewHydrationKey::InvestigationAllowance { .. } => {
            ViewHydrationValue::InvestigationAllowance(Ok(None))
        }
        ViewHydrationKey::FindingGroups(_) => {
            ViewHydrationValue::FindingGroups(Err("missing fixture groups".into()))
        }
        ViewHydrationKey::FindingRelationships { .. } => {
            ViewHydrationValue::FindingRelationships(Err("missing fixture relationships".into()))
        }
        ViewHydrationKey::FindingLessons { .. } => {
            ViewHydrationValue::FindingLessons(Err("missing fixture lessons".into()))
        }
        ViewHydrationKey::ContextMatrixReport { .. } => {
            ViewHydrationValue::ContextMatrixReport(Err("missing fixture matrix".into()))
        }
        ViewHydrationKey::FindingsProjection(_) => {
            ViewHydrationValue::FindingsProjection(Err("missing fixture ledger".into()))
        }
        ViewHydrationKey::StudyUsageCatalogue => {
            ViewHydrationValue::StudyUsageCatalogue(Ok(Default::default()))
        }
        ViewHydrationKey::StudyHistory => ViewHydrationValue::StudyHistory(Ok(Default::default())),
        ViewHydrationKey::StudyUsageRun { .. } => {
            ViewHydrationValue::StudyUsageRun(Err("missing fixture usage".into()))
        }
        ViewHydrationKey::WorkspaceReportReview { .. } => {
            ViewHydrationValue::WorkspaceReportReview(Ok(Default::default()))
        }
        ViewHydrationKey::InvestigationReport { .. }
        | ViewHydrationKey::InvestigationStudyReport { .. } => {
            ViewHydrationValue::InvestigationReport(Ok(None))
        }
        ViewHydrationKey::FileCompletionValues => {
            ViewHydrationValue::FileCompletionValues(FileCompletionIndex::default())
        }
        ViewHydrationKey::FindingCompletionValues => {
            ViewHydrationValue::FindingCompletionValues(Vec::new())
        }
        ViewHydrationKey::RunIdCompletionValues => {
            ViewHydrationValue::RunIdCompletionValues(Vec::new())
        }
        ViewHydrationKey::LatestRunPointer => {
            ViewHydrationValue::LatestRunPointer(LatestRunPointerState::Missing)
        }
        ViewHydrationKey::RunSummaryEntries => {
            ViewHydrationValue::RunSummaryEntries(RunSummaryEntriesHydration::without_recoveries(
                RunSummaryEntriesState::Ready(Vec::new()),
            ))
        }
        ViewHydrationKey::RunArtifactText { run_id, leaf } => {
            ViewHydrationValue::RunArtifactText(kuzushi_core::RunArtifactRead::Missing {
                path: PathBuf::from(run_id).join(leaf),
            })
        }
        ViewHydrationKey::RunProjection { .. } => {
            ViewHydrationValue::RunProjection(Err("missing fixture projection".to_string()))
        }
        ViewHydrationKey::RunResultDocument { .. } => {
            ViewHydrationValue::RunResultDocument(Err("Owned fixture result unavailable".into()))
        }
        ViewHydrationKey::RunRequestContext { .. } => {
            ViewHydrationValue::RunRequestContext(Err("Owned fixture request unavailable".into()))
        }
        ViewHydrationKey::PhaseReceiptOutcome { .. } => {
            ViewHydrationValue::PhaseReceiptOutcome(Ok(None))
        }
        ViewHydrationKey::ScanStageReceipt { .. } => {
            ViewHydrationValue::ScanStageReceipt(ScanStageReceiptState::Missing)
        }
        ViewHydrationKey::FindingPatchTruth { .. } => {
            ViewHydrationValue::FindingPatchTruth(FindingPatchTruthState::Missing)
        }
        ViewHydrationKey::FindingAuditDataflow { .. } => {
            ViewHydrationValue::FindingAuditDataflow(FindingAuditDataflowState::Missing)
        }
        ViewHydrationKey::FindingReviewSource { .. } => {
            ViewHydrationValue::FindingReviewSource(Ok(None))
        }
        ViewHydrationKey::ScannedSnippet { .. } => {
            ViewHydrationValue::ScannedSnippet(ScannedSnippetState::Missing)
        }
        ViewHydrationKey::SourceFile { .. } => {
            ViewHydrationValue::SourceFile(Err("missing fixture source".to_string()))
        }
        ViewHydrationKey::GitMetadata => ViewHydrationValue::GitMetadata(None),
        ViewHydrationKey::RevisionRelationship { .. } => ViewHydrationValue::RevisionRelationship(
            kuzushi_core::workspace::RevisionRelationship::Unavailable,
        ),
        ViewHydrationKey::ProjectScopeTree => {
            ViewHydrationValue::ProjectScopeTree(ProjectScopeTreeState::RootOnly)
        }
        ViewHydrationKey::ThreatModelStore => {
            ViewHydrationValue::ThreatModelStore(ThreatModelStoreState::Legacy)
        }
        ViewHydrationKey::MapRunContext { .. } => ViewHydrationValue::MapRunContext(Ok(None)),
        ViewHydrationKey::ProjectModelDocument { .. } => {
            ViewHydrationValue::ProjectModelDocument(None)
        }
        ViewHydrationKey::StrategyQueue => {
            ViewHydrationValue::StrategyQueue(StrategyQueueState::Ready(Vec::new()))
        }
        ViewHydrationKey::PromptMutations => {
            ViewHydrationValue::PromptMutations(PromptMutationsState::Ready(Vec::new()))
        }
        ViewHydrationKey::HarnessFile => ViewHydrationValue::HarnessFile(None),
        ViewHydrationKey::JsonFile { .. } => {
            ViewHydrationValue::JsonFile(JsonFileHydration::state(JsonFileState::Missing))
        }
        ViewHydrationKey::PathState { .. } => ViewHydrationValue::PathState(PathState::Missing),
        ViewHydrationKey::DirectoryListing { .. } => {
            ViewHydrationValue::DirectoryListing(DirectoryListingState::Missing)
        }
        ViewHydrationKey::PromptOverrideHash { .. } => {
            ViewHydrationValue::PromptOverrideHash(Ok(None))
        }
        ViewHydrationKey::HealthChecks { .. } => {
            ViewHydrationValue::HealthChecks(ViewHealthChecks {
                semgrep_error: None,
                codeql_error: None,
                credential_set: false,
            })
        }
        ViewHydrationKey::TargetProfile => {
            ViewHydrationValue::TargetProfile(TargetProfile::conservative())
        }
        ViewHydrationKey::MapArtifacts => ViewHydrationValue::MapArtifacts(false),
        ViewHydrationKey::RepositoryIndex => {
            ViewHydrationValue::RepositoryIndex(Arc::new(default_context_snapshot_view(None)))
        }
        ViewHydrationKey::CpgArtifacts => ViewHydrationValue::CpgArtifacts(false),
        ViewHydrationKey::ScanRecommendations => {
            ViewHydrationValue::ScanRecommendations(ScanRecommendationsState::Ready(Vec::new()))
        }
        ViewHydrationKey::TargetBase => ViewHydrationValue::TargetBase("target".to_string()),
        ViewHydrationKey::ExecutableOptions { .. } => {
            ViewHydrationValue::ExecutableOptions(Vec::new())
        }
    }
}

#[test]
fn cold_artifact_backed_views_do_not_touch_the_reader_during_render() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let reader = Arc::new(CountingReader::default());
    app.set_view_artifact_reader_for_test(reader.clone());
    app.set_focused_module(Some("sast".to_string()));
    let mut terminal = Terminal::new(TestBackend::new(100, 36)).unwrap();

    for view in [
        ShellView::Home,
        ShellView::Recommend,
        ShellView::Module,
        ShellView::Workbench,
        ShellView::Tune,
        ShellView::Threat,
        ShellView::PromptsEditor,
        ShellView::Runs,
        ShellView::Jobs,
        ShellView::RunDiff,
        ShellView::Replay,
        ShellView::Trace,
        ShellView::Health,
        ShellView::ProjectModel,
        ShellView::StrategyQueue,
        ShellView::FailureHandoff,
        ShellView::Activity,
        ShellView::PlanningPicker,
        ShellView::Scene,
    ] {
        render_cold_view(&mut terminal, &mut app, view);
    }

    assert_eq!(reader.reads.load(Ordering::SeqCst), 0);
}

fn render_cold_view(terminal: &mut Terminal<TestBackend>, app: &mut ShellApp, view: ShellView) {
    match view {
        ShellView::RunDiff => app.open_run_diff_for_test("run-left", "run-right"),
        ShellView::Replay => app.open_replay_for_test("run-replay"),
        ShellView::Trace => app.open_trace_for_test("run-trace"),
        _ => app.set_shell_view(view),
    }
    terminal.draw(|frame| render_app(frame, app)).unwrap();
}

#[test]
fn scheduling_the_same_key_twice_deduplicates_the_read() {
    let temp = tempfile::tempdir().unwrap();
    let reader = Arc::new(CountingReader::default());
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(reader.clone());
    let key = ViewHydrationKey::LatestRunPointer;

    assert_eq!(
        runtime
            .schedule(temp.path().to_path_buf(), vec![key.clone()], None)
            .len(),
        1
    );
    assert!(runtime
        .schedule(temp.path().to_path_buf(), vec![key], None)
        .is_empty());
    wait_until(|| reader.reads.load(Ordering::SeqCst) == 1);

    assert_eq!(reader.reads.load(Ordering::SeqCst), 1);
}

#[test]
fn workbench_hydrates_the_map_artifact_state() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);

    assert!(active_view_hydration_keys(&app).contains(&ViewHydrationKey::MapArtifacts));
}

#[test]
fn comparison_and_origin_artifacts_remain_hydrated_together() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_view_artifact_reader_for_test(Arc::new(CountingReader::default()));
    app.open_run_diff_for_test("run-left", "run-right");
    let mut keys = active_view_hydration_keys(&app);
    // The comparison must coexist with the durable phase's pending result.
    for leaf in ["run.json", "result.json", "scan-input.json"] {
        keys.push(ViewHydrationKey::RunArtifactText {
            run_id: "origin-run".into(),
            leaf: leaf.into(),
        });
    }
    app.hydrate_view_keys_blocking(workspace.root(), keys.clone());
    let cache = app.workbench_cache().borrow();
    for key in keys
        .iter()
        .filter(|key| matches!(key, ViewHydrationKey::RunArtifactText { .. }))
    {
        assert!(
            !cache.view_hydration_needed(workspace.root(), key),
            "evicted active artifact: {key:?}"
        );
    }
}

#[test]
fn hydration_key_enumeration_skips_phase_result_presentation() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let snapshot = kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(temp.path());
    let completed = kuzushi_core::workflow_attempts::PhaseAttemptCompleted::new(
        WorkflowPhase::Map,
        vec!["run-must-not-be-read".to_string()],
        snapshot.clone(),
        kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Completed,
    );
    let attempt_id = completed.attempt_id.clone();
    let ledger = kuzushi_core::workflow_attempts::PhaseAttemptLedger::from_events([
        kuzushi_core::workflow_attempts::PhaseAttemptEvent::PhaseAttemptCompleted(completed),
    ])
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);
    app.engagement
        .set_phase_attempt_projection(Some(snapshot), ledger);
    crate::app::take_phase_result_presentation_calls();

    let keys = active_view_hydration_keys(&app);

    assert!(keys.contains(&ViewHydrationKey::ScanRecommendations));
    assert!(keys.contains(&ViewHydrationKey::PhaseReceiptOutcome { attempt_id }));
    assert_eq!(crate::app::take_phase_result_presentation_calls(), 0);
}

#[test]
fn entry_point_surfaces_hydrate_catalog_context_and_threat_model_together() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let catalog =
        kuzushi_core::workspace::workspace_state_root(workspace.root()).join("entry-points.json");
    let threat_model = kuzushi_core::capabilities::persistent_threat_model_path(workspace.root());
    let context = kuzushi_core::context_snapshot_path(workspace.root());

    for view in [ShellView::Workbench, ShellView::Scene] {
        app.set_shell_view(view);
        let keys = active_view_hydration_keys(&app);
        assert!(keys.contains(&ViewHydrationKey::JsonFile {
            path: catalog.clone(),
        }));
        assert!(keys.contains(&ViewHydrationKey::JsonFile {
            path: threat_model.clone(),
        }));
        assert!(keys.contains(&ViewHydrationKey::JsonFile {
            path: context.clone(),
        }));
    }
}

#[test]
fn contextual_run_views_hydrate_the_visible_surface() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.open_replay_for_test("run-replay");
    let replay_keys = active_view_hydration_keys(&app);
    assert!(replay_keys.contains(&ViewHydrationKey::RunProjection {
        run_id: "run-replay".to_string(),
    }));

    app.restore_contextual_surface_origin();
    app.open_trace_for_test("run-trace");
    let trace_keys = active_view_hydration_keys(&app);
    assert!(trace_keys.contains(&ViewHydrationKey::RunProjection {
        run_id: "run-trace".to_string(),
    }));
}

#[test]
fn fix_requests_generation_bound_finding_patch_truth() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Fix));
    let mut finding = Finding::new_semgrep(
        "fixture.rule",
        "src/lib.rs",
        7,
        None,
        kuzushi_core::Severity::High,
        "fixture finding",
    );
    finding.scan_id = Some("scan-generation".to_string());
    let fingerprint = finding.fingerprint.clone();
    app.set_findings(vec![finding]);
    app.engagement.set_phase_attempt_projection(
        Some(kuzushi_core::workflow_attempts::PhaseTargetSnapshot {
            target: temp.path().display().to_string(),
            revision: Some("revision-1".to_string()),
            dirty: false,
        }),
        kuzushi_core::workflow_attempts::PhaseAttemptLedger::default(),
    );

    let keys = active_view_hydration_keys(&app);

    assert!(keys.contains(&ViewHydrationKey::FindingPatchTruth {
        fingerprint,
        finding_scan_id: Some("scan-generation".to_string()),
        target_revision: Some("revision-1".to_string()),
    }));
}

#[test]
fn workbench_requests_audit_dataflow_for_the_selected_finding() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    let finding = Finding::new_semgrep(
        "fixture.rule",
        "src/lib.rs",
        7,
        None,
        kuzushi_core::Severity::High,
        "fixture finding",
    );
    let fingerprint = finding.fingerprint.clone();
    app.set_findings(vec![finding]);

    let keys = active_view_hydration_keys(&app);

    assert!(keys.contains(&ViewHydrationKey::FindingAuditDataflow { fingerprint }));
}

#[test]
fn non_fix_workbench_pages_do_not_request_finding_patch_truth() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app.set_findings(vec![Finding::new_semgrep(
        "fixture.rule",
        "src/lib.rs",
        7,
        None,
        kuzushi_core::Severity::High,
        "fixture finding",
    )]);

    assert!(!active_view_hydration_keys(&app)
        .iter()
        .any(|key| matches!(key, ViewHydrationKey::FindingPatchTruth { .. })));
}

#[test]
fn replacing_findings_invalidates_same_key_remediation_truth() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let mut finding = Finding::new_semgrep(
        "fixture.rule",
        "src/lib.rs",
        7,
        None,
        kuzushi_core::Severity::High,
        "fixture finding",
    );
    finding.scan_id = Some("scan-generation".to_string());
    let fingerprint = finding.fingerprint.clone();
    app.set_findings(vec![finding.clone()]);
    let key = ViewHydrationKey::FindingPatchTruth {
        fingerprint: fingerprint.clone(),
        finding_scan_id: finding.scan_id.clone(),
        target_revision: None,
    };
    app.hydrate_view_keys_blocking(workspace.root(), vec![key]);
    assert!(matches!(
        app.workbench_cache().borrow().cached_finding_patch_truth(
            workspace.root(),
            &fingerprint,
            finding.scan_id.as_deref(),
            None,
        ),
        ViewDataState::Ready(_)
    ));

    app.set_findings(vec![finding.clone()]);

    assert!(app
        .workbench_cache()
        .borrow()
        .cached_finding_patch_truth(
            workspace.root(),
            &fingerprint,
            finding.scan_id.as_deref(),
            None,
        )
        .is_not_requested());
}

#[test]
fn jobs_requests_the_bounded_run_history_page() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Jobs);

    assert!(active_view_hydration_keys(&app).contains(&ViewHydrationKey::RunSummaryEntries));
}

#[test]
fn jobs_surfaces_a_run_history_reader_failure() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_view_artifact_reader_for_test(Arc::new(FailingRunHistoryReader));
    app.set_shell_view(ShellView::Jobs);
    let target = app.target_owned().expect("jobs fixture target");
    app.hydrate_view_keys_blocking(&target, vec![ViewHydrationKey::RunSummaryEntries]);

    let model = jobs_registry_model(&app, 20);
    assert_eq!(
        model.history_state,
        JobHistoryState::Failed("fixture run-history failure".to_string())
    );
    let mut terminal = Terminal::new(TestBackend::new(100, 36)).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains("recent run history unavailable"),
        "{rendered}"
    );
    assert!(
        rendered.contains("fixture run-history failure"),
        "{rendered}"
    );
    assert!(!rendered.contains("no jobs yet"), "{rendered}");
}

#[test]
fn jobs_keeps_live_rows_when_run_history_fails() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_view_artifact_reader_for_test(Arc::new(FailingRunHistoryReader));
    app.steer_queue_mut().enqueue(QueuedCommand {
        raw: "run context:build".to_string(),
        summary: "run context:build".to_string(),
    });
    let target = app.target_owned().expect("jobs fixture target");
    app.hydrate_view_keys_blocking(&target, vec![ViewHydrationKey::RunSummaryEntries]);

    let model = jobs_registry_model(&app, 20);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(
        model.rows[0].status,
        crate::ui_view_models::JobRunStatus::Queued
    );
    assert!(matches!(model.history_state, JobHistoryState::Failed(_)));
}

#[derive(Debug, Default)]
struct BlockingReader {
    state: Arc<(Mutex<BlockingState>, Condvar)>,
}

#[derive(Debug, Default)]
struct BlockingState {
    started: bool,
    reads_started: usize,
    released: bool,
}

impl ViewArtifactReader for BlockingReader {
    fn read(&self, _target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        let (lock, wake) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.started = true;
        state.reads_started += 1;
        wake.notify_all();
        while !state.released {
            state = wake.wait(state).unwrap();
        }
        missing_value(key)
    }
}

#[test]
fn target_generation_discards_a_stale_result() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let reader = Arc::new(BlockingReader::default());
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(reader.clone());
    schedule_latest(&mut runtime, first.path());
    wait_for_reader_start(&reader);

    runtime.schedule(second.path().to_path_buf(), Vec::new(), None);
    release_reader(&reader);
    wait_until(|| runtime.workers_finished());

    assert!(runtime.drain_current().results.is_empty());
}

#[test]
fn stale_target_generation_discards_target_metadata_results() {
    for key in [
        ViewHydrationKey::TargetProfile,
        ViewHydrationKey::RepositoryIndex,
    ] {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let reader = Arc::new(BlockingReader::default());
        let mut runtime = ViewHydrationRuntime::default();
        runtime.set_reader(reader.clone());
        runtime.schedule(first.path().to_path_buf(), vec![key], None);
        wait_for_reader_start(&reader);

        runtime.schedule(second.path().to_path_buf(), Vec::new(), None);
        release_reader(&reader);
        wait_until(|| runtime.workers_finished());

        assert!(runtime.drain_current().results.is_empty());
    }
}

#[derive(Debug, Default)]
struct PanicReader;

impl ViewArtifactReader for PanicReader {
    fn read(&self, _target: &Path, _key: &ViewHydrationKey) -> ViewHydrationValue {
        panic!("fixture reader panic")
    }
}

#[test]
fn reader_panic_clears_in_flight_key_for_retry() {
    let temp = tempfile::tempdir().unwrap();
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(Arc::new(PanicReader));
    assert_eq!(schedule_latest(&mut runtime, temp.path()).len(), 1);
    wait_until(|| runtime.workers_finished());

    assert_eq!(runtime.drain_current().failures.len(), 1);
    assert_eq!(schedule_latest(&mut runtime, temp.path()).len(), 1);
}

#[test]
fn invalidation_discards_queued_reader_failures() {
    let temp = tempfile::tempdir().unwrap();
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(Arc::new(PanicReader));
    schedule_latest(&mut runtime, temp.path());
    wait_until(|| runtime.workers_finished());

    runtime.invalidate();

    assert!(runtime.drain_current().failures.is_empty());
}

#[test]
fn rapid_target_generations_keep_worker_count_bounded() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let third = tempfile::tempdir().unwrap();
    let reader = Arc::new(BlockingReader::default());
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(reader.clone());

    schedule_latest(&mut runtime, first.path());
    wait_for_reader_start(&reader);
    schedule_latest(&mut runtime, second.path());
    // A superseded batch cancelled before it reaches the reader exits and
    // frees its slot. Wait until both workers are blocked inside the reader
    // so the cap, not that race, decides the third request.
    wait_for_reads_started(&reader, MAX_VIEW_HYDRATION_WORKERS);
    let refused = schedule_latest(&mut runtime, third.path());

    assert!(refused.is_empty());
    assert_eq!(runtime.worker_count(), MAX_VIEW_HYDRATION_WORKERS);
    release_reader(&reader);
}

#[derive(Debug, Default)]
struct CancellationAwareReader {
    started: AtomicUsize,
    exited: AtomicUsize,
}

impl ViewArtifactReader for CancellationAwareReader {
    fn read(&self, _target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        missing_value(key)
    }

    fn read_cancellable(
        &self,
        _target: &Path,
        _key: &ViewHydrationKey,
        cancellation: &ViewHydrationCancellation,
    ) -> Option<ViewHydrationValue> {
        self.started.fetch_add(1, Ordering::SeqCst);
        while !cancellation.is_canceled() {
            std::thread::yield_now();
        }
        self.exited.fetch_add(1, Ordering::SeqCst);
        None
    }
}

#[test]
fn invalidation_cancels_stale_hydration_and_releases_its_worker_slot() {
    let temp = tempfile::tempdir().unwrap();
    let reader = Arc::new(CancellationAwareReader::default());
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(reader.clone());
    assert_eq!(
        runtime
            .schedule(
                temp.path().to_path_buf(),
                vec![ViewHydrationKey::FileCompletionValues],
                None,
            )
            .len(),
        1
    );
    wait_until(|| reader.started.load(Ordering::SeqCst) == 1);

    runtime.invalidate();
    wait_until(|| reader.exited.load(Ordering::SeqCst) == 1);
    wait_until(|| runtime.workers_finished());
    assert!(runtime.drain_current().results.is_empty());
    assert_eq!(runtime.worker_count(), 0);

    let replacement = Arc::new(CountingReader::default());
    runtime.set_reader(replacement.clone());
    assert_eq!(schedule_latest(&mut runtime, temp.path()).len(), 1);
    wait_until(|| replacement.reads.load(Ordering::SeqCst) == 1);
}

#[test]
fn same_target_invalidation_discards_pre_invalidation_result() {
    let temp = tempfile::tempdir().unwrap();
    let reader = Arc::new(BlockingReader::default());
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(reader.clone());

    schedule_latest(&mut runtime, temp.path());
    wait_for_reader_start(&reader);
    runtime.invalidate();
    release_reader(&reader);
    wait_until(|| runtime.workers_finished());

    assert!(runtime.drain_current().results.is_empty());
}

fn schedule_latest(runtime: &mut ViewHydrationRuntime, target: &Path) -> Vec<ViewHydrationKey> {
    runtime.schedule(
        target.to_path_buf(),
        vec![ViewHydrationKey::LatestRunPointer],
        None,
    )
}

fn wait_for_reader_start(reader: &BlockingReader) {
    let (lock, wake) = &*reader.state;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut state = lock.lock().unwrap();
    while !state.started {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "reader did not start");
        let (next, timeout) = wake.wait_timeout(state, remaining).unwrap();
        state = next;
        assert!(
            !timeout.timed_out() || state.started,
            "reader did not start"
        );
    }
}

fn wait_for_reads_started(reader: &BlockingReader, count: usize) {
    let (lock, wake) = &*reader.state;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut state = lock.lock().unwrap();
    while state.reads_started < count {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "readers did not start");
        state = wake.wait_timeout(state, remaining).unwrap().0;
    }
}

fn release_reader(reader: &BlockingReader) {
    let (lock, wake) = &*reader.state;
    let mut state = lock.lock().unwrap();
    state.released = true;
    wake.notify_all();
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !condition() && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(condition(), "condition did not become true");
}

#[test]
fn scan_page_and_report_hydrate_typed_receipts_for_an_earlier_source_selection() {
    use kuzushi_core::workflow_attempts::{
        PhaseAttemptCompleted, PhaseAttemptDisposition, PhaseAttemptDispositionRecorded,
        PhaseAttemptEvent, PhaseAttemptLedger, PhaseAttemptOutcome, PhaseTargetSnapshot,
    };
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let snapshot = |revision: &str| PhaseTargetSnapshot {
        target: "/earlier-source-target".to_string(),
        revision: Some(revision.to_string()),
        dirty: false,
    };
    let completed = PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec!["trial-1".into(), "trial-2".into()],
        snapshot("abc"),
        PhaseAttemptOutcome::Completed,
    );
    let selection = PhaseAttemptDispositionRecorded::new(
        &completed.attempt_id,
        PhaseAttemptDisposition::Selected {
            acknowledged_partial: false,
        },
    );
    let ledger = PhaseAttemptLedger::from_events([
        PhaseAttemptEvent::PhaseAttemptCompleted(completed),
        PhaseAttemptEvent::PhaseAttemptDispositionRecorded(selection),
    ])
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);
    app.set_workbench_page(WorkbenchPage::Scan);
    app.engagement
        .set_phase_attempt_projection(Some(snapshot("def")), ledger);

    for view in [ShellView::Workbench, ShellView::Report] {
        app.set_shell_view(view);
        let keys = active_view_hydration_keys(&app);
        for run_id in ["trial-1", "trial-2"] {
            assert!(
                keys.contains(&ViewHydrationKey::ScanStageReceipt {
                    run_id: run_id.to_string()
                }),
                "{view:?}: {keys:?}"
            );
        }
    }
}
