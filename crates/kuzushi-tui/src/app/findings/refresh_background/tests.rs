use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::{Severity, V2Config};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[derive(Debug, Default)]
struct ControlledLedgerReader {
    started: (Mutex<bool>, Condvar),
    released: (Mutex<bool>, Condvar),
}

impl ControlledLedgerReader {
    fn wait_started(&self) {
        let (value, _) = self
            .started
            .1
            .wait_timeout_while(
                self.started.0.lock().unwrap(),
                Duration::from_secs(5),
                |started| !*started,
            )
            .unwrap();
        assert!(*value, "background reader started");
    }

    fn release(&self) {
        *self.released.0.lock().unwrap() = true;
        self.released.1.notify_all();
    }
}

impl ViewArtifactReader for ControlledLedgerReader {
    fn read(&self, target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        let ViewHydrationKey::FindingsProjection(request) = key else {
            panic!("unexpected test request")
        };
        if request.filter.as_deref() != Some("name:beta") {
            *self.started.0.lock().unwrap() = true;
            self.started.1.notify_all();
            let (_guard, timeout) = self
                .released
                .1
                .wait_timeout_while(
                    self.released.0.lock().unwrap(),
                    Duration::from_secs(5),
                    |released| !*released,
                )
                .unwrap();
            assert!(!timeout.timed_out(), "test releases bounded reader");
        }
        ViewHydrationValue::FindingsProjection(
            read_findings_projection(target, request).map_err(|error| error.to_string()),
        )
    }
}

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("lib.rs"),
        "// Benign source, never executed.\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("fixture", workspace.root(), "completed")
        .unwrap();
    for name in ["alpha", "beta"] {
        store
            .insert_finding(
                "fixture",
                &Finding::new_tool("fixture", name, "lib.rs", 1, None, Severity::Low, name),
            )
            .unwrap();
    }
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let request = app.findings_read_request(0, root.path().to_path_buf(), None);
    let snapshot = read_findings_projection(root.path(), &request).unwrap();
    app.apply_findings_read_snapshot(snapshot, &request, false);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app.set_input_mode(InputMode::Prompt);
    let (_, wake) = TerminalLoopInbox::channel_for_test();
    app.set_loop_wake(Some(wake));
    (root, app)
}

fn install_reader(app: &mut ShellApp) -> Arc<ControlledLedgerReader> {
    let reader = Arc::new(ControlledLedgerReader::default());
    app.set_view_artifact_reader_for_test(reader.clone());
    reader
}

fn request(app: &mut ShellApp, filter: Option<&str>, continuation: Vec<ShellEffect>) {
    let mut effects = vec![ShellEffect::RefreshFindings(FindingsRefresh {
        announce: false,
        filter: filter.map(str::to_owned),
    })];
    effects.extend(continuation);
    EffectRuntime::execute(app, effects);
}

fn settle(app: &mut ShellApp) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while app.runtime_state.findings_refresh.pending.is_some() {
        app.apply_view_hydration_results();
        assert!(Instant::now() < deadline, "bounded refresh settles");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn blocked_refresh_accepts_typing_and_does_not_steal_later_focus() {
    let (_root, mut app) = fixture();
    let reader = install_reader(&mut app);
    request(
        &mut app,
        None,
        vec![ShellEffect::OpenFinding(OpenFindingReference {
            reference: "F-0001".into(),
        })],
    );
    reader.wait_started();
    let status = crate::ui_view_models::review_queue_model(
        &app,
        crate::ui_view_models::ReviewQueueMode::All,
    );
    assert!(status
        .refresh_status
        .unwrap()
        .message
        .contains("previous results"));
    assert!(
        app.reduce_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE))
            .handled
    );
    app.set_shell_view(ShellView::Activity);
    reader.release();
    settle(&mut app);
    assert_eq!(app.input(), "x");
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.selected_finding().is_none());
    assert_eq!(app.findings().len(), 2);
}

#[test]
fn study_read_failure_keeps_the_filter_draft_and_scope_through_retry() {
    let (_root, mut app) = fixture();
    app.set_active_findings_filter(Some("severity:low limit:2".into()));
    app.router.campaign_mut().active_batch_id = Some("missing-study".into());
    app.set_input("Held draft\nsecond line");
    app.set_cursor(4);
    let reader = install_reader(&mut app);
    let update = app.reduce_command_message(ShellCommand::FindingsRefresh);
    EffectRuntime::execute(&mut app, update.effects);
    reader.wait_started();
    let pending = app.findings_read_feedback().unwrap();
    assert_eq!(pending.population_title(), "FINDINGS · reading study");
    assert!(!pending.message.contains("previous results"));
    reader.release();
    settle(&mut app);
    let failed = app.findings_read_feedback().unwrap();
    assert_eq!(failed.population_title(), "FINDINGS · study unavailable");
    assert!(failed.recovery_lines().contains(&"Retry: findings refresh"));
    assert!(failed
        .recovery_lines()
        .contains(&"Workspace history: batch clear"));
    assert_eq!(
        app.active_findings_filter().as_deref(),
        Some("severity:low limit:2")
    );
    assert_eq!(
        app.router.campaign().active_batch_id.as_deref(),
        Some("missing-study")
    );
    assert_eq!(app.input(), "Held draft\nsecond line");
    assert_eq!(app.cursor(), 4);
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert!(!app.has_running_work());
}

#[test]
fn findings_refresh_keeps_the_current_view_and_selected_row() {
    let (_root, mut app) = fixture();
    app.set_active_findings_filter(Some("name:alpha".into()));
    app.router.findings_mut().set_cursor(1);
    app.set_shell_view(ShellView::Activity);
    let update = app.reduce_command_message(ShellCommand::FindingsRefresh);
    assert_eq!(app.active_findings_filter().as_deref(), Some("name:alpha"));
    assert_eq!(app.router.findings().cursor(), 1);
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(
        matches!(update.effects.as_slice(), [ShellEffect::RefreshFindings(FindingsRefresh { announce: false, filter: Some(filter) })] if filter == "name:alpha")
    );
}

#[test]
fn newer_filter_wins_when_older_reader_finishes_last() {
    let (_root, mut app) = fixture();
    let reader = install_reader(&mut app);
    request(&mut app, Some("name:alpha"), vec![]);
    reader.wait_started();
    request(&mut app, Some("name:beta"), vec![]);
    settle(&mut app);
    assert_eq!(app.active_findings_filter().as_deref(), Some("name:beta"));
    assert_eq!(app.findings()[0].message.as_str(), "beta");
    reader.release();
    std::thread::sleep(Duration::from_millis(30));
    app.apply_view_hydration_results();
    assert_eq!(app.findings()[0].message.as_str(), "beta");
}

#[test]
fn target_change_discards_old_rows_and_navigation() {
    let (_root, mut app) = fixture();
    let reader = install_reader(&mut app);
    request(
        &mut app,
        None,
        vec![ShellEffect::OpenFinding(OpenFindingReference {
            reference: "F-0001".into(),
        })],
    );
    reader.wait_started();
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().to_path_buf()));
    reader.release();
    settle(&mut app);
    assert!(app.selected_finding().is_none());
    assert_eq!(app.target(), Some(other.path()));
}

#[test]
fn invalid_filter_preserves_rows_and_validated_progress() {
    let (_root, mut app) = fixture();
    let reader = install_reader(&mut app);
    app.domain_mut()
        .set_finding_ledger_counts(FindingLedgerCounts {
            total: 2,
            reviewed: 2,
            confirmed: 2,
            ..Default::default()
        });
    request(&mut app, Some("unknown:invalid"), vec![]);
    reader.wait_started();
    reader.release();
    settle(&mut app);
    assert_eq!(app.findings().len(), 2);
    assert_eq!(app.active_findings_filter(), &None);
    assert!(app
        .findings_refresh_status()
        .unwrap()
        .contains("Refresh failed"));
    let counts = app.domain().finding_ledger_counts().unwrap();
    assert_eq!((counts.total, counts.reviewed, counts.confirmed), (2, 2, 2));
}

#[test]
fn unavailable_ledger_preserves_rows_and_clears_completion_claims() {
    let (root, mut app) = fixture();
    let reader = install_reader(&mut app);
    app.domain_mut()
        .set_finding_ledger_counts(FindingLedgerCounts {
            total: 2,
            reviewed: 2,
            confirmed: 2,
            ..Default::default()
        });
    request(&mut app, None, vec![]);
    reader.wait_started();
    std::fs::rename(
        root.path().join(".kuzushi/v3/index.sqlite3"),
        root.path().join("unavailable.sqlite3"),
    )
    .unwrap();
    reader.release();
    settle(&mut app);
    assert_eq!(app.findings().len(), 2);
    let counts = app.domain().finding_ledger_counts().unwrap();
    assert_eq!((counts.total, counts.reviewed, counts.confirmed), (2, 0, 0));
    assert!(app
        .findings_refresh_status()
        .unwrap()
        .contains("Refresh failed"));
}

#[test]
fn only_presentation_effects_are_deferred() {
    let (_root, app) = fixture();
    assert!(app.can_defer_findings_refresh(&VecDeque::new()));
    assert!(
        !app.can_defer_findings_refresh(&VecDeque::from(vec![ShellEffect::PersistCommandHistory]))
    );
}

#[test]
fn synchronous_newer_projection_invalidates_a_pending_read() {
    let (_root, mut app) = fixture();
    let reader = install_reader(&mut app);
    request(&mut app, Some("name:alpha"), vec![]);
    reader.wait_started();
    app.set_findings_read_watermark(Some(u64::MAX));
    reader.release();
    settle(&mut app);
    assert_eq!(app.findings().len(), 2);
    assert_eq!(app.findings_read_watermark(), Some(u64::MAX));
    assert_eq!(app.active_findings_filter(), &None);
}

#[test]
fn unchanged_interaction_opens_alias_after_projection_arrives() {
    let (_root, mut app) = fixture();
    let reader = install_reader(&mut app);
    request(
        &mut app,
        None,
        vec![ShellEffect::OpenFinding(OpenFindingReference {
            reference: "F-0001".into(),
        })],
    );
    reader.wait_started();
    assert!(app.selected_finding().is_none());
    reader.release();
    settle(&mut app);
    assert!(app.selected_finding().is_some());
    assert_eq!(app.router.workbench().page(), Some(WorkbenchPage::Review));
}

#[test]
fn passive_external_refresh_retains_pending_filter_and_open_action() {
    let (_root, mut app) = fixture();
    let reader = install_reader(&mut app);
    request(
        &mut app,
        Some("name:alpha"),
        vec![ShellEffect::OpenFinding(OpenFindingReference {
            reference: "F-0001".into(),
        })],
    );
    reader.wait_started();
    request(&mut app, None, vec![]);
    assert_eq!(
        app.runtime_state
            .findings_refresh
            .pending
            .as_ref()
            .unwrap()
            .request
            .filter
            .as_deref(),
        Some("name:alpha")
    );
    reader.release();
    settle(&mut app);
    assert_eq!(app.active_findings_filter().as_deref(), Some("name:alpha"));
    assert_eq!(app.findings().len(), 1);
    assert_eq!(app.selected_finding().as_ref().unwrap().message, "alpha");
}

#[test]
fn a_failed_refresh_status_does_not_follow_another_target() {
    let (_root, mut app) = fixture();
    let reader = install_reader(&mut app);
    request(&mut app, Some("unknown:invalid"), vec![]);
    reader.wait_started();
    reader.release();
    settle(&mut app);
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().to_path_buf()));
    assert!(app.findings_refresh_status().is_none());
}

#[test]
fn a_successful_retry_clears_only_its_refresh_error() {
    let (_root, mut app) = fixture();
    let reader = install_reader(&mut app);
    request(&mut app, Some("unknown:invalid"), vec![]);
    reader.wait_started();
    reader.release();
    settle(&mut app);
    assert!(app.advisory().notice.is_some());
    request(&mut app, Some("name:beta"), vec![]);
    settle(&mut app);
    assert!(app.findings_refresh_status().is_none());
    assert!(app.advisory().notice.is_none());
    assert_eq!(app.findings()[0].message, "beta");
}

#[test]
fn a_new_target_without_a_ledger_keeps_its_honest_empty_state() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    for id in [1, 2] {
        let request = app.findings_read_request(id, root.path().to_path_buf(), None);
        let snapshot = read_findings_projection(root.path(), &request).unwrap();
        app.apply_findings_read_snapshot(snapshot, &request, false);
        assert!(app.findings().is_empty());
        assert!(app.findings_refresh_status().is_none());
        assert_eq!(app.domain().finding_ledger_counts().unwrap().total, 0);
    }
}
