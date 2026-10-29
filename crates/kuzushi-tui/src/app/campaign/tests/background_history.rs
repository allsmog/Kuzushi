use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
struct ControlledHistoryReader {
    released: AtomicBool,
    ignore_cancel: AtomicBool,
    panic: AtomicBool,
    capture_before_hold: AtomicBool,
    started: AtomicUsize,
    canceled: AtomicUsize,
    active: AtomicUsize,
    max_active: AtomicUsize,
}

impl ViewArtifactReader for ControlledHistoryReader {
    fn read(&self, target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        assert!(
            !self.panic.load(Ordering::Acquire),
            "Controlled history-reader failure"
        );
        crate::app::view_hydration::read_view_artifact_for_test(target, key)
    }

    fn read_cancellable(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
        cancellation: &ViewHydrationCancellation,
    ) -> Option<ViewHydrationValue> {
        if !matches!(key, ViewHydrationKey::CampaignHistory(_)) {
            return Some(crate::app::view_hydration::read_view_artifact_for_test(
                target, key,
            ));
        }
        let captured = self
            .capture_before_hold
            .load(Ordering::Acquire)
            .then(|| self.read(target, key));
        self.started.fetch_add(1, Ordering::AcqRel);
        let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
        self.max_active.fetch_max(active, Ordering::AcqRel);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.released.load(Ordering::Acquire) {
            if cancellation.is_canceled() && !self.ignore_cancel.load(Ordering::Acquire) {
                self.canceled.fetch_add(1, Ordering::AcqRel);
                self.active.fetch_sub(1, Ordering::AcqRel);
                return None;
            }
            assert!(
                Instant::now() < deadline,
                "Controlled reader release timed out"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        self.active.fetch_sub(1, Ordering::AcqRel);
        Some(captured.unwrap_or_else(|| self.read(target, key)))
    }
}

fn enable_background(app: &mut ShellApp) {
    let workspace = kuzushi_core::WorkspaceTarget::new(app.target().unwrap()).unwrap();
    app.set_target(Some(workspace.root().into()));
    let (_, wake) = crate::app::runtime::TerminalLoopInbox::channel_for_test();
    app.set_loop_wake(Some(wake));
}

fn controlled_app() -> (tempfile::TempDir, ShellApp, Arc<ControlledHistoryReader>) {
    let (root, mut app) = deck_app();
    app.open_campaign_view(Some("camp1".into()));
    enable_background(&mut app);
    let reader = Arc::new(ControlledHistoryReader::default());
    app.set_view_artifact_reader_for_test(reader.clone());
    (root, app, reader)
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "Background history did not reach the required state"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn wait_for_history(app: &mut ShellApp, reader: &ControlledHistoryReader, count: usize) {
    wait_until(|| {
        app.apply_view_hydration_results();
        reader.started.load(Ordering::Acquire) == count
    });
}

fn finish(app: &mut ShellApp) {
    wait_until(|| {
        app.apply_view_hydration_results();
        !app.campaign_history_loading()
    });
}

#[test]
fn cold_history_open_defers_the_catalogue_until_background_completion() {
    let (_root, mut app) = deck_app();
    enable_background(&mut app);
    app.set_input("retained 東京 history draft");
    app.open_campaign_view(Some("camp1".into()));
    assert!(
        app.router.campaign().campaigns.is_empty(),
        "Terminal history must not synchronously load its catalogue"
    );
    assert_eq!(app.input(), "retained 東京 history draft");
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(
        crate::ui_view_models::context_strip_model(&app).study_title,
        Some("Investigation history")
    );
    finish(&mut app);
    assert_eq!(
        app.router
            .campaign()
            .selected_campaign()
            .unwrap()
            .campaign_id,
        "camp1"
    );
}

#[test]
fn held_history_keeps_keyboard_input_and_does_not_steal_navigation() {
    let (_root, mut app, reader) = controlled_app();
    app.router.campaign_mut().selected_job = 1;
    app.router.campaign_mut().read_scroll = 4;
    app.refresh_campaign_deck();
    wait_for_history(&mut app, &reader, 1);
    app.set_input_mode(InputMode::Prompt);
    app.set_input("history draft ");
    let update = app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('λ'),
        crossterm::event::KeyModifiers::NONE,
    ));
    assert!(update.handled);
    assert_eq!(app.input(), "history draft λ");
    assert!(app.campaign_history_loading());
    assert_eq!(app.router.campaign().selected_job().unwrap().job_id, "j2");
    app.set_shell_view(ShellView::Report);
    reader.released.store(true, Ordering::Release);
    finish(&mut app);
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.input(), "history draft λ");
    assert_eq!(app.router.campaign().selected_job().unwrap().job_id, "j2");
    assert_eq!(app.router.campaign().read_scroll, 4);
}

#[test]
fn unread_history_refuses_launch_and_plan_edits_but_keeps_reading() {
    let (root, mut app, reader) = controlled_app();
    let queue = kuzushi_core::capabilities::campaign::campaign_queue_path(root.path(), "camp1");
    let before = std::fs::read(&queue).unwrap();
    let workers = app.router.campaign().workers;
    app.refresh_campaign_deck();
    wait_for_history(&mut app, &reader, 1);
    for action in [
        ViewHotkeyAction::CampaignLaunch,
        ViewHotkeyAction::CampaignCycleWorkers,
        ViewHotkeyAction::CampaignToggleExclude,
        ViewHotkeyAction::CampaignReviewStudy,
    ] {
        app.apply_campaign_hotkey(action);
    }
    assert_eq!(app.router.campaign().workers, workers);
    assert!(app.router.campaign().excluded.is_empty());
    assert!(app.router.campaign().dispatcher_pid.is_none());
    assert_eq!(std::fs::read(queue).unwrap(), before);
    app.apply_campaign_hotkey(ViewHotkeyAction::CampaignCursorNext);
    assert_eq!(app.router.campaign().selected_job().unwrap().job_id, "j2");
    reader.released.store(true, Ordering::Release);
    finish(&mut app);
    assert_eq!(app.router.campaign().selected_job().unwrap().job_id, "j2");
    assert!(!app
        .router
        .campaign()
        .notice
        .as_deref()
        .unwrap_or_default()
        .contains("Wait for history"));
}

#[test]
fn batch_result_scope_waits_for_the_selected_history_record_without_launching() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("owned.rs"),
        "// Owned inert source, never executed\n",
    )
    .unwrap();
    kuzushi_core::capabilities::campaign::compile_scan_batch_plan(
        kuzushi_core::capabilities::campaign::ScanBatchPlanSpec {
            root: root.path(),
            batch_id: Some("owned-batch".into()),
            trials: 3,
            requested_workers: 1,
            gate_policy: Default::default(),
            prepared_input: serde_json::json!({"taskMode":"manual","tasks":["secret-scan"]}),
            config: &V2Config::default(),
            registry: &kuzushi_core::ModuleRegistry::with_v2_builtins(),
        },
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    enable_background(&mut app);
    app.open_batch_results("owned-batch");
    assert!(app.router.campaign().active_batch_id.is_none());
    finish(&mut app);
    assert_eq!(
        app.router.campaign().active_batch_id.as_deref(),
        Some("owned-batch")
    );
    assert_eq!(
        app.router
            .campaign()
            .selected_campaign()
            .unwrap()
            .campaign_id,
        "owned-batch"
    );
    assert!(
        !kuzushi_core::capabilities::campaign::campaign_queue_path(root.path(), "owned-batch")
            .exists()
    );
}

#[test]
fn newer_history_request_cancels_the_older_read_and_keeps_the_exact_id() {
    let (root, mut app, reader) = controlled_app();
    let path = kuzushi_core::capabilities::campaign::campaign_plan_path(root.path(), "other");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
        r#"{"campaignId":"other","tool":"sast:scan","jobs":[]}"#,
    )
    .unwrap();
    app.open_campaign_view(Some("camp1".into()));
    wait_for_history(&mut app, &reader, 1);
    app.open_campaign_view(Some("other".into()));
    wait_until(|| {
        app.apply_view_hydration_results();
        reader.canceled.load(Ordering::Acquire) > 0
    });
    reader.released.store(true, Ordering::Release);
    finish(&mut app);
    assert_eq!(
        app.router
            .campaign()
            .selected_campaign()
            .unwrap()
            .campaign_id,
        "other"
    );
}

#[test]
fn target_change_ignores_the_old_history_and_preserves_the_new_view() {
    let (_root, mut app, reader) = controlled_app();
    app.refresh_campaign_deck();
    wait_for_history(&mut app, &reader, 1);
    let next = tempfile::tempdir().unwrap();
    let next_workspace = kuzushi_core::WorkspaceTarget::new(next.path()).unwrap();
    app.set_target(Some(next_workspace.root().into()));
    app.open_campaign_view(None);
    reader.released.store(true, Ordering::Release);
    finish(&mut app);
    assert!(app.router.campaign().campaigns.is_empty());
    assert!(app
        .router
        .campaign()
        .history_coverage
        .as_ref()
        .unwrap()
        .complete());
    assert_eq!(app.target(), Some(next_workspace.root()));
}

#[test]
fn repeated_refreshes_coalesce_behind_the_two_existing_worker_slots() {
    let (_root, mut app, reader) = controlled_app();
    reader.ignore_cancel.store(true, Ordering::Release);
    app.open_campaign_view(Some("camp1".into()));
    wait_for_history(&mut app, &reader, 1);
    app.refresh_campaign_deck();
    wait_until(|| {
        app.apply_view_hydration_results();
        reader.started.load(Ordering::Acquire) == 2
    });
    for _ in 0..20 {
        app.refresh_campaign_deck();
    }
    assert!(app.campaign_history_loading());
    assert_eq!(reader.started.load(Ordering::Acquire), 2);
    reader.released.store(true, Ordering::Release);
    finish(&mut app);
    assert_eq!(reader.started.load(Ordering::Acquire), 3);
    assert!(reader.max_active.load(Ordering::Acquire) <= 2);
    assert_eq!(
        app.router
            .campaign()
            .selected_campaign()
            .unwrap()
            .campaign_id,
        "camp1"
    );
}

#[test]
fn failed_reader_retains_records_and_can_be_explicitly_refreshed() {
    let (_root, mut app, reader) = controlled_app();
    reader.panic.store(true, Ordering::Release);
    reader.released.store(true, Ordering::Release);
    app.refresh_campaign_deck();
    finish(&mut app);
    assert!(app
        .campaign_history_feedback()
        .unwrap()
        .contains("refresh failed"));
    assert_eq!(
        app.router
            .campaign()
            .selected_campaign()
            .unwrap()
            .campaign_id,
        "camp1"
    );
    assert!(
        app.router
            .campaign()
            .trend
            .unwrap()
            .provider_spend_unresolved
    );
    reader.panic.store(false, Ordering::Release);
    app.refresh_campaign_deck();
    finish(&mut app);
    assert!(app.campaign_history_feedback().is_none());
}

#[test]
fn a_newer_notice_and_job_selection_survive_the_completed_refresh() {
    let (_root, mut app, reader) = controlled_app();
    app.open_campaign_view(Some("camp1".into()));
    wait_for_history(&mut app, &reader, 1);
    app.router.campaign_mut().selected_job = 1;
    app.router.campaign_mut().notice = Some("Plan approved. Launch remains separate.".into());
    reader.released.store(true, Ordering::Release);
    finish(&mut app);
    assert_eq!(app.router.campaign().selected_job().unwrap().job_id, "j2");
    assert_eq!(
        app.router.campaign().notice.as_deref(),
        Some("Plan approved. Launch remains separate.")
    );
}

#[test]
fn returning_to_the_list_during_loading_does_not_reopen_detail() {
    let (_root, mut app, reader) = controlled_app();
    app.open_campaign_view(Some("camp1".into()));
    wait_for_history(&mut app, &reader, 1);
    app.apply_campaign_hotkey(ViewHotkeyAction::CampaignBackToList);
    assert!(!app.router.campaign().detail);
    reader.released.store(true, Ordering::Release);
    finish(&mut app);
    assert!(!app.router.campaign().detail);
}

#[test]
fn an_older_history_completion_cannot_overwrite_a_newer_phase_projection() {
    let (_root, mut app, reader) = controlled_app();
    reader.capture_before_hold.store(true, Ordering::Release);
    app.refresh_campaign_deck();
    wait_for_history(&mut app, &reader, 1);
    app.engagement
        .set_phase_attempt_projection_health(None, Default::default(), true);
    let generation = app.engagement.phase_projection_generation();
    reader.released.store(true, Ordering::Release);
    finish(&mut app);
    assert_eq!(app.engagement.phase_projection_generation(), generation);
    assert!(app.engagement.phase_attempt_projection_is_degraded());
}

#[test]
fn history_persists_the_review_counts_accepted_before_its_read_is_admitted() {
    use kuzushi_core::capabilities::campaign::{trend::TrendMetrics, trend_history};
    let (root, mut app, reader) = controlled_app();
    reader.capture_before_hold.store(true, Ordering::Release);
    app.refresh_campaign_deck();
    // Install the projection that the pending ledger read was requested to refresh.
    app.runtime_state.findings_refresh.accept_projection();
    app.domain_mut().set_review_trend(TrendMetrics {
        decided_findings: 2,
        rejected_false_positives: 1,
        confirmed_findings: 1,
        ..Default::default()
    });
    app.schedule_pending_campaign_history();
    wait_until(|| reader.started.load(Ordering::Acquire) == 1);
    let rows = trend_history::load_trend_history(root.path(), trend_history::TREND_HISTORY_LIMIT);
    let recorded = rows
        .last()
        .expect("The current known counts must be retained");
    assert_eq!(recorded.decided_findings, 2);
    assert_eq!(recorded.rejected_false_positives, 1);
    reader.released.store(true, Ordering::Release);
    finish(&mut app);
}

#[test]
fn a_live_refresh_reads_in_the_background_and_never_restarts_an_inflight_read() {
    let (_root, mut app, reader) = controlled_app();
    app.router.campaign_mut().dispatcher_pid = Some(u32::MAX);
    let start = Instant::now();

    assert!(app.poll_live_campaign_progress(start));
    wait_for_history(&mut app, &reader, 1);
    assert!(app.campaign_history_loading());
    let later = start + Duration::from_secs(10);
    assert!(!app.poll_live_campaign_progress(later));
    assert_eq!(reader.canceled.load(Ordering::Acquire), 0);

    reader.released.store(true, Ordering::Release);
    finish(&mut app);
    assert!(app.poll_live_campaign_progress(later));
}
