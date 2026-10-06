use super::*;
use crate::app::BatchScanConfig;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
struct DelayedUsageReader {
    entered: AtomicBool,
    completed: AtomicBool,
    released: Mutex<bool>,
    wake: Condvar,
}

impl DelayedUsageReader {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}

impl ViewArtifactReader for DelayedUsageReader {
    fn read(&self, _target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        if key == &ViewHydrationKey::StudyUsageCatalogue {
            self.entered.store(true, Ordering::Release);
            let _ = self
                .wake
                .wait_timeout_while(
                    self.released.lock().unwrap(),
                    Duration::from_secs(3),
                    |released| !*released,
                )
                .unwrap();
            self.completed.store(true, Ordering::Release);
        }
        tests::missing_value(key)
    }
}

fn wait_for(mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !check() {
        assert!(Instant::now() < deadline, "usage hydration timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn study_app(root: &Path) -> ShellApp {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.router.campaign_mut().batch_scan_config =
        Some(BatchScanConfig::load(root, Some("older-baseline")));
    app.set_shell_view(ShellView::Campaign);
    app.set_input_mode(InputMode::Navigate);
    app
}

fn study_config_mut(app: &mut ShellApp) -> &mut BatchScanConfig {
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
}

#[test]
fn study_usage_open_navigation_and_cancel_stay_responsive_during_slow_read() {
    let root = tempfile::tempdir().unwrap();
    let reader = Arc::new(DelayedUsageReader::default());
    let mut app = study_app(root.path());
    app.set_view_artifact_reader_for_test(reader.clone());
    app.schedule_active_view_hydration();
    wait_for(|| reader.entered.load(Ordering::Acquire));
    let before = Instant::now();
    assert!(app
        .handle_batch_config_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE))
        .is_some());
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .cursor,
        1
    );
    assert!(app
        .handle_batch_config_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .is_some());
    assert!(before.elapsed() < Duration::from_millis(500));
    assert!(app.router.campaign().batch_scan_config.is_none());
    let view = app.shell_view();
    reader.release();
    wait_for(|| reader.completed.load(Ordering::Acquire));
    app.apply_view_hydration_results();
    assert_eq!(app.shell_view(), view);
}

#[test]
fn target_change_discards_old_usage_completion_and_cancelled_refresh_generation() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let reader = Arc::new(DelayedUsageReader::default());
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(reader.clone());
    runtime.schedule(
        first.path().into(),
        vec![ViewHydrationKey::StudyUsageCatalogue],
        None,
    );
    wait_for(|| reader.entered.load(Ordering::Acquire));
    runtime.invalidate();
    runtime.schedule(
        second.path().into(),
        vec![ViewHydrationKey::StudyUsageRun {
            run_id: "current-baseline".into(),
        }],
        None,
    );
    reader.release();
    wait_for(|| runtime.workers_finished());
    let drain = runtime.drain_current();
    assert_eq!(drain.results.len(), 1);
    assert_eq!(drain.results[0].target, second.path());
    assert!(matches!(
        drain.results[0].key,
        ViewHydrationKey::StudyUsageRun { .. }
    ));
}

#[test]
fn usage_completion_preserves_selection_focus_draft_and_allowance() {
    let root = tempfile::tempdir().unwrap();
    let mut app = study_app(root.path());
    let config = study_config_mut(&mut app);
    config.cursor = 7;
    config.detail_scroll = 6;
    config.study.max_provider_calls = Some(8);
    config.study.protected_review_calls = Some(2);
    let before = config.clone();
    let view = app.shell_view();
    let mode = app.input_mode();
    app.apply_view_hydration_drain(catalogue_drain(root.path()));
    let after = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(
        (
            after.cursor,
            after.detail_scroll,
            &after.prior_run_id,
            &after.study
        ),
        (
            before.cursor,
            before.detail_scroll,
            &before.prior_run_id,
            &before.study
        )
    );
    assert!(after.selected_prior().is_some());
    assert_eq!((app.shell_view(), app.input_mode()), (view, mode));
    assert!(
        crate::ui_view_models::study_config::study_resource_lines(after)
            .join("\n")
            .contains("most recent 100")
    );
}

fn catalogue_drain(root: &Path) -> ViewHydrationDrain {
    ViewHydrationDrain {
        results: vec![ViewHydrationResult {
            target: root.into(),
            key: ViewHydrationKey::StudyUsageCatalogue,
            value: ViewHydrationValue::StudyUsageCatalogue(Ok(
                kuzushi_core::capabilities::campaign::ScanUsageCatalogue {
                    run_ids: vec!["newer-run".into()],
                    inspected_entries: 100,
                    history_limit_reached: true,
                },
            )),
        }],
        failures: vec![],
    }
}

#[test]
fn stale_named_usage_cannot_change_the_new_selection() {
    let root = tempfile::tempdir().unwrap();
    let mut app = study_app(root.path());
    study_config_mut(&mut app).apply_usage_catalogue(ViewDataState::Ready(Ok(
        kuzushi_core::capabilities::campaign::ScanUsageCatalogue {
            run_ids: vec!["newer-run".into()],
            inspected_entries: 1,
            history_limit_reached: false,
        },
    )));
    study_config_mut(&mut app).cycle_prior_run();
    study_config_mut(&mut app).cycle_prior_run();
    app.apply_view_hydration_drain(ViewHydrationDrain {
        results: vec![ViewHydrationResult {
            target: root.path().into(),
            key: ViewHydrationKey::StudyUsageRun {
                run_id: "older-baseline".into(),
            },
            value: ViewHydrationValue::StudyUsageRun(Err("stale result".into())),
        }],
        failures: vec![],
    });
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.prior_run_id.as_deref(), Some("newer-run"));
    assert_eq!(
        config.selected_prior().unwrap().evidence,
        ViewDataState::NotRequested
    );
}

#[test]
fn failed_usage_reader_is_honest_and_waits_for_explicit_refresh() {
    let root = tempfile::tempdir().unwrap();
    let mut app = study_app(root.path());
    let key = ViewHydrationKey::StudyUsageRun {
        run_id: "older-baseline".into(),
    };
    app.apply_view_hydration_drain(ViewHydrationDrain {
        results: vec![],
        failures: vec![ViewHydrationFailure {
            target: root.path().into(),
            key: key.clone(),
        }],
    });
    assert!(!app
        .workbench_cache()
        .borrow()
        .view_hydration_needed(root.path(), &key));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(
        crate::ui_view_models::study_config::study_resource_lines(config)
            .join("\n")
            .contains("Usage reader failed")
    );
    app.invalidate_view_hydration();
    app.workbench_cache()
        .borrow_mut()
        .invalidate_study_usage(root.path());
    assert!(app
        .workbench_cache()
        .borrow()
        .view_hydration_needed(root.path(), &key));
}

#[test]
fn loading_study_configuration_does_not_touch_missing_target_or_create_storage() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("missing-source");
    let config = BatchScanConfig::load(&target, Some("baseline"));
    assert!(!target.exists());
    assert_eq!(config.prior_run_id.as_deref(), Some("baseline"));
    assert_eq!(
        config.selected_prior().unwrap().evidence,
        ViewDataState::NotRequested
    );
    assert!(config
        .resource_projection()
        .unwrap_err()
        .contains("loading"));
}
