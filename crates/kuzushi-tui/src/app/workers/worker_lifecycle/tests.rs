use super::*;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[test]
fn worker_handle_registry_reaps_finished_handles() {
    let mut registry = WorkerHandleRegistry::default();
    registry.register("test", WorkerGeneration::new(3), std::thread::spawn(|| {}));

    let finished = wait_for_finished_handles(&mut registry);

    assert_eq!(
        finished,
        vec![FinishedWorkerHandle {
            label: "test",
            generation: WorkerGeneration::new(3),
            panicked: false,
        }]
    );
    assert_eq!(registry.active_count(), 0);
}

#[test]
fn worker_handle_registry_keeps_running_handles() {
    let (tx, rx) = mpsc::channel::<()>();
    let mut registry = WorkerHandleRegistry::default();
    registry.register(
        "blocked",
        WorkerGeneration::new(4),
        std::thread::spawn(move || {
            let _ = rx.recv();
        }),
    );

    assert!(registry.reap_finished().is_empty());
    assert_eq!(registry.active_count(), 1);
    drop(tx);

    let finished = wait_for_finished_handles(&mut registry);

    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].label, "blocked");
    assert_eq!(registry.active_count(), 0);
}

#[test]
fn worker_handle_registry_cancels_timed_out_handles_once() {
    let (tx, rx) = mpsc::channel::<()>();
    let cancel = ScanCancellation::default();
    let mut registry = WorkerHandleRegistry::default();
    registry.register_with_watchdog(
        "blocked",
        WorkerGeneration::new(5),
        std::thread::spawn(move || {
            let _ = rx.recv();
        }),
        Some(WorkerWatchdog::new(
            cancel.clone(),
            Duration::from_millis(5),
        )),
    );

    assert!(registry.cancel_timed_out(Instant::now()).is_empty());
    std::thread::sleep(Duration::from_millis(15));
    let timed_out = registry.cancel_timed_out(Instant::now());

    assert_eq!(timed_out.len(), 1);
    assert_eq!(timed_out[0].label, "blocked");
    assert!(cancel.is_cancelled());
    assert_eq!(registry.active_count(), 1);
    assert!(registry.cancel_timed_out(Instant::now()).is_empty());
    drop(tx);
    assert_eq!(wait_for_finished_handles(&mut registry).len(), 1);
}

#[test]
fn app_drain_marks_timed_out_tool_abort_requested() {
    let (tx, rx) = mpsc::channel::<()>();
    let mut config = V2Config::default();
    config.runtime.worker_watchdog_timeout_ms = Some(5);
    let mut app = ShellApp::new(config, None);
    let ticket = app.jobs_mut().start(JobKind::Run, "semgrep:scan");
    let generation = ticket.generation();
    let cancel = ticket.cancel.clone();
    app.set_running_tool_for_test("semgrep:scan");
    app.set_tool_cancel_for_test(cancel.clone());
    app.register_worker_handle_with_watchdog(
        "tool",
        generation,
        std::thread::spawn(move || {
            let _ = rx.recv();
        }),
        cancel.clone(),
    );

    std::thread::sleep(Duration::from_millis(15));

    assert!(app.drain_background_events());
    assert!(cancel.is_cancelled());
    assert!(app.tool_abort_requested());
    assert_eq!(app.worker_handle_active_count_for_test(), 1);
    drop(tx);
    assert!(wait_for_app_handle_reap(&mut app));
}

#[test]
fn unresponsive_worker_quarantines_job_after_grace() {
    let (tx, rx) = mpsc::channel::<()>();
    let mut config = V2Config::default();
    config.runtime.worker_watchdog_timeout_ms = Some(5);
    let mut app = ShellApp::new(config, None);
    let ticket = app.jobs_mut().start(JobKind::Run, "semgrep:scan");
    let generation = ticket.generation();
    let cancel = ticket.cancel.clone();
    app.set_running_tool_for_test("semgrep:scan");
    app.set_tool_cancel_for_test(cancel.clone());
    app.register_worker_handle_with_watchdog(
        "tool",
        generation,
        std::thread::spawn(move || {
            // Simulates a worker blocked in a syscall: never polls the token,
            // never emits a terminal event.
            let _ = rx.recv();
        }),
        cancel.clone(),
    );

    std::thread::sleep(Duration::from_millis(15));

    // Watchdog fires: cooperative cancel requested, but the worker ignores it,
    // so the slot stays lit and overlap-reject would block all new work.
    assert!(app.drain_background_events());
    assert!(cancel.is_cancelled());
    assert!(app.has_running_work());
    assert!(app.jobs().is_running(JobKind::Run));

    // Before the grace window elapses, quarantine is not armed.
    assert!(!app.jobs_mut().quarantine_unresponsive_slots(Instant::now()));
    assert!(app.has_running_work());

    // Grace elapses with still no terminal event: quarantine keeps exclusive
    // ownership because the OS thread can still perform side effects.
    let after_grace = Instant::now() + WORKER_UNRESPONSIVE_GRACE;
    assert!(app.jobs_mut().quarantine_unresponsive_slots(after_grace));
    assert!(app.has_running_work());
    assert!(app.jobs().is_running(JobKind::Run));
    assert!(app.jobs().is_quarantined(JobKind::Run));
    assert!(app.jobs_mut().try_start(JobKind::Run, "next:tool").is_err());

    // Once the worker truly exits, its guard emits the real terminal event
    // and the slot is released through the normal job-event path.
    drop(tx);
    assert!(wait_for_app_handle_reap(&mut app));
    assert!(app.has_running_work());
    drop(ticket);
    assert!(app.drain_background_events());
    assert!(!app.has_running_work());
}

#[test]
fn app_drain_reaps_finished_worker_handles() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.register_worker_handle("test", WorkerGeneration::new(9), std::thread::spawn(|| {}));

    assert!(wait_for_app_handle_reap(&mut app));
    assert_eq!(app.worker_handle_active_count_for_test(), 0);
}

fn wait_for_finished_handles(registry: &mut WorkerHandleRegistry) -> Vec<FinishedWorkerHandle> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let finished = registry.reap_finished();
        if !finished.is_empty() || Instant::now() >= deadline {
            return finished;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_app_handle_reap(app: &mut ShellApp) -> bool {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if app.drain_background_events() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
