use super::panic_safe::worker_panic_message;
use super::*;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[test]
fn spawn_panic_safe_worker_emits_stamped_failure_event() {
    let generation = WorkerGeneration::new(7);
    let (tx, rx) = std::sync::mpsc::channel();

    let handle = spawn_panic_safe_worker(
        "tool",
        tx,
        generation,
        None,
        || std::panic::resume_unwind(Box::new("boom")),
        |error| ToolEvent::Failed {
            tool_name: "semgrep:scan".to_string(),
            error,
        },
    );

    assert!(handle.join().is_ok());
    let event = rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(event.generation, generation);
    match event.payload {
        ToolEvent::Failed { tool_name, error } => {
            assert_eq!(tool_name, "semgrep:scan");
            assert_eq!(error, "tool worker panicked: boom");
        }
        ToolEvent::Finished { .. } => panic!("expected failure event"),
    }
}

#[test]
fn spawn_panic_safe_worker_notifies_terminal_loop_after_failure() {
    let generation = WorkerGeneration::new(8);
    let (tx, rx) = std::sync::mpsc::channel();
    let (inbox, wake) = TerminalLoopInbox::channel_for_test();

    let handle = spawn_panic_safe_worker(
        "agent",
        tx,
        generation,
        Some(wake),
        || std::panic::resume_unwind(Box::new("boom")),
        |error| AgentEvent::Failed {
            error,
            audit: AgentCallAudit::for_prompt("openai:gpt-test", ASK_SYSTEM_PROMPT, "wake"),
        },
    );

    assert!(handle.join().is_ok());
    let event = rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(event.generation, generation);
    assert!(matches!(event.payload, AgentEvent::Failed { .. }));
    assert!(matches!(
        inbox.recv_timeout(Duration::from_secs(1)).unwrap(),
        Some(TerminalLoopEvent::Wake)
    ));
}

#[test]
fn panic_message_handles_non_string_payloads() {
    let message = worker_panic_message("scan", Box::new(42usize));
    assert_eq!(message, "scan worker panicked: non-string panic payload");
}

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
    let cancel = ScanCancellation::default();
    let generation = WorkerGeneration::new(10);
    let mut config = V2Config::default();
    config.runtime.worker_watchdog_timeout_ms = Some(5);
    let mut app = ShellApp::new(config, None);
    app.tool_running = Some("semgrep:scan".to_string());
    app.tool_generation = Some(generation);
    app.tool_cancel = Some(cancel.clone());
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
    assert!(app.tool_abort_requested);
    assert_eq!(app.worker_handles.active_count(), 1);
    drop(tx);
    assert!(wait_for_app_handle_reap(&mut app));
}

#[test]
fn app_drain_reaps_finished_worker_handles() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.register_worker_handle("test", WorkerGeneration::new(9), std::thread::spawn(|| {}));

    assert!(wait_for_app_handle_reap(&mut app));
    assert_eq!(app.worker_handles.active_count(), 0);
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
