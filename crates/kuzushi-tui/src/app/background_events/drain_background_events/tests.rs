use super::runtime_event_drains::{JOB_DRAIN_LIMIT, TRACE_DRAIN_LIMIT};
use super::*;
use std::sync::mpsc;

fn stamped_channel<T>() -> (
    WorkerGeneration,
    mpsc::Sender<StampedEvent<T>>,
    mpsc::Receiver<StampedEvent<T>>,
) {
    let generation = WorkerGeneration::new(1);
    let (tx, rx) = mpsc::channel();
    (generation, tx, rx)
}

fn send_stamped<T>(tx: &mpsc::Sender<StampedEvent<T>>, generation: WorkerGeneration, payload: T) {
    tx.send(StampedEvent::new(generation, payload)).unwrap();
}

#[test]
fn disconnected_tool_channel_synthesizes_failure_and_clears_liveness() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (generation, tx, rx) = stamped_channel::<ToolEvent>();
    drop(tx);
    app.tool_generation = Some(generation);
    app.tool_rx = Some(rx);
    app.tool_running = Some("semgrep:scan".to_string());

    assert!(app.drain_tool_events());

    assert!(app.tool_running.is_none());
    assert!(app.tool_rx.is_none());
    assert!(app.log.iter().any(|line| {
        line.body
            .contains("tool worker disconnected before reporting completion")
    }));
}

#[test]
fn terminal_tool_event_followed_by_disconnect_does_not_synthesize_failure() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (generation, tx, rx) = stamped_channel::<ToolEvent>();
    send_stamped(
        &tx,
        generation,
        ToolEvent::Finished {
            tool_name: "semgrep:scan".to_string(),
            result: serde_json::json!({ "output": "scan complete" }),
        },
    );
    drop(tx);
    app.tool_generation = Some(generation);
    app.tool_rx = Some(rx);
    app.tool_running = Some("semgrep:scan".to_string());

    assert!(app.drain_tool_events());

    assert!(app.tool_running.is_none());
    assert!(app.tool_rx.is_none());
    assert!(!app.log.iter().any(|line| line
        .body
        .contains("tool worker disconnected before reporting completion")));
}

#[test]
fn panic_tool_failure_event_clears_guard_without_disconnect_synthesis() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (generation, tx, rx) = stamped_channel::<ToolEvent>();
    send_stamped(
        &tx,
        generation,
        ToolEvent::Failed {
            tool_name: "semgrep:scan".to_string(),
            error: "tool worker panicked: boom".to_string(),
        },
    );
    drop(tx);
    app.tool_generation = Some(generation);
    app.tool_rx = Some(rx);
    app.tool_running = Some("semgrep:scan".to_string());

    assert!(app.drain_tool_events());

    assert!(app.tool_running.is_none());
    assert!(app.tool_rx.is_none());
    assert!(app
        .log
        .iter()
        .any(|line| line.body.contains("tool worker panicked: boom")));
    assert!(!app.log.iter().any(|line| {
        line.body
            .contains("tool worker disconnected before reporting completion")
    }));
}

#[test]
fn stale_tool_event_is_discarded_without_clearing_current_guard() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (generation, tx, rx) = stamped_channel::<ToolEvent>();
    send_stamped(
        &tx,
        WorkerGeneration::new(999),
        ToolEvent::Finished {
            tool_name: "semgrep:scan".to_string(),
            result: serde_json::json!({ "output": "stale complete" }),
        },
    );
    app.tool_generation = Some(generation);
    app.tool_rx = Some(rx);
    app.tool_running = Some("semgrep:scan".to_string());

    assert!(!app.drain_tool_events());

    assert_eq!(app.tool_running.as_deref(), Some("semgrep:scan"));
    assert!(app.tool_rx.is_some());
    assert!(!app
        .log
        .iter()
        .any(|line| line.body.contains("stale complete")));
    drop(tx);
}

#[test]
fn stale_then_current_tool_events_apply_only_current_generation() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (generation, tx, rx) = stamped_channel::<ToolEvent>();
    send_stamped(
        &tx,
        WorkerGeneration::new(999),
        ToolEvent::Finished {
            tool_name: "semgrep:scan".to_string(),
            result: serde_json::json!({ "output": "stale complete" }),
        },
    );
    send_stamped(
        &tx,
        generation,
        ToolEvent::Finished {
            tool_name: "semgrep:scan".to_string(),
            result: serde_json::json!({ "output": "current complete" }),
        },
    );
    drop(tx);
    app.tool_generation = Some(generation);
    app.tool_rx = Some(rx);
    app.tool_running = Some("semgrep:scan".to_string());

    assert!(app.drain_tool_events());

    assert!(app.tool_running.is_none());
    assert!(app
        .log
        .iter()
        .any(|line| line.body.contains("current complete")));
    assert!(!app
        .log
        .iter()
        .any(|line| line.body.contains("stale complete")));
}

#[test]
fn disconnected_plan_channel_synthesizes_failure_and_clears_liveness() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (generation, tx, rx) = stamped_channel::<PlanEvent>();
    drop(tx);
    app.plan_generation = Some(generation);
    app.plan_rx = Some(rx);
    app.planner_running = true;

    assert!(app.drain_plan_events());

    assert!(!app.planner_running);
    assert!(app.plan_rx.is_none());
    assert!(app.log.iter().any(|line| {
        line.body
            .contains("planner worker disconnected before reporting completion")
    }));
}

#[test]
fn disconnected_scan_channel_synthesizes_failure_and_clears_liveness() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (generation, tx, rx) = stamped_channel::<ScanEvent>();
    drop(tx);
    app.scan_generation = Some(generation);
    app.scan_rx = Some(rx);
    app.scan = Some(ScanPanelState {
        run_id: None,
        target: std::path::PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });

    assert!(app.drain_scan_events());

    let scan = app.scan.as_ref().expect("scan state should remain visible");
    assert!(!scan.running);
    assert!(app.scan_rx.is_none());
    assert!(scan
        .error
        .as_deref()
        .is_some_and(|error| error.contains("scan worker disconnected")));
}

#[test]
fn disconnected_agent_channel_synthesizes_failure_and_clears_liveness() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (generation, tx, rx) = stamped_channel::<AgentEvent>();
    drop(tx);
    let mut agent = AgentChatView::default();
    agent.question = "what next?".to_string();
    agent.running = true;
    app.agent_chat = Some(agent);
    app.agent_generation = Some(generation);
    app.agent_rx = Some(rx);

    assert!(app.drain_agent_events());

    let agent = app
        .agent_chat
        .as_ref()
        .expect("agent chat state should remain visible");
    assert!(!agent.running);
    assert!(app.agent_rx.is_none());
    assert!(agent
        .error
        .as_deref()
        .is_some_and(|error| error.contains("agent worker disconnected")));
}

#[test]
fn disconnected_threat_channel_synthesizes_failure_and_clears_liveness() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (generation, tx, rx) = stamped_channel::<ThreatPatchEvent>();
    drop(tx);
    app.threat_generation = Some(generation);
    app.threat_rx = Some(rx);
    app.threat_worker_running = true;

    assert!(app.drain_threat_events());

    assert!(!app.threat_worker_running);
    assert!(app.threat_rx.is_none());
    assert!(app.log.iter().any(|line| {
        line.body
            .contains("threat model worker disconnected before reporting completion")
    }));
}

#[test]
fn trace_receiver_stays_installed_while_other_work_is_running() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (generation, tx, rx) = stamped_channel::<RunTraceStep>();
    app.trace_generation = Some(generation);
    app.trace_rx = Some(rx);
    app.planner_running = true;

    assert!(!app.drain_trace_events());
    assert!(app.trace_rx.is_some());

    drop(tx);
    assert!(app.drain_trace_events());
    assert!(app.trace_rx.is_none());
}

#[test]
fn trace_drain_is_budgeted_and_keeps_buffered_tail() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (generation, tx, rx) = stamped_channel::<RunTraceStep>();
    for i in 0..(TRACE_DRAIN_LIMIT + 5) {
        send_stamped(
            &tx,
            generation,
            RunTraceStep::new(i + 1, "tool", format!("event {i}"))
                .with_module_id("semgrep")
                .with_verb("scan"),
        );
    }
    drop(tx);
    app.trace_generation = Some(generation);
    app.trace_rx = Some(rx);

    assert!(app.drain_trace_events());
    assert_eq!(
        app.activity.as_ref().unwrap().events.len(),
        TRACE_DRAIN_LIMIT
    );
    assert!(app.trace_rx.is_some());

    assert!(app.drain_trace_events());
    assert_eq!(
        app.activity.as_ref().unwrap().events.len(),
        TRACE_DRAIN_LIMIT + 5
    );
    assert!(app.trace_rx.is_none());
}

#[test]
fn stale_trace_step_is_discarded() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (generation, tx, rx) = stamped_channel::<RunTraceStep>();
    send_stamped(
        &tx,
        WorkerGeneration::new(999),
        RunTraceStep::new(1, "tool", "stale tail")
            .with_module_id("semgrep")
            .with_verb("scan"),
    );
    app.trace_generation = Some(generation);
    app.trace_rx = Some(rx);

    assert!(!app.drain_trace_events());

    assert!(app.activity.is_none());
    assert!(app.trace_rx.is_none());
    assert!(app.trace_generation.is_none());
    drop(tx);
}

#[test]
fn job_drain_preserves_trace_terminal_order() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs.start(JobKind::Run, "semgrep:scan");
    let budget = app.jobs.trace_budget();
    assert!(budget.reserve_for_test());
    ticket.send(ShellEvent::Trace(
        RunTraceStep::new(1, "tool", "ordered trace")
            .with_module_id("semgrep")
            .with_verb("scan"),
    ));
    ticket.send(ShellEvent::Tool(ToolEvent::Failed {
        tool_name: "semgrep:scan".to_string(),
        error: "tool failed".to_string(),
    }));
    app.tool_generation = Some(ticket.generation());
    app.trace_generation = Some(ticket.generation());
    app.tool_running = Some("semgrep:scan".to_string());
    app.activity = Some(ActivitySession::new("r-1"));

    assert!(app.drain_job_events());

    let labels = app
        .activity
        .as_ref()
        .unwrap()
        .events
        .iter()
        .map(|event| event.step.label.as_str())
        .collect::<Vec<_>>();
    assert_eq!(labels, vec!["ordered trace", "tool failed"]);
    assert_eq!(budget.pending(), 0);
    assert!(!app.jobs.is_running(JobKind::Run));
}

#[test]
fn job_drain_does_not_finish_tool_slot_on_scan_terminal_event() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs.start(JobKind::Run, "sast:scan");
    ticket.send(ShellEvent::Scan(ScanEvent::Finished {
        run_id: "run-1".to_string(),
        findings_count: 0,
        cost_usd: None,
    }));
    app.tool_generation = Some(ticket.generation());
    app.tool_running = Some("sast:scan".to_string());

    assert!(app.drain_job_events());

    assert_eq!(app.tool_running.as_deref(), Some("sast:scan"));
    assert!(app.jobs.is_running(JobKind::Run));

    ticket.send(ShellEvent::Tool(ToolEvent::Finished {
        tool_name: "sast:scan".to_string(),
        result: serde_json::json!({ "output": "tool complete" }),
    }));

    assert!(app.drain_job_events());

    assert!(app.tool_running.is_none());
    assert!(!app.jobs.is_running(JobKind::Run));
}

#[test]
fn job_drain_finishes_scan_slot_on_scan_terminal_event() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs.start(JobKind::Run, "scan");
    ticket.send(ShellEvent::Scan(ScanEvent::Finished {
        run_id: "run-1".to_string(),
        findings_count: 0,
        cost_usd: None,
    }));
    app.scan_generation = Some(ticket.generation());
    app.scan = Some(ScanPanelState {
        run_id: None,
        target: std::path::PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });

    assert!(app.drain_job_events());

    assert!(!app.scan.as_ref().unwrap().running);
    assert!(!app.jobs.is_running(JobKind::Run));
}

#[test]
fn job_drain_is_budgeted_and_keeps_buffered_tail() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs.start(JobKind::Run, "semgrep:scan");
    let budget = app.jobs.trace_budget();
    for i in 0..(JOB_DRAIN_LIMIT + 5) {
        assert!(budget.reserve_for_test());
        ticket.send(ShellEvent::Trace(
            RunTraceStep::new(i + 1, "tool", format!("event {i}"))
                .with_module_id("semgrep")
                .with_verb("scan"),
        ));
    }
    app.trace_generation = Some(ticket.generation());
    app.activity = Some(ActivitySession::new("r-1"));

    assert!(app.drain_job_events());
    assert_eq!(app.activity.as_ref().unwrap().events.len(), JOB_DRAIN_LIMIT);
    assert_eq!(budget.pending(), 5);
    assert!(app.jobs.is_running(JobKind::Run));

    assert!(app.drain_job_events());
    assert_eq!(
        app.activity.as_ref().unwrap().events.len(),
        JOB_DRAIN_LIMIT + 5
    );
    assert_eq!(budget.pending(), 0);
    assert!(app.jobs.is_running(JobKind::Run));
}

#[test]
fn stale_job_tool_event_is_discarded_without_clearing_current_guard() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let stale = app.jobs.start(JobKind::Run, "old-tool");
    let current = app.jobs.start(JobKind::Run, "semgrep:scan");
    stale.send(ShellEvent::Tool(ToolEvent::Finished {
        tool_name: "semgrep:scan".to_string(),
        result: serde_json::json!({ "output": "stale complete" }),
    }));
    app.tool_generation = Some(current.generation());
    app.tool_running = Some("semgrep:scan".to_string());

    assert!(!app.drain_job_events());

    assert_eq!(app.tool_running.as_deref(), Some("semgrep:scan"));
    assert!(app.jobs.is_running(JobKind::Run));
    assert!(!app
        .log
        .iter()
        .any(|line| line.body.contains("stale complete")));
}

#[test]
fn stale_job_trace_step_releases_budget_without_activity_update() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let stale = app.jobs.start(JobKind::Run, "old-tool");
    let current = app.jobs.start(JobKind::Run, "semgrep:scan");
    let budget = app.jobs.trace_budget();
    assert!(budget.reserve_for_test());
    stale.send(ShellEvent::Trace(
        RunTraceStep::new(1, "tool", "stale trace")
            .with_module_id("semgrep")
            .with_verb("scan"),
    ));
    app.trace_generation = Some(current.generation());

    assert!(!app.drain_job_events());

    assert_eq!(budget.pending(), 0);
    assert!(app.activity.is_none());
    assert!(app.jobs.is_running(JobKind::Run));
}

#[test]
fn background_drain_applies_trace_before_terminal_tool_event() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (tool_generation, tool_tx, tool_rx) = stamped_channel::<ToolEvent>();
    send_stamped(
        &tool_tx,
        tool_generation,
        ToolEvent::Failed {
            tool_name: "semgrep:scan".to_string(),
            error: "tool failed".to_string(),
        },
    );
    drop(tool_tx);

    let (trace_generation, trace_tx, trace_rx) = stamped_channel::<RunTraceStep>();
    send_stamped(
        &trace_tx,
        trace_generation,
        RunTraceStep::new(1, "tool", "producer tail")
            .with_module_id("semgrep")
            .with_verb("scan"),
    );
    drop(trace_tx);

    app.tool_generation = Some(tool_generation);
    app.tool_rx = Some(tool_rx);
    app.trace_generation = Some(trace_generation);
    app.trace_rx = Some(trace_rx);
    app.tool_running = Some("semgrep:scan".to_string());
    app.activity = Some(ActivitySession::new("r-1"));

    assert!(app.drain_background_events());

    let labels = app
        .activity
        .as_ref()
        .unwrap()
        .events
        .iter()
        .map(|event| event.step.label.as_str())
        .collect::<Vec<_>>();
    assert_eq!(labels, vec!["producer tail", "tool failed"]);
}

#[test]
fn direct_tool_drain_flushes_trace_before_terminal_event() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let (tool_generation, tool_tx, tool_rx) = stamped_channel::<ToolEvent>();
    send_stamped(
        &tool_tx,
        tool_generation,
        ToolEvent::Failed {
            tool_name: "semgrep:scan".to_string(),
            error: "tool failed".to_string(),
        },
    );
    drop(tool_tx);

    let (trace_generation, trace_tx, trace_rx) = stamped_channel::<RunTraceStep>();
    send_stamped(
        &trace_tx,
        trace_generation,
        RunTraceStep::new(1, "tool", "late producer tail")
            .with_module_id("semgrep")
            .with_verb("scan"),
    );
    drop(trace_tx);

    app.tool_generation = Some(tool_generation);
    app.tool_rx = Some(tool_rx);
    app.trace_generation = Some(trace_generation);
    app.trace_rx = Some(trace_rx);
    app.tool_running = Some("semgrep:scan".to_string());
    app.activity = Some(ActivitySession::new("r-1"));

    assert!(app.drain_tool_events());

    let labels = app
        .activity
        .as_ref()
        .unwrap()
        .events
        .iter()
        .map(|event| event.step.label.as_str())
        .collect::<Vec<_>>();
    assert_eq!(labels, vec!["late producer tail", "tool failed"]);
}
