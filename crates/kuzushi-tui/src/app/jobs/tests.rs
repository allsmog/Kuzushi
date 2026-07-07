use super::*;

#[test]
fn shell_event_reports_kind_and_terminal_state() {
    assert_eq!(
        ShellEvent::Trace(RunTraceStep::new(1, "reasoning", "step")).kind(),
        JobKind::Run
    );
    assert!(!ShellEvent::Scan(ScanEvent::Stage("running".to_string())).is_terminal());
    assert!(ShellEvent::Plan(PlanEvent::Failed {
        error: "nope".to_string()
    })
    .is_terminal());
}

#[test]
fn jobhub_drops_stale_events_per_kind() {
    let mut hub = JobHub::default();
    let old = hub.start(JobKind::Run, "old-tool");
    old.send(ShellEvent::Tool(ToolEvent::Failed {
        tool_name: "old-tool".to_string(),
        error: "old".to_string(),
    }));
    old.complete();

    let current = hub.start(JobKind::Run, "new-tool");
    current.send(ShellEvent::Tool(ToolEvent::Failed {
        tool_name: "new-tool".to_string(),
        error: "new".to_string(),
    }));
    current.complete();

    let events = hub.drain(8);
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        ShellEvent::Tool(ToolEvent::Failed { tool_name, error })
            if tool_name == "new-tool" && error == "new"
    ));
}

#[test]
fn jobhub_preserves_send_order_for_current_generation() {
    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Run, "scan");
    ticket.send(ShellEvent::Trace(RunTraceStep::new(
        1,
        "reasoning",
        "first",
    )));
    ticket.send(ShellEvent::Scan(ScanEvent::Stage("second".to_string())));
    ticket.complete();

    let events = hub.drain(8);
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[0], ShellEvent::Trace(step) if step.label == "first"));
    assert!(matches!(events[1], ShellEvent::Scan(ScanEvent::Stage(_))));
}

#[test]
fn jobhub_cancel_arms_slot_token() {
    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Agent, "agent");
    let cancel = ticket.cancel.clone();

    assert!(hub.is_running(JobKind::Agent));
    assert_eq!(hub.running_label(JobKind::Agent), Some("agent"));
    assert!(hub.cancel(JobKind::Agent));
    assert!(hub.cancel_requested(JobKind::Agent));
    assert!(cancel.is_cancelled());

    ticket.complete();
}

#[test]
fn job_ticket_exposes_identity_and_finish_clears_slot() {
    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Plan, "planner");

    assert_eq!(ticket.kind(), JobKind::Plan);
    assert_eq!(ticket.label(), "planner");
    assert!(hub.is_running(ticket.kind()));
    assert_eq!(hub.running_label(ticket.kind()), Some("planner"));

    hub.finish(ticket.kind());

    assert!(!hub.is_running(JobKind::Plan));
    assert!(!hub.cancel(JobKind::Plan));
    assert_ne!(ticket.generation(), WorkerGeneration::new(0));
    ticket.complete();
}

#[test]
fn job_ticket_rejects_wrong_kind_events() {
    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Plan, "planner");

    assert!(!ticket.send(ShellEvent::Threat(ThreatPatchEvent::Failed {
        error: "wrong".to_string()
    })));
    ticket.complete();
    assert!(hub.drain(8).is_empty());
}

#[test]
fn job_ticket_complete_disarms_panic_guard() {
    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Plan, "planner");
    ticket.send(ShellEvent::Plan(PlanEvent::Failed {
        error: "planned failure".to_string(),
    }));
    ticket.complete();

    let events = hub.drain(8);
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        ShellEvent::Plan(PlanEvent::Failed { error }) if error == "planned failure"
    ));
}

#[test]
fn panic_guard_synthesizes_failure_when_ticket_drops_armed() {
    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Threat, "threat model");
    drop(ticket);

    let events = hub.drain(8);
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        ShellEvent::Threat(ThreatPatchEvent::Failed { error })
            if error.contains("threat model worker ended without reporting completion")
    ));
}

#[test]
fn drain_releases_trace_budget_slots() {
    let mut hub = JobHub::default();
    let budget = hub.trace_budget();
    assert!(budget.reserve_for_test());
    let ticket = hub.start(JobKind::Run, "scan");
    ticket.send(ShellEvent::Trace(RunTraceStep::new(
        1,
        "reasoning",
        "reserved",
    )));
    ticket.complete();

    assert_eq!(budget.pending(), 1);
    assert_eq!(hub.drain(8).len(), 1);
    assert_eq!(budget.pending(), 0);
}
