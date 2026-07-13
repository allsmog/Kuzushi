use super::*;

#[test]
fn shell_event_reports_kind_and_terminal_state() {
    assert_eq!(
        ShellEvent::Trace(RunTraceStep::new(1, "reasoning", "step")).kind(),
        JobKind::Run
    );
    assert!(!ShellEvent::Scan(ScanEvent::Stage("running".to_string())).is_terminal());
    assert!(ShellEvent::Plan(PlanEvent::Failed {
        error: "nope".to_string(),
        audit: AgentCallAudit::test(),
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
fn jobhub_try_start_preserves_the_single_live_job() {
    let mut hub = JobHub::default();
    let current = hub.try_start(JobKind::Run, "scan").unwrap();

    let conflict = match hub.try_start(JobKind::Plan, "planner") {
        Ok(ticket) => {
            ticket.complete();
            panic!("a second live job must be rejected");
        }
        Err(conflict) => conflict,
    };

    assert_eq!(conflict.kind, JobKind::Run);
    assert_eq!(conflict.label, "scan");
    assert!(hub.is_current_generation(JobKind::Run, current.generation()));
    assert!(!hub.is_running(JobKind::Plan));
    current.complete();
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
fn jobhub_drops_non_terminal_events_when_channel_is_full() {
    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Run, "scan");
    let mut accepted = 0;

    for index in 0..(super::hub::JOB_EVENT_CHANNEL_CAPACITY + 8) {
        if ticket.send(ShellEvent::Scan(ScanEvent::Stage(format!("stage-{index}")))) {
            accepted += 1;
        }
    }
    ticket.complete();

    assert_eq!(accepted, super::hub::JOB_EVENT_CHANNEL_CAPACITY);
    assert_eq!(
        hub.drain(super::hub::JOB_EVENT_CHANNEL_CAPACITY + 8).len(),
        super::hub::JOB_EVENT_CHANNEL_CAPACITY
    );
}

#[test]
fn jobhub_unresponsive_escalation_quarantines_slot_once_after_grace() {
    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Run, "hung:tool");
    let generation = ticket.generation();
    let now = std::time::Instant::now();

    // A stale generation must not arm the escalation.
    hub.schedule_unresponsive_escalation(JobKind::Run, WorkerGeneration::new(999), now);
    assert!(!hub.quarantine_unresponsive_slots(now + WORKER_UNRESPONSIVE_GRACE));

    hub.schedule_unresponsive_escalation(JobKind::Run, generation, now);
    assert!(!hub.quarantine_unresponsive_slots(now)); // grace not yet elapsed

    let after_grace = now + WORKER_UNRESPONSIVE_GRACE;
    assert!(hub.quarantine_unresponsive_slots(after_grace));
    assert!(!hub.quarantine_unresponsive_slots(after_grace)); // single-shot
    assert!(hub.is_quarantined(JobKind::Run));
    assert!(hub.has_running_job());
    assert!(hub.try_start(JobKind::Run, "next:tool").is_err());
    assert!(hub.drain(4).is_empty());
    ticket.complete();
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
        error: "wrong".to_string(),
        audit: AgentCallAudit::test(),
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
        audit: AgentCallAudit::test(),
    }));
    ticket.complete();

    let events = hub.drain(8);
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        ShellEvent::Plan(PlanEvent::Failed { error, .. }) if error == "planned failure"
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
        ShellEvent::Threat(ThreatPatchEvent::Failed { error, .. })
            if error.contains("threat model worker ended without reporting completion")
    ));
}

#[test]
fn spawn_job_worker_emits_failure_event_on_panic() {
    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Run, "semgrep:scan");
    let handle = spawn_job_worker("tool", ticket, |_sink, _cancel| {
        std::panic::resume_unwind(Box::new("boom"))
    });

    assert!(handle.join().is_ok());
    let events = hub.drain(8);
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        ShellEvent::Tool(ToolEvent::Failed { tool_name, error })
            if tool_name == "semgrep:scan" && error == "tool worker panicked: boom"
    ));
}

#[test]
fn spawn_job_worker_notifies_terminal_loop_after_failure() {
    let mut hub = JobHub::default();
    let (inbox, wake) = TerminalLoopInbox::channel_for_test();
    hub.set_wake(Some(wake));
    let ticket = hub.start(JobKind::Agent, "agent");
    let handle = spawn_job_worker("agent", ticket, |_sink, _cancel| {
        std::panic::resume_unwind(Box::new("boom"))
    });

    assert!(handle.join().is_ok());
    assert!(matches!(
        inbox.recv_timeout(Duration::from_secs(1)).unwrap(),
        Some(TerminalLoopEvent::Wake)
    ));
    assert!(matches!(
        hub.drain(8).pop(),
        Some(ShellEvent::Agent(AgentEvent::Failed { error, .. }))
            if error == "agent worker panicked: boom"
    ));
}

#[test]
fn spawn_job_worker_formats_non_string_panic_payloads() {
    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Plan, "planner");
    let handle = spawn_job_worker("planner", ticket, |_sink, _cancel| {
        std::panic::resume_unwind(Box::new(42usize))
    });

    assert!(handle.join().is_ok());
    assert!(matches!(
        hub.drain(8).pop(),
        Some(ShellEvent::Plan(PlanEvent::Failed { error, .. }))
            if error == "planner worker panicked: non-string panic payload"
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
