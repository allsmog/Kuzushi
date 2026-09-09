use super::*;

#[test]
fn shell_event_reports_kind_and_terminal_state() {
    assert_eq!(
        ShellEvent::RunItem(test_run_item(1, "step")).kind(),
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
fn planner_sink_accepts_only_cross_kind_operator_interactions() {
    use crate::app::operator_questions::{
        OperatorQuestion, OperatorQuestionEnvelope, OperatorQuestionOption, OperatorQuestionRequest,
    };
    use std::sync::mpsc::sync_channel;

    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Plan, "planner");
    let (control, _responses) = sync_channel(1);
    let question = OperatorQuestionEnvelope {
        request: OperatorQuestionRequest {
            request_id: "q-1".to_string(),
            run_id: "run-1".to_string(),
            questions: vec![OperatorQuestion {
                id: "scope".to_string(),
                header: "Scope".to_string(),
                prompt: "What should be scanned?".to_string(),
                options: vec![
                    OperatorQuestionOption {
                        label: "Changed".to_string(),
                        description: "Only changed files".to_string(),
                        recommended: true,
                    },
                    OperatorQuestionOption {
                        label: "All".to_string(),
                        description: "The whole repository".to_string(),
                        recommended: false,
                    },
                ],
            }],
            auto_resolution_ms: None,
        },
        generation: ticket.generation(),
        control,
    };

    assert!(ticket.send(ShellEvent::OperatorQuestion(question)));
    assert!(!ticket.send(ShellEvent::Agent(AgentEvent::Failed {
        error: "wrong worker kind".to_string(),
        audit: AgentCallAudit::test(),
    })));
    ticket.complete();

    assert!(matches!(
        hub.drain(2).as_slice(),
        [ShellEvent::OperatorQuestion(_)]
    ));
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
fn read_only_agent_is_the_only_authorized_pairing() {
    let mut hub = JobHub::default();
    let run = hub.start(JobKind::Run, "scan");
    let agent = hub
        .try_start_read_only_agent_alongside_run("read-only Ask")
        .unwrap();

    assert!(hub.is_running(JobKind::Run));
    assert!(hub.is_running(JobKind::Agent));
    assert!(hub.try_start(JobKind::Plan, "planner").is_err());
    assert!(hub
        .try_start_read_only_agent_alongside_run("second Ask")
        .is_err());
    run.complete();
    agent.complete();
}

#[test]
fn read_only_agent_requires_a_run_and_refuses_other_job_kinds() {
    for kind in [JobKind::Agent, JobKind::Plan, JobKind::Threat] {
        let mut hub = JobHub::default();
        assert!(hub.try_start_read_only_agent_alongside_run("Ask").is_err());
        let active = hub.start(kind, "active");
        assert!(hub.try_start_read_only_agent_alongside_run("Ask").is_err());
        active.complete();
    }
}

#[test]
fn jobhub_preserves_send_order_for_current_generation() {
    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Run, "scan");
    ticket.send(ShellEvent::RunItem(test_run_item(1, "first")));
    ticket.send(ShellEvent::Scan(ScanEvent::Stage("second".to_string())));
    ticket.complete();

    let events = hub.drain(8);
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[0], ShellEvent::RunItem(item)
        if matches!(&item.item, kuzushi_core::run_lifecycle::RunItemV1::DiagnosticNotice { message, .. }
            if message.as_str() == "first")));
    assert!(matches!(events[1], ShellEvent::Scan(ScanEvent::Stage(_))));
}

#[test]
fn job_sink_publishes_only_structured_run_item_writer_faults() {
    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Run, "scan");
    let fault = kuzushi_core::run_lifecycle::RunItemWriterFault {
        stage: kuzushi_core::run_lifecycle::PersistenceFailureStage::Sync,
        last_durable_seq: 3,
        detail: kuzushi_core::run_lifecycle::SafeText::operator_visible("sync failed"),
        execution_may_have_occurred: false,
    };
    let error = anyhow::Error::new(fault.clone()).context("terminal settlement failed");

    assert!(ticket
        .sink()
        .publish_run_item_writer_error("run-3", &error, true));
    assert!(!ticket.sink().publish_run_item_writer_error(
        "run-3",
        &anyhow::anyhow!("unrelated"),
        false
    ));
    ticket.complete();

    assert!(matches!(
        hub.drain(2).as_slice(),
        [ShellEvent::RunItemsFault { run_id, fault: delivered }]
            if run_id == "run-3"
                && delivered.execution_may_have_occurred
                && delivered.detail.as_str().contains("do not retry automatically")
    ));
}

#[test]
fn job_sink_routes_structured_delivery_faults_as_reliable_lifecycle_events() {
    let mut hub = JobHub::default();
    let ticket = hub.start(JobKind::Run, "scan");
    let (_, _, _, report_fault) = ticket.sink().run_lifecycle_subscribers("run-delivery");
    report_fault(kuzushi_core::run_lifecycle::RunItemDeliveryFault {
        stage: kuzushi_core::run_lifecycle::RunItemDeliveryFailureStage::ReadStream,
        applied_seq: 2,
        durable_seq: 4,
        detail: kuzushi_core::run_lifecycle::SafeText::operator_visible("read failed"),
    });
    ticket.complete();

    assert!(matches!(
        hub.drain(1).as_slice(),
        [ShellEvent::RunItemsDeliveryFault { run_id, fault }]
            if run_id == "run-delivery"
                && fault.applied_seq == 2
                && fault.durable_seq == 4
    ));
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
fn jobhub_names_the_one_live_job_without_being_told_its_kind() {
    // A stop request knows only "something is running"; the hub is globally
    // exclusive, so it can still name it.
    let mut hub = JobHub::default();
    assert_eq!(hub.live_job_label(), None);

    let ticket = hub.start(JobKind::Run, "taint-iris:hunt");
    assert_eq!(hub.live_job_label(), Some("taint-iris:hunt"));

    hub.finish(ticket.kind());
    assert_eq!(hub.live_job_label(), None);
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

fn test_run_item(seq: u64, message: &str) -> kuzushi_core::run_lifecycle::RunItemEnvelopeV1 {
    use kuzushi_core::run_lifecycle::{
        DiagnosticLevel, RunId, RunItemEnvelopeV1, RunItemId, RunItemSource, RunItemV1, SafeText,
    };
    RunItemEnvelopeV1::new(
        seq,
        RunId::parse("run-jobs-test").unwrap(),
        RunItemId::new(),
        RunItemSource::Workflow,
        RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Info,
            message: SafeText::operator_visible(message),
        },
        None,
    )
    .unwrap()
}

#[test]
fn jobhub_response_text_is_reliable_under_backpressure_and_generation_scoped() {
    use kuzushi_openai::langgraph_runtime::ResponseTextEvent;
    let mut hub = JobHub::default();
    let old = hub.start(JobKind::Agent, "old Ask");
    old.send(ShellEvent::Agent(AgentEvent::ResponseText(
        ResponseTextEvent::Delta("stale".into()),
    )));
    old.complete();
    let ticket = hub.start(JobKind::Agent, "current Ask");
    let sink = ticket.sink();
    let count = super::hub::JOB_EVENT_CHANNEL_CAPACITY + 8;
    let sender = std::thread::spawn(move || {
        for index in 0..count {
            assert!(sink.send(ShellEvent::Agent(AgentEvent::ResponseText(
                ResponseTextEvent::Delta(index.to_string())
            ))));
        }
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut text = Vec::new();
    while text.len() < count {
        assert!(std::time::Instant::now() < deadline);
        for event in hub.drain(count) {
            if let ShellEvent::Agent(AgentEvent::ResponseText(ResponseTextEvent::Delta(value))) =
                event
            {
                text.push(value);
            }
        }
        std::thread::yield_now();
    }
    sender.join().unwrap();
    assert_eq!(text, (0..count).map(|n| n.to_string()).collect::<Vec<_>>());
    assert!(hub.is_running(JobKind::Agent));
    ticket.complete();
}
