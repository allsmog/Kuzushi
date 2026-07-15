use super::runtime_event_drains::JOB_DRAIN_LIMIT;
use super::*;
use std::sync::Arc;

struct NoopTraceSink;

impl kuzushi_core::TraceSink for NoopTraceSink {
    fn record(&self, _step: &RunTraceStep) {}
}

#[test]
fn job_drain_preserves_trace_terminal_order() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Run, "semgrep:scan");
    let budget = app.jobs().trace_budget();
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
    app.set_running_tool_for_test("semgrep:scan");
    app.set_activity(Some(ActivitySession::new("r-1")));

    assert!(app.drain_job_events());

    let labels = activity_labels(&app);
    assert_eq!(labels, vec!["ordered trace", "tool failed"]);
    assert_eq!(budget.pending(), 0);
    assert!(!app.jobs().is_running(JobKind::Run));
}

#[test]
fn zero_duration_job_slice_applies_one_event_and_keeps_tail() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Run, "scan");
    app.set_scan_panel(Some(ScanPanelState {
        run_id: None,
        target: std::path::PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    ticket.send(ShellEvent::Scan(ScanEvent::Stage("first".to_string())));
    ticket.send(ShellEvent::Scan(ScanEvent::Stage("second".to_string())));

    let outcome = app.drain_job_events_for(std::time::Duration::ZERO);

    assert!(outcome.changed);
    assert!(outcome.time_slice_exhausted);
    assert_eq!(app.scan().unwrap().stage, "first");

    assert!(app.drain_job_events());
    assert_eq!(app.scan().unwrap().stage, "second");
}

#[test]
fn job_drain_does_not_finish_tool_slot_on_scan_terminal_event() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Run, "sast:scan");
    ticket.send(ShellEvent::Scan(ScanEvent::Finished {
        result: serde_json::json!({
            "ok": true,
            "status": "completed",
            "data": {"runId": "run-1", "findingsCount": 0},
        }),
    }));
    app.set_running_tool_for_test("sast:scan");

    assert!(app.drain_job_events());

    assert_eq!(app.running_tool_name(), Some("sast:scan"));
    assert!(app.jobs().is_running(JobKind::Run));

    ticket.send(ShellEvent::Tool(ToolEvent::Finished {
        tool_name: "sast:scan".to_string(),
        result: serde_json::json!({ "output": "tool complete" }),
    }));

    assert!(app.drain_job_events());

    assert!(!app.tool_is_running());
    assert!(!app.jobs().is_running(JobKind::Run));
}

#[test]
fn job_drain_finishes_scan_slot_on_scan_terminal_event() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Run, "scan");
    ticket.send(ShellEvent::Scan(ScanEvent::Finished {
        result: serde_json::json!({
            "ok": true,
            "status": "completed",
            "data": {"runId": "run-1", "findingsCount": 0},
        }),
    }));
    app.set_scan_panel(Some(ScanPanelState {
        run_id: None,
        target: std::path::PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));

    assert!(app.drain_job_events());

    assert!(!app.scan().unwrap().running);
    assert!(!app.jobs().is_running(JobKind::Run));
}

#[test]
fn job_drain_finishes_plan_slot_and_clears_liveness() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Plan, "planner");
    let cancel = ticket.cancel.clone();
    ticket.send(ShellEvent::Plan(PlanEvent::Failed {
        error: "planner failed".to_string(),
        audit: AgentCallAudit::test(),
    }));
    app.set_plan_cancel(Some(cancel));
    app.set_planner_running(true);

    assert!(app.drain_job_events());

    assert!(!app.planner_running());
    assert!(app.plan_cancel_token().is_none());
    assert!(!app.jobs().is_running(JobKind::Plan));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("planner failed")));
}

#[test]
fn job_drain_finishes_agent_slot_and_clears_liveness() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Agent, "agent");
    let cancel = ticket.cancel.clone();
    ticket.send(ShellEvent::Agent(AgentEvent::Failed {
        error: "agent failed".to_string(),
        audit: AgentCallAudit {
            model: "unknown".to_string(),
            provider: "unknown".to_string(),
            prompt_hash: "test".to_string(),
            cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
            call_attempted: true,
        },
    }));
    let agent = AgentChatView {
        question: "what next?".to_string(),
        running: true,
        ..AgentChatView::default()
    };
    app.set_agent_chat(Some(agent));
    app.set_agent_cancel(Some(cancel));

    assert!(app.drain_job_events());

    let agent = app
        .agent_chat()
        .expect("agent chat state should remain visible");
    assert!(!agent.running);
    assert!(app.agent_cancel_token().is_none());
    assert!(!app.jobs().is_running(JobKind::Agent));
    assert!(agent
        .error
        .as_deref()
        .is_some_and(|error| error.contains("agent failed")));
}

#[test]
fn job_drain_finishes_threat_slot_and_clears_liveness() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Threat, "threat model");
    let cancel = ticket.cancel.clone();
    ticket.send(ShellEvent::Threat(ThreatPatchEvent::Failed {
        error: "threat failed".to_string(),
        audit: AgentCallAudit::test(),
    }));
    app.set_threat_cancel(Some(cancel));
    app.set_threat_worker_running(true);

    assert!(app.drain_job_events());

    assert!(!app.threat_worker_running());
    assert!(app.threat_cancel_token().is_none());
    assert!(!app.jobs().is_running(JobKind::Threat));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("threat failed")));
}

#[test]
fn job_drain_is_budgeted_and_keeps_buffered_tail() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Run, "semgrep:scan");
    let budget = app.jobs().trace_budget();
    for i in 0..(JOB_DRAIN_LIMIT + 5) {
        assert!(budget.reserve_for_test());
        ticket.send(ShellEvent::Trace(
            RunTraceStep::new(i + 1, "tool", format!("event {i}"))
                .with_module_id("semgrep")
                .with_verb("scan"),
        ));
    }
    app.set_activity(Some(ActivitySession::new("r-1")));

    assert!(app.drain_job_events());
    let first_tick_count = app.activity().unwrap().events.len();
    assert!(first_tick_count > 0);
    assert!(first_tick_count <= JOB_DRAIN_LIMIT);
    assert_eq!(budget.pending(), JOB_DRAIN_LIMIT + 5 - first_tick_count);
    assert!(app.jobs().is_running(JobKind::Run));

    drain_remaining_job_events(&mut app, &budget);
    assert_eq!(app.activity().unwrap().events.len(), JOB_DRAIN_LIMIT + 5);
    assert_eq!(budget.pending(), 0);
    assert!(app.jobs().is_running(JobKind::Run));
}

#[test]
fn dropped_live_trace_degrades_cost_until_terminal_reconciliation() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Run, "runtime tool");
    let budget = app.jobs().trace_budget();
    for _ in 0..LIVE_TRACE_CHANNEL_CAPACITY {
        assert!(budget.reserve_for_test());
    }
    let sink = StampedTraceSink::new(Arc::new(NoopTraceSink), ticket.sink(), budget);
    app.set_activity(Some(ActivitySession::new("runtime-drop")));
    app.begin_run_cost_tracking("runtime-drop", true);

    kuzushi_core::TraceSink::record(
        &sink,
        &RunTraceStep::new(1, "llm", "provider call")
            .with_call_attempted(true)
            .with_cost_usd(Some(0.20))
            .with_model_metadata("openai:gpt-test", "openai", "fnv1a64:test"),
    );

    assert!(app.drain_job_events());
    assert!(!app.session().cost_accounting_is_complete());
    assert!(!app
        .activity()
        .unwrap()
        .runtime_cost_report()
        .unwrap()
        .is_complete());

    let terminal = kuzushi_core::runtime::RuntimeCostReport::known(
        kuzushi_core::runtime::RuntimeCost::from_usd(0.20, "terminal cost").unwrap(),
    );
    app.settle_run_cost_report("runtime-drop", terminal);

    assert!(app.session().cost_accounting_is_complete());
    assert_eq!(app.session().session_cost_usd(), 0.20);
    assert_eq!(
        app.activity()
            .unwrap()
            .runtime_cost_report()
            .unwrap()
            .exact_usd(),
        Some(0.20)
    );
}

#[test]
fn stale_job_tool_event_is_discarded_without_clearing_current_guard() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let stale = app.jobs_mut().start(JobKind::Run, "old-tool");
    let _current = app.jobs_mut().start(JobKind::Run, "semgrep:scan");
    stale.send(ShellEvent::Tool(ToolEvent::Finished {
        tool_name: "semgrep:scan".to_string(),
        result: serde_json::json!({ "output": "stale complete" }),
    }));
    app.set_running_tool_for_test("semgrep:scan");

    assert!(!app.drain_job_events());

    assert_eq!(app.running_tool_name(), Some("semgrep:scan"));
    assert!(app.jobs().is_running(JobKind::Run));
    assert!(!app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("stale complete")));
}

fn test_operator_question_request(run_id: &str) -> OperatorQuestionRequest {
    OperatorQuestionRequest::from_tool_input(
        run_id,
        serde_json::json!({"questions": [{
            "id": "scope",
            "header": "Scope",
            "prompt": "What should Scan inspect?",
            "options": [
                {"label": "Changed", "description": "Current diff", "recommended": true},
                {"label": "All", "description": "Whole target", "recommended": false}
            ]
        }]}),
    )
    .unwrap()
}

#[test]
fn stale_operator_completion_cannot_clear_matching_current_question() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_activity(Some(ActivitySession::new("shared-run")));
    let stale = app.jobs_mut().start(JobKind::Agent, "old-agent");
    let current = app.jobs_mut().start(JobKind::Agent, "current-agent");
    let request = test_operator_question_request("shared-run");
    let request_id = request.request_id.clone();
    let (control, _responses) = std::sync::mpsc::sync_channel(1);
    assert!(
        current.send(ShellEvent::OperatorQuestion(OperatorQuestionEnvelope {
            request,
            generation: current.generation(),
            control,
        }))
    );
    assert!(stale.send(ShellEvent::OperatorQuestionCompleted(
        OperatorQuestionCompleted {
            request_id: request_id.clone(),
            run_id: "shared-run".to_string(),
            outcome: OperatorQuestionOutcome::Submitted,
            selected_labels: vec!["Changed".to_string()],
            freeform_supplied: false,
        }
    )));

    app.drain_job_events();

    let session = app.activity().expect("current activity");
    let card = session
        .operator_question
        .as_ref()
        .expect("current question must remain");
    assert_eq!(card.request().request_id, request_id);
    assert_eq!(session.operator_answer_acknowledgement, None);
    stale.complete();
    current.complete();
}

#[test]
fn stale_job_burst_consumes_drain_budget_before_current_event() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let stale = app.jobs_mut().start(JobKind::Run, "old-tool");
    for index in 0..(JOB_DRAIN_LIMIT + 5) {
        stale.send(ShellEvent::Scan(ScanEvent::Stage(format!("old {index}"))));
    }
    stale.complete();
    let current = app.jobs_mut().start(JobKind::Run, "semgrep:scan");
    current.send(ShellEvent::Tool(ToolEvent::Failed {
        tool_name: "semgrep:scan".to_string(),
        error: "current failed".to_string(),
    }));
    app.set_running_tool_for_test("semgrep:scan");
    app.set_activity(Some(ActivitySession::new("r-1")));

    assert!(!app.drain_job_events());
    assert!(activity_labels(&app).is_empty());
    assert!(app.jobs().is_running(JobKind::Run));

    assert!(app.drain_job_events());
    assert_eq!(activity_labels(&app), vec!["current failed"]);
    assert!(!app.jobs().is_running(JobKind::Run));
}

#[test]
fn stale_job_trace_step_releases_budget_without_activity_update() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let stale = app.jobs_mut().start(JobKind::Run, "old-tool");
    let _current = app.jobs_mut().start(JobKind::Run, "semgrep:scan");
    let budget = app.jobs().trace_budget();
    assert!(budget.reserve_for_test());
    stale.send(ShellEvent::Trace(
        RunTraceStep::new(1, "tool", "stale trace")
            .with_module_id("semgrep")
            .with_verb("scan"),
    ));

    assert!(!app.drain_job_events());

    assert_eq!(budget.pending(), 0);
    assert!(app.activity().is_none());
    assert!(app.jobs().is_running(JobKind::Run));
}

#[test]
fn background_drain_applies_trace_before_terminal_tool_event() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs_mut().start(JobKind::Run, "semgrep:scan");
    let budget = app.jobs().trace_budget();
    assert!(budget.reserve_for_test());
    ticket.send(ShellEvent::Trace(
        RunTraceStep::new(1, "tool", "producer tail")
            .with_module_id("semgrep")
            .with_verb("scan"),
    ));
    ticket.send(ShellEvent::Tool(ToolEvent::Failed {
        tool_name: "semgrep:scan".to_string(),
        error: "tool failed".to_string(),
    }));

    app.set_running_tool_for_test("semgrep:scan");
    app.set_activity(Some(ActivitySession::new("r-1")));

    assert!(app.drain_background_events());

    assert_eq!(activity_labels(&app), vec!["producer tail", "tool failed"]);
}

fn activity_labels(app: &ShellApp) -> Vec<&str> {
    app.activity()
        .unwrap()
        .events
        .iter()
        .map(|event| event.step.label.as_str())
        .collect()
}

fn drain_remaining_job_events(app: &mut ShellApp, budget: &LiveTraceBudget) {
    for _ in 0..100 {
        if budget.pending() == 0 {
            return;
        }
        assert!(app.drain_job_events());
    }
    panic!("job events did not drain within the test iteration budget");
}
