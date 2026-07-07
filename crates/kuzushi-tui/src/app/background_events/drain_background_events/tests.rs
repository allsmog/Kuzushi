use super::runtime_event_drains::JOB_DRAIN_LIMIT;
use super::*;

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
    app.set_running_tool_for_test("semgrep:scan");
    app.set_activity(Some(ActivitySession::new("r-1")));

    assert!(app.drain_job_events());

    let labels = activity_labels(&app);
    assert_eq!(labels, vec!["ordered trace", "tool failed"]);
    assert_eq!(budget.pending(), 0);
    assert!(!app.jobs.is_running(JobKind::Run));
}

#[test]
fn job_drain_collects_messages_before_applying_updates() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs.start(JobKind::Run, "scan");
    app.set_scan_panel(Some(ScanPanelState {
        run_id: None,
        target: std::path::PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    ticket.send(ShellEvent::Scan(ScanEvent::Stage(
        "running semgrep".to_string(),
    )));

    let messages = app.drain_job_messages();

    assert!(matches!(
        &messages[..],
        [Msg::Job(ShellEvent::Scan(ScanEvent::Stage(stage)))] if stage == "running semgrep"
    ));
    assert_eq!(app.scan().unwrap().stage, "running");

    assert!(update_many_and_execute_effects(&mut app, messages));

    assert_eq!(app.scan().unwrap().stage, "running semgrep");
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
    app.set_running_tool_for_test("sast:scan");

    assert!(app.drain_job_events());

    assert_eq!(app.running_tool_name(), Some("sast:scan"));
    assert!(app.jobs.is_running(JobKind::Run));

    ticket.send(ShellEvent::Tool(ToolEvent::Finished {
        tool_name: "sast:scan".to_string(),
        result: serde_json::json!({ "output": "tool complete" }),
    }));

    assert!(app.drain_job_events());

    assert!(!app.tool_is_running());
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
    assert!(!app.jobs.is_running(JobKind::Run));
}

#[test]
fn job_drain_finishes_plan_slot_and_clears_liveness() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs.start(JobKind::Plan, "planner");
    let cancel = ticket.cancel.clone();
    ticket.send(ShellEvent::Plan(PlanEvent::Failed {
        error: "planner failed".to_string(),
    }));
    app.set_plan_cancel(Some(cancel));
    app.set_planner_running(true);

    assert!(app.drain_job_events());

    assert!(!app.planner_running());
    assert!(app.plan_cancel_token().is_none());
    assert!(!app.jobs.is_running(JobKind::Plan));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("planner failed")));
}

#[test]
fn job_drain_finishes_agent_slot_and_clears_liveness() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs.start(JobKind::Agent, "agent");
    let cancel = ticket.cancel.clone();
    ticket.send(ShellEvent::Agent(AgentEvent::Failed {
        error: "agent failed".to_string(),
        audit: AgentCallAudit {
            model: "unknown".to_string(),
            provider: "unknown".to_string(),
            prompt_hash: "test".to_string(),
            cost_usd: None,
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
    assert!(!app.jobs.is_running(JobKind::Agent));
    assert!(agent
        .error
        .as_deref()
        .is_some_and(|error| error.contains("agent failed")));
}

#[test]
fn job_drain_finishes_threat_slot_and_clears_liveness() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs.start(JobKind::Threat, "threat model");
    let cancel = ticket.cancel.clone();
    ticket.send(ShellEvent::Threat(ThreatPatchEvent::Failed {
        error: "threat failed".to_string(),
    }));
    app.set_threat_cancel(Some(cancel));
    app.set_threat_worker_running(true);

    assert!(app.drain_job_events());

    assert!(!app.threat_worker_running());
    assert!(app.threat_cancel_token().is_none());
    assert!(!app.jobs.is_running(JobKind::Threat));
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("threat failed")));
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
    app.set_activity(Some(ActivitySession::new("r-1")));

    assert!(app.drain_job_events());
    let first_tick_count = app.activity().unwrap().events.len();
    assert!(first_tick_count > 0);
    assert!(first_tick_count <= JOB_DRAIN_LIMIT);
    assert_eq!(budget.pending(), JOB_DRAIN_LIMIT + 5 - first_tick_count);
    assert!(app.jobs.is_running(JobKind::Run));

    drain_remaining_job_events(&mut app, &budget);
    assert_eq!(app.activity().unwrap().events.len(), JOB_DRAIN_LIMIT + 5);
    assert_eq!(budget.pending(), 0);
    assert!(app.jobs.is_running(JobKind::Run));
}

#[test]
fn stale_job_tool_event_is_discarded_without_clearing_current_guard() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let stale = app.jobs.start(JobKind::Run, "old-tool");
    let _current = app.jobs.start(JobKind::Run, "semgrep:scan");
    stale.send(ShellEvent::Tool(ToolEvent::Finished {
        tool_name: "semgrep:scan".to_string(),
        result: serde_json::json!({ "output": "stale complete" }),
    }));
    app.set_running_tool_for_test("semgrep:scan");

    assert!(!app.drain_job_events());

    assert_eq!(app.running_tool_name(), Some("semgrep:scan"));
    assert!(app.jobs.is_running(JobKind::Run));
    assert!(!app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("stale complete")));
}

#[test]
fn stale_job_burst_consumes_drain_budget_before_current_event() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let stale = app.jobs.start(JobKind::Run, "old-tool");
    for index in 0..(JOB_DRAIN_LIMIT + 5) {
        stale.send(ShellEvent::Scan(ScanEvent::Stage(format!("old {index}"))));
    }
    stale.complete();
    let current = app.jobs.start(JobKind::Run, "semgrep:scan");
    current.send(ShellEvent::Tool(ToolEvent::Failed {
        tool_name: "semgrep:scan".to_string(),
        error: "current failed".to_string(),
    }));
    app.set_running_tool_for_test("semgrep:scan");
    app.set_activity(Some(ActivitySession::new("r-1")));

    assert!(!app.drain_job_events());
    assert!(activity_labels(&app).is_empty());
    assert!(app.jobs.is_running(JobKind::Run));

    assert!(app.drain_job_events());
    assert_eq!(activity_labels(&app), vec!["current failed"]);
    assert!(!app.jobs.is_running(JobKind::Run));
}

#[test]
fn stale_job_trace_step_releases_budget_without_activity_update() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let stale = app.jobs.start(JobKind::Run, "old-tool");
    let _current = app.jobs.start(JobKind::Run, "semgrep:scan");
    let budget = app.jobs.trace_budget();
    assert!(budget.reserve_for_test());
    stale.send(ShellEvent::Trace(
        RunTraceStep::new(1, "tool", "stale trace")
            .with_module_id("semgrep")
            .with_verb("scan"),
    ));

    assert!(!app.drain_job_events());

    assert_eq!(budget.pending(), 0);
    assert!(app.activity().is_none());
    assert!(app.jobs.is_running(JobKind::Run));
}

#[test]
fn background_drain_applies_trace_before_terminal_tool_event() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let ticket = app.jobs.start(JobKind::Run, "semgrep:scan");
    let budget = app.jobs.trace_budget();
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
