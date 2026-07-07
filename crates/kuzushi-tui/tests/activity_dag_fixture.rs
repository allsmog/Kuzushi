//! End-to-end fixture for the live module-progress view: simulate a fake
//! scan that emits RunTraceStep events through a real BroadcastSink ->
//! mpsc::channel -> ShellApp.trace_rx -> drain_trace_events -> ActivitySession,
//! then render the Activity view and assert on the expected output.

use std::sync::mpsc;
use std::sync::Arc;

use kuzushi_core::{
    BroadcastSink, Finding, JsonlSink, RunTraceStep, Severity, TraceHandle, TraceSink, V2Config,
};
use kuzushi_tui::{render_plain_app, ShellApp, ShellCommand, ShellView};

#[test]
fn fake_scan_dag_renders_with_module_tags_and_subsystems_collapse() {
    let mut app = ShellApp::new(V2Config::default(), None);

    // Mint the broadcast sink + receiver pair the way start_background_tool
    // does (sans the worker thread). Inner sink is a no-op JsonlSink writing
    // to a temp dir so `record` doesn't fail.
    let tmp = tempfile::tempdir().unwrap();
    let inner: Arc<dyn TraceSink> = Arc::new(JsonlSink::new(tmp.path().to_path_buf(), "r-fixture"));
    let (tx, rx) = mpsc::channel::<RunTraceStep>();
    let sink: Arc<dyn TraceSink> = Arc::new(BroadcastSink::new(inner, tx));
    let handle = TraceHandle::new(sink);

    // Simulate the dispatch wrapper auto-stamping module_id, then have each
    // producer emit its phase events. This is the exact pattern Phase D
    // wired into the real producers.
    let context = handle.for_module("context");
    let _ = context.step("tool", "build", "context:build start").emit();
    let _ = context
        .step(
            "done",
            "build",
            "context:build complete · 412 files indexed",
        )
        .emit();

    let semgrep = handle.for_module("semgrep");
    let _ = semgrep
        .step("tool", "scan", "semgrep start · target=./repo")
        .emit();
    let _ = semgrep
        .step("done", "scan", "semgrep complete · 14 findings")
        .emit();

    let triage = handle.for_module("triage");
    let triage_start = triage
        .step("tool", "run", "triage start (concurrency=10)")
        .emit();
    let _ = triage
        .child(triage_start)
        .step("reasoning", "run", "evidence-collect · stage1 kept 14/14")
        .emit();
    let _ = triage
        .step(
            "done",
            "run",
            "verdict-write · tp=3 fp=2 review=9 byDesign=0",
        )
        .emit();

    // A hidden subsystem event should collapse into the aggregate row, not
    // surface in the right pane.
    let pipeline = handle.for_module("pipeline");
    let _ = pipeline
        .step("tool", "task-selector", "selected next task")
        .emit();

    // Wire the receiver onto the app, open the Activity view, drain.
    app.handle_command(ShellCommand::Activity);
    {
        // Emulate ShellApp::trace_rx assignment without exposing the field.
        // Since trace_rx is pub(crate), use a small helper: replicate the
        // drain loop manually here by reading from rx and applying through
        // the public ActivitySession API.
        let session = app.activity_mut().expect("activity session minted");
        while let Ok(step) = rx.try_recv() {
            session.apply_step(step);
        }
    }

    assert!(matches!(app.shell_view, ShellView::Activity));

    let output = render_plain_app(&app, 120);
    assert!(
        output.contains("[context:build]"),
        "context:build start should appear in feed: {output}"
    );
    assert!(output.contains("[semgrep:scan]"), "semgrep tag missing");
    assert!(output.contains("[triage:run]"), "triage tag missing");
    assert!(
        output.contains("subsystems"),
        "hidden pipeline:* should collapse into subsystems aggregate row"
    );
    assert!(
        !output.contains("[pipeline:task-selector]"),
        "hidden module event should not appear in feed by default"
    );
}

#[test]
fn parent_step_indents_child_event_in_feed() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let tmp = tempfile::tempdir().unwrap();
    let inner: Arc<dyn TraceSink> =
        Arc::new(JsonlSink::new(tmp.path().to_path_buf(), "r-fixture-2"));
    let (tx, rx) = mpsc::channel::<RunTraceStep>();
    let sink: Arc<dyn TraceSink> = Arc::new(BroadcastSink::new(inner, tx));
    let handle = TraceHandle::new(sink);

    let agentic = handle.for_module("agentic-sast");
    let parent = agentic.step("tool", "scan", "agentic-sast start").emit();
    let _ = agentic
        .child(parent)
        .step("reasoning", "scan", "static-validation · 3 candidates")
        .emit();

    app.handle_command(ShellCommand::Activity);
    let session = app.activity_mut().unwrap();
    while let Ok(step) = rx.try_recv() {
        session.apply_step(step);
    }

    // The child event has parent_step set; the renderer prepends "↳ " for
    // sub-step rows.
    let output = render_plain_app(&app, 120);
    assert!(
        output.contains("↳"),
        "indented sub-step glyph missing in: {output}"
    );
    assert!(output.contains("static-validation"));
}

#[test]
fn auto_open_flips_view_on_tool_start() {
    use kuzushi_tui::{ShellApp, ShellCommand, ShellView};
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    // M1 §1.3: target must be set explicitly — dispatch no longer falls back
    // to cwd silently. Use a tempdir so the workspace resolves cleanly.
    app.set_target(Some(tmp.path().to_path_buf()));
    app.shell_view = ShellView::Home;
    assert!(matches!(app.shell_view, ShellView::Home));

    // Issue a /run command for a tool whose dispatcher we know — the
    // background_tool_worker will fail without a real workspace, but we only
    // care that start_background_tool flips the view before the worker thread
    // runs.
    app.handle_command(ShellCommand::RunTool {
        tool: Some("findings:list".to_string()),
        input: None,
    });

    assert!(
        matches!(app.shell_view, ShellView::Activity),
        "shell_view should auto-flip to Activity on tool start"
    );
}

#[test]
fn auto_open_disabled_does_not_open_activity() {
    use kuzushi_tui::{ShellApp, ShellCommand, ShellView};
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.handle_command(ShellCommand::SetOption {
        global: false,
        name: "ui.auto_open_activity".to_string(),
        value: "false".to_string(),
    });

    app.handle_command(ShellCommand::RunTool {
        tool: Some("findings:list".to_string()),
        input: None,
    });

    assert!(
        !matches!(app.shell_view, ShellView::Activity),
        "Activity should not auto-open when the toggle is off; got {:?}",
        app.shell_view
    );
}

#[test]
fn pane_focus_routes_jk_to_focused_scroll_offset() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(ShellCommand::Activity);
    app.set_findings(sample_findings(10));
    {
        let session = app.activity_mut().unwrap();
        // Seed enough events that scrolling makes sense.
        for i in 0..50 {
            session.apply_step(
                RunTraceStep::new(i, "tool", format!("event {i}"))
                    .with_module_id("semgrep")
                    .with_verb("scan"),
            );
        }
    }
    // pane_focus defaults to Left (DAG)
    app.scroll_down(3);
    let route = app.activity_route();
    assert_eq!(route.task_scroll, 3);
    assert_eq!(route.feed_scroll, 0, "feed must not move");

    // Tab to right pane and scroll
    app.activity_route_mut().toggle_pane_focus();
    app.scroll_down(7);
    let route = app.activity_route();
    assert_eq!(route.deck_cursor, 7);
    assert_eq!(route.feed_scroll, 0, "feed rows now live in TASKS/ACTIONS");
    assert_eq!(route.task_scroll, 3, "DAG must not move");
    assert!(
        !route.feed_auto_tail,
        "manually scrolling OUTPUT unpins live auto-tail"
    );
    assert!(
        !route.paused,
        "manual scroll no longer flips paused (decoupled in R4.D)"
    );
}

#[test]
fn pause_toggle_preserves_pinned_output_cursor() {
    use kuzushi_tui::ActivitySession;
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(ShellCommand::Activity);
    app.set_findings(sample_findings(10));
    {
        let session: &mut ActivitySession = app.activity_mut().unwrap();
        for i in 0..40 {
            session.apply_step(
                RunTraceStep::new(i, "tool", format!("event {i}"))
                    .with_module_id("triage")
                    .with_verb("run"),
            );
        }
    }
    app.activity_route_mut().pane_focus = kuzushi_tui::PaneFocus::Right;

    // Operator scrolls OUTPUT by 5 — moves the artifact cursor and unpins
    // auto-tail. The live event feed itself now lives under TASKS/ACTIONS.
    app.scroll_down(5);
    let route = app.activity_route();
    assert_eq!(route.deck_cursor, 5);
    assert_eq!(route.feed_scroll, 0);
    assert!(!route.feed_auto_tail);

    // Toggle pause on, then off — output cursor and feed_auto_tail must be
    // preserved (R4.D contract).
    let event_count = app.activity().unwrap().events.len();
    app.activity_route_mut().toggle_paused(event_count);
    app.activity_route_mut().toggle_paused(event_count);
    let route = app.activity_route();
    assert_eq!(
        route.deck_cursor, 5,
        "pause toggle must not reset output cursor position"
    );
    assert!(
        !route.feed_auto_tail,
        "pause toggle must not re-engage auto-tail"
    );

    // G on OUTPUT jumps to the bottom of the output view; it does not re-arm
    // feed auto-tail because the feed is no longer the focused right pane.
    app.scroll_to_bottom();
    let route = app.activity_route();
    assert_eq!(route.deck_cursor, 9);
    assert!(
        !route.feed_auto_tail,
        "OUTPUT bottom should not reset live auto-tail"
    );
}

#[test]
fn seed_from_registry_pre_populates_dag_pane() {
    use kuzushi_core::ModuleRegistry;
    use kuzushi_tui::ActivitySession;
    let registry = ModuleRegistry::with_v2_builtins();
    let mut session = ActivitySession::new("scan-pending");
    assert!(session.tasks.is_empty());

    session.seed_from_registry(&registry);

    assert!(
        !session.tasks.is_empty(),
        "registry seed should produce queued rows"
    );
    // Spot-check a known DAG node.
    assert!(
        session.tasks.contains_key("context:build"),
        "context:build should be in the seeded tasks: {:?}",
        session.tasks.keys().collect::<Vec<_>>()
    );
    // Hidden modules should not produce rows but should bump the
    // subsystem aggregate's queued total.
    assert!(
        !session.tasks.keys().any(|k| k.starts_with("pipeline:")),
        "hidden pipeline:* nodes should not get DAG rows"
    );
    assert!(
        session.subsystem_aggregate.total_count > 0,
        "hidden module count should land in subsystem aggregate"
    );
}

#[test]
fn cancel_command_in_activity_emits_visible_signal() {
    use kuzushi_tui::{ShellApp, ShellCommand, ShellView};
    let tmp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    // M1 §1.3: dispatch requires an explicit target.
    app.set_target(Some(tmp.path().to_path_buf()));
    app.handle_command(ShellCommand::RunTool {
        tool: Some("findings:list".to_string()),
        input: None,
    });
    assert!(matches!(app.shell_view, ShellView::Activity));

    app.handle_command(ShellCommand::Cancel);

    // The cancel path is wired iff one of the cancel handlers logs:
    //   - tool path: "cancel requested" / "abort requested"
    //   - scan path: "abort requested" (request_scan_abort)
    //   - no-op fallback: "no running tool or scan to cancel"
    let log_has_signal = app.log_lines().iter().any(|line| {
        line.body.contains("cancel requested")
            || line.body.contains("abort requested")
            || line.body.contains("no running tool or scan")
    });
    assert!(
        log_has_signal,
        "Ctrl+C should produce a visible signal in the transcript; \
         got log: {:?}",
        app.log_lines()
            .iter()
            .map(|l| format!("{}: {}", l.prefix, l.body))
            .collect::<Vec<_>>()
    );
    assert!(matches!(app.shell_view, ShellView::Activity));
    assert!(!app.should_quit());
}

fn sample_findings(count: usize) -> Vec<Finding> {
    (0..count)
        .map(|index| Finding {
            id: None,
            scan_id: None,
            fingerprint: format!("fp-{index}"),
            rule_id: "test/rule".to_string(),
            title: format!("finding {index}"),
            severity: Severity::High,
            file_path: "src/x.rs".to_string(),
            start_line: (index + 1) as u32,
            end_line: None,
            message: String::new(),
            tool: "test".to_string(),
            ..Finding::default()
        })
        .collect()
}

#[test]
fn verbose_subsystems_toggle_reveals_hidden_module_events() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let tmp = tempfile::tempdir().unwrap();
    let inner: Arc<dyn TraceSink> =
        Arc::new(JsonlSink::new(tmp.path().to_path_buf(), "r-fixture-3"));
    let (tx, rx) = mpsc::channel::<RunTraceStep>();
    let sink: Arc<dyn TraceSink> = Arc::new(BroadcastSink::new(inner, tx));
    let handle = TraceHandle::new(sink);

    let pipeline = handle.for_module("pipeline");
    let _ = pipeline
        .step(
            "tool",
            "approval-before-verification",
            "approval gate cleared",
        )
        .emit();

    app.handle_command(ShellCommand::Activity);
    {
        let session = app.activity_mut().unwrap();
        while let Ok(step) = rx.try_recv() {
            session.apply_step(step);
        }
    }
    app.activity_route_mut().toggle_verbose_subsystems();

    let output = render_plain_app(&app, 180);
    assert!(
        output.contains("[pipeline:approval-before-"),
        "verbose toggle should expose hidden module events: {output}"
    );
}
