//! End-to-end fixture for the live module-progress view: simulate a fake
//! scan that emits RunTraceStep events through a real BroadcastSink ->
//! mpsc::channel -> ShellApp.trace_rx -> drain_trace_events -> ActivitySession,
//! then render the Activity view and assert on the expected output.

use std::sync::mpsc;
use std::sync::Arc;

use kuzushi_core::{
    BroadcastSink, JsonlSink, RunTraceStep, TraceHandle, TraceSink, V2Config,
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
    let _ = context
        .step("tool", "build", "context:build start")
        .emit();
    let _ = context.step("done", "build", "context:build complete · 412 files indexed").emit();

    let semgrep = handle.for_module("semgrep");
    let _ = semgrep.step("tool", "scan", "semgrep start · target=./repo").emit();
    let _ = semgrep
        .step("done", "scan", "semgrep complete · 14 findings")
        .emit();

    let triage = handle.for_module("triage");
    let triage_start = triage.step("tool", "run", "triage start (batch=10)").emit();
    let _ = triage
        .child(triage_start)
        .step("reasoning", "run", "evidence-collect · stage1 kept 14/14")
        .emit();
    let _ = triage
        .step("done", "run", "verdict-write · tp=3 fp=2 review=9 byDesign=0")
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
        let session = app.activity.as_mut().expect("activity session minted");
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
    let inner: Arc<dyn TraceSink> = Arc::new(JsonlSink::new(tmp.path().to_path_buf(), "r-fixture-2"));
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
    let session = app.activity.as_mut().unwrap();
    while let Ok(step) = rx.try_recv() {
        session.apply_step(step);
    }

    // The child event has parent_step set; the renderer prepends "↳ " for
    // sub-step rows.
    let output = render_plain_app(&app, 120);
    assert!(output.contains("↳"), "indented sub-step glyph missing in: {output}");
    assert!(output.contains("static-validation"));
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
        .step("tool", "approval-before-verification", "approval gate cleared")
        .emit();

    app.handle_command(ShellCommand::Activity);
    {
        let session = app.activity.as_mut().unwrap();
        while let Ok(step) = rx.try_recv() {
            session.apply_step(step);
        }
        session.toggle_verbose_subsystems();
    }

    let output = render_plain_app(&app, 120);
    assert!(
        output.contains("[pipeline:approval-before-verification]"),
        "verbose toggle should expose hidden module events: {output}"
    );
}
