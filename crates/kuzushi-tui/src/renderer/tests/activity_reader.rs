use super::*;
use crate::ui_view_models::{ActivityPaneLayout, ActivityViewModel};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn reader(width: u16, height: u16) -> ShellApp {
    reader_with_config(width, height, V2Config::default())
}

fn reader_with_config(width: u16, height: u16, config: V2Config) -> ShellApp {
    let mut session = ActivitySession::new("activity-reading-fixture");
    session.tasks.insert(
        "trace:expand".into(),
        crate::DagTaskRow::queued("trace:expand".into(), "Read source".into(), Vec::new()),
    );
    for index in 0..40 {
        apply_renderer_notice(&mut session, &format!("read-row-{index:02}"));
    }
    fail_session(&mut session);
    let mut app = ShellApp::new(config, None);
    app.set_activity(Some(session));
    app.set_shell_view(ShellView::Activity);
    app.set_input_mode(crate::InputMode::Navigate);
    app.set_viewport(crate::TerminalViewport::new(width, height));
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Char('V'));
    app.clear_notice();
    app
}

fn fail_session(session: &mut ActivitySession) {
    use kuzushi_core::run_lifecycle::*;
    let item = RunItemEnvelopeV1::new(
        session.run_projection.last_committed_seq + 1,
        RunId::parse(&session.run_id).unwrap(),
        RunItemId::new(),
        RunItemSource::Workflow,
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Failed,
            summary: SafeText::operator_visible("Restore the missing code-analysis component: from source run `cargo build --workspace`; otherwise reinstall Kuzushi."),
            cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
            continuation: WorkflowContinuation::NoFurtherAction {
                reason: SafeText::operator_visible("Restore the helper before retrying."),
            },
        },
        session.run_projection.last_event_hash.clone(),
    ).unwrap();
    session.apply_run_item(item).unwrap();
}

fn key(app: &mut ShellApp, code: KeyCode) {
    assert!(
        app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE))
            .handled
    );
}

fn output_area(app: &ShellApp) -> Rect {
    let viewport = app.viewport();
    let workspace = crate::renderer::workbench_primary_area(
        app,
        Rect::new(0, 0, viewport.columns, viewport.rows),
    );
    let ActivityViewModel::Active(activity) = crate::ui_view_models::activity_view_model(app)
    else {
        panic!("expected active reader");
    };
    let now = std::time::Instant::now();
    let (_, health) = activity.heartbeat_rows(workspace.width, now);
    let mut geometry = activity.frame_layout(workspace.width, health.len());
    if let Some(chrome) = activity.compact_chrome(workspace.width, workspace.height) {
        geometry.header_rows = chrome.header.len() as u16;
        geometry.footer_rows = chrome.footer.len() as u16;
    }
    let area = Rect::new(
        workspace.x,
        workspace.y + geometry.header_rows,
        workspace.width,
        workspace
            .height
            .saturating_sub(geometry.header_rows + geometry.footer_rows),
    );
    let pane = match activity.pane_layout(area.width, area.height, now) {
        ActivityPaneLayout::Focused => area,
        ActivityPaneLayout::SideBySide { task_width } => {
            Rect::new(task_width, area.y, area.width - task_width, area.height)
        }
        ActivityPaneLayout::Stacked { task_height } => Rect::new(
            0,
            area.y + task_height,
            area.width,
            area.height - task_height,
        ),
    };
    cockpit_pane_block("OUTPUT", true).inner(pane)
}

fn draw_output(app: &ShellApp) -> String {
    let size = app.viewport();
    let mut terminal = Terminal::new(TestBackend::new(size.columns, size.rows)).unwrap();
    terminal.draw(|frame| render_app(frame, app)).unwrap();
    let buffer = terminal.backend().buffer();
    let area = output_area(app);
    (area.y..area.bottom())
        .map(|y| {
            (area.x..area.right())
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn activity_reader_moves_down_immediately_after_go_to_top() {
    for (width, height) in [(80, 24), (40, 12)] {
        let mut app = reader(width, height);
        key(&mut app, KeyCode::Char('g'));
        let before = draw_output(&app);
        key(&mut app, KeyCode::Char('j'));
        let after = draw_output(&app);
        assert_ne!(
            before, after,
            "output stuck at top at {width}x{height}:\n{after}"
        );
    }
}

#[test]
fn activity_reader_recovers_after_scrolling_past_the_top() {
    let mut app = reader(40, 12);
    for _ in 0..100 {
        key(&mut app, KeyCode::Char('k'));
    }
    let before = draw_output(&app);
    key(&mut app, KeyCode::Char('j'));
    let after = draw_output(&app);
    assert_ne!(before, after, "output stuck after overscroll:\n{after}");
}

#[test]
fn activity_reader_pages_reach_every_output_row_at_minimum_size() {
    let mut app = reader(40, 12);
    key(&mut app, KeyCode::Char('g'));
    let mut seen = String::new();
    for _ in 0..80 {
        seen.push_str(&draw_output(&app));
        key(&mut app, KeyCode::PageDown);
    }
    for index in 0..40 {
        assert!(
            seen.contains(&format!("read-row-{index:02}")),
            "missing row {index}"
        );
    }
}

#[test]
fn activity_reader_failed_output_footer_describes_the_actual_interrupt() {
    let app = reader(80, 24);
    let ActivityViewModel::Active(model) = crate::ui_view_models::activity_view_model(&app) else {
        panic!("expected failed run reader");
    };
    let footer = model.footer(80);
    assert!(!footer.body.contains("live trace"), "{}", footer.body);
    assert!(footer.body.contains("Ctrl+C exit"), "{}", footer.body);
}

#[test]
fn activity_reader_footer_keeps_background_cancel_and_cleanup_states() {
    let mut app = reader(80, 24);
    app.set_planner_running(true);
    assert!(output_footer(&app).contains("Ctrl+C request abort"));
    app.set_plan_abort_requested(true);
    assert!(output_footer(&app).contains("ABORT REQUESTED"));
    assert!(!output_footer(&app).contains("Ctrl+C exit"));
}

fn output_footer(app: &ShellApp) -> String {
    let ActivityViewModel::Active(model) = crate::ui_view_models::activity_view_model(app) else {
        panic!("expected run reader");
    };
    model.footer(80).body
}

#[test]
fn activity_reader_anchors_movement_to_resized_output() {
    let mut app = reader(40, 12);
    key(&mut app, KeyCode::Char('g'));
    app.set_viewport(crate::TerminalViewport::new(80, 24));
    let before = draw_output(&app);
    key(&mut app, KeyCode::Char('j'));
    assert_ne!(before, draw_output(&app));
}

#[test]
fn activity_reader_compact_chrome_keeps_identity_and_five_output_rows() {
    let mut app = reader(40, 12);
    key(&mut app, KeyCode::Char('g'));
    assert!(
        output_area(&app).height >= 7,
        "need five content rows and both disclosures"
    );
    let output = draw_output(&app);
    assert!(output.lines().filter(|row| !row.trim().is_empty()).count() >= 5);
    let text = draw_full(&app);
    assert!(text.contains("run activity-reading-fixture"), "{text}");
    assert!(text.contains("Ctrl+C exit"), "{text}");
    assert!(text.contains("Ctrl+G → keys"), "{text}");
}

#[test]
fn activity_reader_compact_control_map_keeps_origin_and_output_position() {
    let mut app = reader(40, 12);
    key(&mut app, KeyCode::Char('g'));
    key(&mut app, KeyCode::PageDown);
    let before = draw_output(&app);
    let mode = app.input_mode();
    let scroll = app.router.activity().feed_scroll;
    assert!(
        app.reduce_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL))
            .handled
    );
    for ch in "keys".chars() {
        key(&mut app, KeyCode::Char(ch));
    }
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.shell_view(), ShellView::Keymap);
    let model = crate::ui_view_models::keymap_model(&app);
    let controls = model
        .sections
        .iter()
        .find(|section| section.name == "VIEW · Activity")
        .unwrap();
    for action in ["verbose", "feed pause", "reset view", "steer", "focus task"] {
        assert!(
            controls.rows.iter().any(|row| row.action == action),
            "missing {action}"
        );
    }
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert_eq!(app.input_mode(), mode);
    assert_eq!(app.router.activity().feed_scroll, scroll);
    assert_eq!(draw_output(&app), before);
}

#[test]
fn activity_reader_failure_notice_route_exposes_the_complete_error() {
    let mut app = reader(40, 12);
    let message = (0..20)
        .map(|i| format!("remedy-{i:02}"))
        .collect::<Vec<_>>()
        .join(" ");
    app.set_error_notice("tool", &message);
    let banner = draw_full(&app);
    assert!(banner.contains("Esc dismiss"), "{banner}");
    assert!(!banner.contains("Esc leave"), "{banner}");
    assert!(banner.contains("Ctrl+G → logs"), "{banner}");
    assert!(
        app.reduce_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL))
            .handled
    );
    for ch in "logs".chars() {
        key(&mut app, KeyCode::Char(ch));
    }
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.shell_view(), ShellView::Logs);
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Logs);
    key(&mut app, KeyCode::Char('g'));
    let mut seen = String::new();
    for _ in 0..30 {
        seen.push_str(&draw_full(&app));
        key(&mut app, KeyCode::PageDown);
    }
    for index in 0..20 {
        assert!(
            seen.contains(&format!("remedy-{index:02}")),
            "missing remedy-{index:02}: {seen}"
        );
    }
}

fn draw_full(app: &ShellApp) -> String {
    let size = app.viewport();
    let mut terminal = Terminal::new(TestBackend::new(size.columns, size.rows)).unwrap();
    terminal.draw(|frame| render_app(frame, app)).unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[test]
fn activity_reader_compact_controls_follow_task_focus_and_palette_override() {
    let mut config = V2Config::default();
    config.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
        context: "global".into(),
        action: "command_palette".into(),
        bindings: vec!["ctrl+y".into()],
    }];
    let mut app = reader_with_config(40, 12, config);
    key(&mut app, KeyCode::Tab);
    let text = draw_full(&app);
    assert!(text.contains("j/k/g/G select"), "{text}");
    assert!(text.contains("ctrl+y → keys"), "{text}");
    assert!(!text.contains("Ctrl+G"), "{text}");
    assert!(
        app.reduce_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::CONTROL))
            .handled
    );
    for ch in "keys".chars() {
        key(&mut app, KeyCode::Char(ch));
    }
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.shell_view(), ShellView::Keymap);
}

#[test]
fn activity_reader_log_tail_and_resize_preserve_manual_reading() {
    let mut app = reader(40, 12);
    for index in 0..50 {
        app.log("error", format!("bounded-log-{index:02}"));
    }
    app.set_shell_view(ShellView::Logs);
    key(&mut app, KeyCode::Char('G'));
    assert!(app.router.logs().is_following());
    let tail = draw_full(&app);
    key(&mut app, KeyCode::Char('k'));
    assert!(!app.router.logs().is_following());
    assert_ne!(draw_full(&app), tail);
    for _ in 0..100 {
        key(&mut app, KeyCode::Char('j'));
    }
    let bottom = draw_full(&app);
    key(&mut app, KeyCode::PageUp);
    assert_ne!(draw_full(&app), bottom);
    key(&mut app, KeyCode::Char('G'));
    app.set_viewport(crate::TerminalViewport::new(80, 24));
    let resized = draw_full(&app);
    key(&mut app, KeyCode::PageUp);
    assert_ne!(draw_full(&app), resized);
    assert!(!app.router.logs().is_following());
}
