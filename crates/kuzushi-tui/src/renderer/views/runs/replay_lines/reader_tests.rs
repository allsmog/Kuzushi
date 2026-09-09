use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::run_lifecycle::*;
use kuzushi_core::V2Config;
use ratatui::buffer::CellWidth;

const RUN: &str = "failed-reader-fixture";
const REMEDY: &str = "Restore the missing code-analysis component: from source run `cargo build --workspace`; otherwise reinstall Kuzushi. Retain the source path `資料/my  project` exactly.";

fn failed_replay() -> (tempfile::TempDir, ShellApp) {
    let target = tempfile::tempdir().unwrap();
    let summary =
        kuzushi_core::RunSummary::running(RUN, "trace:expand", None, "fixture").failed(REMEDY);
    kuzushi_core::write_run_summary(target.path(), &summary).unwrap();
    let observation = RunObservationHandle::jsonl(target.path(), RUN).unwrap();
    observation
        .emit(RunItemRecord::new(
            RunItemId::new(),
            RunItemSource::Workflow,
            RunItemV1::TerminalOutcome {
                status: RunItemStatus::Failed,
                summary: SafeText::operator_visible(REMEDY),
                cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
                continuation: WorkflowContinuation::NoFurtherAction {
                    reason: SafeText::operator_visible("Restore the helper before retrying."),
                },
            },
        ))
        .unwrap();
    observation.flush().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.path().to_path_buf()));
    app.open_replay_for_test(RUN);
    app.hydrate_active_view_blocking();
    (target, app)
}

fn press(app: &mut ShellApp, key: KeyCode) {
    assert!(
        app.reduce_key(KeyEvent::new(key, KeyModifiers::NONE))
            .handled
    );
}

fn body(app: &ShellApp) -> Rect {
    let viewport = app.viewport();
    let area =
        crate::renderer::primary_body_area(app, Rect::new(0, 0, viewport.columns, viewport.rows));
    crate::ui_view_models::answers_layout(app, area).workspace
}

#[test]
fn replay_reader_wraps_complete_failure_messages_to_display_width() {
    let (_target, app) = failed_replay();
    for width in [40, 80] {
        let lines = replay_lines(&app, Rect::new(0, 0, width, 24), RUN);
        assert!(
            lines.iter().all(|line| line.width() <= width as usize),
            "Replay rows overflow {width} columns"
        );
        let text: String = lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect();
        let compact: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
        let remedy: String = REMEDY.chars().filter(|ch| !ch.is_whitespace()).collect();
        assert!(compact.contains(&remedy), "complete remedy missing");
        assert!(text.contains("my  project"), "path whitespace was changed");
    }
}

#[test]
fn replay_reader_pages_by_its_body_and_recovers_immediately_from_the_tail() {
    let (_target, mut app) = failed_replay();
    app.set_viewport(crate::app::TerminalViewport::new(40, 12));
    let area = body(&app);
    press(&mut app, KeyCode::PageDown);
    let step = app.router.default_scroll().offset() as usize;
    assert!(
        step > 0 && step <= area.height as usize,
        "page skips visible rows: {step} > {}",
        area.height
    );
    let max = replay_lines(&app, area, RUN)
        .len()
        .saturating_sub(area.height as usize);
    for _ in 0..20 {
        press(&mut app, KeyCode::PageDown);
    }
    assert_eq!(app.router.default_scroll().offset() as usize, max);
    app.router.default_scroll_mut().tail();
    app.scroll_up(1);
    assert_eq!(
        app.router.default_scroll().offset() as usize,
        max.saturating_sub(1)
    );
    app.set_viewport(crate::app::TerminalViewport::new(80, 24));
    let area = body(&app);
    let max = replay_lines(&app, area, RUN)
        .len()
        .saturating_sub(area.height as usize);
    press(&mut app, KeyCode::PageUp);
    assert!(app.router.default_scroll().offset() as usize <= max);
}

#[test]
fn replay_reader_footer_matches_escape_and_preserves_the_draft() {
    for view in [ShellView::Replay, ShellView::Trace] {
        for mode in [crate::InputMode::Prompt, crate::InputMode::Navigate] {
            let mut app = ShellApp::new(V2Config::default(), None);
            app.set_shell_view(ShellView::Workbench);
            app.set_input_mode(mode);
            app.set_shell_view(view);
            app.set_input("unsent 修正".to_string());
            let bindings = crate::ui_view_models::footer_keybindings(&app);
            assert!(
                bindings
                    .iter()
                    .any(|key| key.key == "Esc" && key.label == "back"),
                "{bindings:?}"
            );
            assert!(bindings.iter().any(|key| key.key == "PgUp/PgDn"));
            press(&mut app, KeyCode::Esc);
            assert_eq!(app.shell_view(), ShellView::Workbench);
            assert_eq!(app.input_mode(), mode);
            assert_eq!(app.input(), "unsent 修正");
        }
    }
}

#[test]
fn replay_reader_alert_owns_the_advertised_escape_action() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Replay);
    app.set_error_notice("tool", "Inspect the failed run.");
    let bindings = crate::ui_view_models::footer_keybindings(&app);
    assert!(bindings
        .iter()
        .any(|key| key.key == "Esc" && key.label == "dismiss notice"));
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Replay);
    assert!(app.advisory().notice.is_none());
}

#[test]
fn replay_reader_keeps_contextual_escape_when_composer_keys_are_remapped() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let keymap =
        crate::app::RuntimeKeymap::from_config(&[kuzushi_core::config::KeybindingOverrideConfig {
            context: "composer".to_string(),
            action: "navigate_mode".to_string(),
            bindings: vec!["ctrl+n".to_string()],
        }]);
    app.ui_mut().replace_runtime_keymap(keymap).unwrap();
    app.set_shell_view(ShellView::Workbench);
    app.set_shell_view(ShellView::Replay);
    let bindings = crate::ui_view_models::footer_keybindings(&app);
    assert!(bindings
        .iter()
        .any(|key| key.key == "Esc" && key.label == "back"));
    assert!(!bindings.iter().any(|key| key.key == "ctrl+n"));
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Workbench);
}

#[test]
fn replay_reader_wrap_retains_styles_graphemes_and_path_spaces() {
    use ratatui::style::Color;
    let original = "資料 👩‍💻 /my  project/repair";
    let line = Line::from(vec![Span::styled(
        original,
        Style::default().add_modifier(Modifier::BOLD),
    )])
    .style(Style::default().fg(Color::Red));
    let lines = wrap_document_lines(vec![line], 9);
    assert!(lines.iter().all(|line| line.width() <= 9));
    let spans: Vec<_> = lines.iter().flat_map(|line| line.spans.iter()).collect();
    let text: String = spans.iter().map(|span| span.content.as_ref()).collect();
    assert_eq!(text, original);
    assert!(spans.iter().any(|span| span.content.contains("👩‍💻")));
    assert!(spans.iter().all(|span| span.style.fg == Some(Color::Red)
        && span.style.add_modifier.contains(Modifier::BOLD)));
}

#[test]
fn replay_reader_footer_retains_background_cancellation_state() {
    for view in [ShellView::Replay, ShellView::Trace] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(view);
        for (running, abort_requested, label) in [
            (false, false, "exit"),
            (true, false, "request abort"),
            (true, true, "wait cleanup"),
        ] {
            app.set_planner_running(running);
            app.set_plan_abort_requested(abort_requested);
            let bindings = crate::ui_view_models::footer_keybindings(&app);
            let interrupt = bindings.iter().find(|key| key.key == "Ctrl+C").unwrap();
            assert_eq!(interrupt.label, label, "{view:?}");
        }
    }
}

#[test]
fn replay_reader_full_frame_paging_reaches_every_projected_row() {
    use ratatui::{backend::TestBackend, Terminal};
    for (width, height) in [(40, 12), (80, 24)] {
        let (_target, mut app) = failed_replay();
        app.set_viewport(crate::app::TerminalViewport::new(width, height));
        let area = body(&app);
        let lines = replay_lines(&app, area, RUN);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..lines.len().div_ceil(area.height as usize) + 2 {
            terminal
                .draw(|frame| crate::renderer::render_app(frame, &app))
                .unwrap();
            seen.extend(visible_page(terminal.backend().buffer(), area));
            press(&mut app, KeyCode::PageDown);
        }
        for line in lines {
            let text: String = line
                .spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect();
            assert!(
                seen.contains(&without_spaces(&text)),
                "unreachable at {width}x{height}, area {area:?}: {text}\nseen: {seen:#?}"
            );
        }
    }
}

fn visible_page(buffer: &ratatui::buffer::Buffer, area: Rect) -> Vec<String> {
    (area.y..area.bottom())
        .map(|y| without_spaces(&visible_row(buffer, area, y)))
        .collect()
}

fn visible_row(buffer: &ratatui::buffer::Buffer, area: Rect, y: u16) -> String {
    let mut row = String::new();
    let mut hidden: u16 = 0;
    for x in area.x..area.right() {
        let cell = &buffer[(x, y)];
        if hidden == 0 {
            row.push_str(cell.symbol());
        }
        // TestBackend retains cells hidden beneath a multi-column grapheme.
        hidden = hidden.max(cell.cell_width()).saturating_sub(1);
    }
    row
}

fn without_spaces(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_whitespace()).collect()
}
