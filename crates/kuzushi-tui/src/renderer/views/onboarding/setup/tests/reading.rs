use super::*;
use crate::app::{PlanningTaskId, PlanningTaskRow, SetupEditor, ShellView};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};

mod launch_failures;

fn import_setup() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    let tasks = [
        PlanningTaskId::GatherRepoContext,
        PlanningTaskId::ImportThreatModel,
    ];
    let rows = tasks
        .iter()
        .map(|task| PlanningTaskRow::for_task(*task, root.path()))
        .collect();
    app.engagement
        .planning_picker_mut()
        .open(rows, tasks.into_iter().collect());
    app.engagement.set_option_override(
        PlanningTaskId::ImportThreatModel,
        "path".into(),
        serde_json::json!(format!(
            "{}/owned-context.json",
            "complete-source-directory/".repeat(12)
        )),
    );
    app.router.setup_mut().set_cursor(2);
    app.set_shell_view(ShellView::Setup);
    (root, app)
}

fn draw(app: &ShellApp) -> String {
    let size = app.viewport();
    let mut terminal = Terminal::new(TestBackend::new(size.columns, size.rows)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .chunks(size.columns as usize)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

fn key(app: &mut ShellApp, code: KeyCode) {
    let update = app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE));
    assert!(update.handled && update.effects.is_empty());
}

#[test]
fn overview_keeps_every_readiness_row_and_start_in_all_supported_sizes() {
    let (_root, mut app) = import_setup();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let text = draw(&app);
        for label in [
            "Target",
            "Map plan",
            "Context import",
            "Model",
            "Credentials",
            "Prompt",
            "Budget",
            "Start Map",
        ] {
            assert!(
                text.contains(label),
                "{width}x{height}: missing {label}: {text}"
            );
        }
        assert!(text.contains("Tab details"), "{text}");
    }
}

#[test]
fn complete_import_explanation_survives_paging_and_plain_output() {
    let (_root, mut app) = import_setup();
    let detail = setup_readiness_model(&app).rows[2].detail.clone();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        app.router.setup_mut().set_detail_scroll(0);
        app.router.setup_mut().begin_editor(SetupEditor::Details);
        let mut seen = String::new();
        for _ in 0..40 {
            seen.push_str(&draw(&app));
            key(&mut app, KeyCode::PageDown);
        }
        let body = crate::renderer::workbench_primary_area(&app, Rect::new(0, 0, width, height));
        for fragment in wrap_text(&detail, body.width as usize) {
            assert!(
                seen.contains(&fragment),
                "{width}x{height}: missing {fragment:?}"
            );
        }
        assert!(seen.contains("PLANNED WORK"), "{seen}");
        let plain = crate::renderer::render_plain_app(&app, width as usize);
        for fragment in wrap_text(&detail, width as usize) {
            assert!(
                plain.contains(&fragment),
                "plain output omitted {fragment:?}"
            );
        }
        key(&mut app, KeyCode::Tab);
        assert_eq!(app.router.setup().cursor(), 2);
        assert!(!app.has_running_work());
    }
}
