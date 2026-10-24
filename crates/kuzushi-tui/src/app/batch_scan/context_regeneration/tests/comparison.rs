use super::*;
use crate::app::ContextComparisonView;
use crate::ui_view_models::study_context::comparison;
use ratatui::{backend::TestBackend, Terminal};

fn loaded_comparison() -> (tempfile::TempDir, ShellApp, ThreatModelRef) {
    let (root, mut app, parent) = fixture();
    let candidate = edited_candidate(&mut app, root.path(), parent.clone());
    app.compare_study_context();
    let read = dispatch(
        &app,
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":parent}),
    );
    app.cache_study_context_preview(&read["data"]);
    (root, app, candidate)
}

fn comparison(app: &ShellApp) -> &crate::app::StudyContextComparison {
    app.study_context_picker()
        .unwrap()
        .comparison
        .as_ref()
        .unwrap()
}

fn frame_text(app: &ShellApp, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    format!("{:?}", terminal.backend().buffer())
}

#[test]
fn comparison_views_keep_independent_cursors_and_accept_only_a_complete_read() {
    let (_root, mut app, candidate) = loaded_comparison();
    app.reduce_resize(40, 12);
    app.handle_context_comparison_key(KeyCode::End);
    let text_cursor = comparison(&app).cursor();
    app.handle_context_comparison_key(KeyCode::Tab);
    assert_eq!(comparison(&app).view, ContextComparisonView::Structure);
    app.handle_context_comparison_key(KeyCode::Down);
    app.handle_context_comparison_key(KeyCode::End);
    let graph_cursor = comparison(&app).cursor();
    app.handle_context_comparison_key(KeyCode::BackTab);
    assert_eq!(comparison(&app).cursor(), text_cursor);
    app.handle_context_comparison_key(KeyCode::Tab);
    assert_eq!(comparison(&app).cursor(), graph_cursor);
    app.context_comparison_failed("threat-model:read", "Owned failed refresh");
    app.handle_context_comparison_key(KeyCode::Char('a'));
    assert_eq!(comparison(&app).candidate, candidate);
    let retry = app.handle_context_comparison_key(KeyCode::Enter).unwrap();
    assert!(matches!(
        retry.effects.as_slice(),
        [ShellEffect::PrepareRunTool(_)]
    ));
    assert_eq!(comparison(&app).view, ContextComparisonView::Structure);
    assert_eq!(comparison(&app).cursor(), graph_cursor);
    assert!(!comparison(&app).ready());
}

#[test]
fn comparison_layout_and_key_paging_reach_every_line_at_six_sizes() {
    let (_root, mut app, candidate) = loaded_comparison();
    app.set_input("preserved operator draft");
    app.set_cursor(9);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        for view in ContextComparisonView::ALL {
            while comparison(&app).view != view {
                app.handle_context_comparison_key(KeyCode::Tab);
            }
            app.handle_context_comparison_key(KeyCode::Home);
            let layout = comparison::layout(
                crate::ui_view_models::study_config::study_config_area(width, height),
            );
            let lines = comparison::selected_lines(comparison(&app), layout.detail.width as usize);
            let mut reached = vec![false; lines.len()];
            loop {
                let offset = comparison(&app).cursor().scroll;
                for row in reached
                    .iter_mut()
                    .skip(offset)
                    .take(layout.detail.height as usize)
                {
                    *row = true;
                }
                let screen = frame_text(&app, width, height);
                assert!(
                    screen.contains("COMPARE SAVED CONTEXT"),
                    "{width}x{height}: {screen}"
                );
                assert!(
                    screen.contains("PgUp/Dn") && screen.contains("Tab view"),
                    "{screen}"
                );
                assert!(screen.contains("Esc back"), "{width}x{height}: {screen}");
                app.handle_context_comparison_key(KeyCode::PageDown);
                if comparison(&app).cursor().scroll == offset {
                    break;
                }
            }
            assert!(reached.iter().all(|row| *row), "{width}x{height} {view:?}");
            app.handle_context_comparison_key(KeyCode::End);
            assert_eq!(
                comparison(&app).cursor().scroll,
                lines.len().saturating_sub(layout.detail.height as usize)
            );
        }
    }
    app.handle_context_comparison_key(KeyCode::Esc);
    assert_eq!(
        app.study_context_picker().unwrap().selected.as_ref(),
        Some(&candidate)
    );
    assert_eq!((app.input(), app.cursor()), ("preserved operator draft", 9));
    assert!(!app.has_running_work());
}
