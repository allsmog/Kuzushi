use super::*;
use crate::{InputMode, ShellApp, ShellView};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};

fn detail_app(width: u16, height: u16) -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join(".kuzushi");
    std::fs::create_dir_all(&state).unwrap();
    let description = (0..25)
        .map(|i| format!("evidence-{i:02}"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(state.join("threat-model.json"),serde_json::to_vec(&serde_json::json!({"systemContext":"Owned reading fixture.","dfd":{"nodes":[{"id":"owned","name":"Owned component","description":description,"purpose":"Operator reading","type":"process","trustZone":"owned"}],"flows":[],"trustBoundaries":[]},"threats":[]})).unwrap()).unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    app.hydrate_all_view_data_for_test();
    app.set_shell_view(ShellView::Scene);
    app.router
        .scene_mut()
        .set_page(crate::scene3d::VizPage::Dfd);
    app.set_input_mode(InputMode::Navigate);
    app.reduce_resize(width, height);
    app.set_input("held λ draft");
    app.set_cursor(4);
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
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

fn press(app: &mut ShellApp, code: KeyCode) {
    app.reduce_key(KeyEvent::new(code, KeyModifiers::empty()));
}

#[test]
fn keyboard_dfd_paging_reaches_every_visible_detail_row_and_clamps_at_the_tail() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let (_root, mut app) = detail_app(width, height);
        let Some(reader) = dfd_detail_scroll(&app) else {
            assert!(draw(&app).contains("Resize to read selected details"));
            let before = app.router.scene().dfd_detail_scroll();
            press(&mut app, KeyCode::PageDown);
            assert_eq!(app.router.scene().dfd_detail_scroll(), before);
            continue;
        };
        let mut seen = String::new();
        let mut samples = Vec::new();
        for tick in 0..40 {
            let frame = draw(&app);
            if tick < 6 {
                samples.push(format!(
                    "tick={tick} scroll={} page={} max={} body={:?} frame={frame}",
                    app.router.scene().dfd_detail_scroll(),
                    reader.page_rows,
                    reader.max_offset,
                    gallery_body_area(&app)
                ));
            }
            seen.push_str(&frame);
            press(&mut app, KeyCode::PageDown);
            assert!(app.router.scene().dfd_detail_scroll() <= reader.max_offset);
        }
        for i in 0..25 {
            assert!(
                seen.contains(&format!("evidence-{i:02}")),
                "{width}x{height}: missing {i}; {samples:?}"
            );
        }
        assert_eq!(app.router.scene().dfd_detail_scroll(), reader.max_offset);
        press(&mut app, KeyCode::PageUp);
        assert_eq!(
            app.router.scene().dfd_detail_scroll(),
            reader.max_offset.saturating_sub(reader.page_rows.min(10))
        );
        assert_eq!((app.input(), app.cursor()), ("held λ draft", 4));
    }
}
