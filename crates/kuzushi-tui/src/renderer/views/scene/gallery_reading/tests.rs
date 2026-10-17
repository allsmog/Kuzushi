use super::*;
use crate::TerminalViewport;
use kuzushi_core::V2Config;
use serde_json::json;

fn app_with_long_row() -> (tempfile::TempDir, ShellApp) {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.cache_tool_snapshot("worklist:rank", &json!({"data": {
        "rows": [{"path": "owned/".repeat(50) + "component.rs", "line": 12, "score": 0.8, "rank": 1,
            "citations": [{"contributor": "systemsHunt", "raw": 40.0, "rawDisplay": "score 40", "normalized": 0.5, "normalization": "rank", "reasons": []}]}],
        "rankedTotal": 1, "contributors": {"systemsHunt": "live"}, "unranked": [], "degraded": []
    }}));
    app.set_shell_view(ShellView::Scene);
    app.router.scene_mut().set_page(VizPage::Worklist);
    app.set_viewport(TerminalViewport::new(40, 12));
    (temp, app)
}

#[test]
fn repeated_resize_keeps_the_original_continuation_and_composer() {
    let (_temp, mut app) = app_with_long_row();
    app.router.default_scroll_mut().set(7);
    let before = capture_gallery_reading(&app).unwrap();
    app.set_input("unsubmitted draft");
    app.set_cursor(4);
    for (width, height) in [(120, 36), (60, 20), (160, 48), (96, 89), (40, 12)] {
        app.set_viewport(TerminalViewport::new(width, height));
        let position = capture_gallery_reading(&app).unwrap();
        assert_eq!(position.anchor, before.anchor, "{width}x{height}");
        assert_eq!(app.shell_view(), ShellView::Scene);
    }
    assert_eq!(app.router.default_scroll().offset(), 7);
    assert_eq!(app.input(), "unsubmitted draft");
    assert_eq!(app.cursor(), 4);
}

#[test]
fn moving_after_resize_replaces_the_remembered_continuation() {
    let (_temp, mut app) = app_with_long_row();
    app.router.default_scroll_mut().set(7);
    app.set_viewport(TerminalViewport::new(60, 20));
    app.router.default_scroll_mut().set(0);
    app.set_viewport(TerminalViewport::new(40, 12));
    assert_eq!(app.router.default_scroll().offset(), 0);
}

#[test]
fn end_then_one_line_up_moves_from_the_real_tail() {
    let (_temp, mut app) = app_with_long_row();
    app.router.default_scroll_mut().tail();
    let up = gallery_line_offset(&app, -1).unwrap();
    let canvas = line_canvas(&app).unwrap();
    let rows = page_body_rows(&app, canvas.area, canvas.page);
    let tail = rows.normalized_scroll(canvas.visible, u16::MAX as usize);
    assert_eq!(up as usize, tail - 1);
}

#[test]
fn frame_pages_and_other_views_keep_their_own_readers() {
    let (_temp, mut app) = app_with_long_row();
    app.router.scene_mut().set_page(VizPage::Dfd);
    assert!(capture_gallery_reading(&app).is_none());
    assert!(gallery_line_offset(&app, 1).is_none());
    app.set_shell_view(ShellView::Logs);
    assert!(capture_gallery_reading(&app).is_none());
}

#[test]
fn repeating_the_same_viewport_does_not_reproject_a_position() {
    let (_temp, mut app) = app_with_long_row();
    assert!(app.ui().gallery_reading().is_some());
    app.ui_mut().set_gallery_reading(None);
    app.set_viewport(TerminalViewport::new(40, 12));
    assert!(app.ui().gallery_reading().is_none());
}
