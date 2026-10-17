use super::*;
use crate::scene3d::VizPage;

fn reading_app() -> (tempfile::TempDir, ShellApp) {
    let target = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.path().into()));
    let rows = (0..30)
        .map(|rank| {
            serde_json::json!({
                "path": format!("owned/part-{rank}.rs"), "rank": rank + 1,
                "citations": [], "score": 0.5
            })
        })
        .collect::<Vec<_>>();
    app.cache_tool_snapshot(
        "worklist:rank",
        &serde_json::json!({"data": {
            "rows": rows, "rankedTotal": 30, "unranked": [], "contributors": {}, "degraded": []
        }}),
    );
    app.set_shell_view(ShellView::Scene);
    app.router.scene_mut().set_page(VizPage::Worklist);
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    app.set_warn_notice(
        "inventory",
        "The saved inventory is partial; inspect the retained evidence.",
    );
    (target, app)
}

#[test]
fn compact_gallery_reserves_room_for_reading_and_visible_controls() {
    let (_target, app) = reading_app();
    let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let lines = rendered_buffer_rows(terminal.backend().buffer());
    let text = lines.join("\n");
    assert!(text.contains("PgUp/PgDn page"), "{text}");
    assert!(text.contains("q back"), "{text}");
    assert!(text.contains("Tab"), "{text}");
    let body = primary_body_area(&app, Rect::new(0, 0, 40, 12));
    let projected = crate::renderer::scene_line_page_viewport_lines(&app, body, 0).unwrap();
    let position = projected
        .iter()
        .position(|line| line.to_string().trim_start().starts_with("row"))
        .unwrap();
    assert!(projected.len() - position > 6, "{text}");
}

#[test]
fn compact_gallery_keeps_budget_controls_visible() {
    let (_target, mut app) = reading_app();
    app.advisory_mut().budget_halt = Some(crate::BudgetHalt {
        spent_usd: 1.0,
        limit_usd: 1.0,
    });
    assert!(!crate::ui_view_models::compact_gallery_reading(&app, 12));
    let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let text = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
    assert!(text.contains("COST CAP"), "{text}");
    assert!(text.contains("Esc inspect"), "{text}");
}

#[test]
fn compact_gallery_returns_session_chrome_for_drafts_active_work_and_decisions() {
    let (_target, mut app) = reading_app();
    assert!(crate::ui_view_models::compact_gallery_reading(&app, 12));
    app.set_input("held operator draft");
    assert!(!crate::ui_view_models::compact_gallery_reading(&app, 12));
    assert_eq!(
        crate::ui_view_models::status_footer_chrome_height(&app, 12),
        1
    );
    app.clear_input();
    app.set_planner_running(true);
    assert!(app.has_running_work());
    assert!(!crate::ui_view_models::compact_gallery_reading(&app, 12));
    app.set_planner_running(false);
    app.advisory_mut().pending_confirm = Some(crate::PendingConfirm {
        kind: crate::ConfirmKind::DescriptorEffect,
        tool: "workspace:export-findings".into(),
        target: "owned output".into(),
        rationale: None,
        allowlist: None,
        actor: None,
        remembered: false,
    });
    assert!(!crate::ui_view_models::compact_gallery_reading(&app, 12));
    assert_eq!(app.input(), "");
}
