use super::*;
use crate::{
    app::{Msg, TermEvent},
    InputMode, TerminalViewport,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::V2Config;
use ratatui::{backend::TestBackend, Terminal};

const SIZES: &[(u16, u16)] = &[(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)];

fn request(work: bool) -> PendingConfirm {
    let mut input = serde_json::json!({"investigationId":"operator-study","expectedRevision":2,
        "model":"openai-codex:gpt-5.5", "maxProviderCalls":12, "protectedReviewCalls":4,
        "reason":"Review the parser and shared dependencies"});
    if work {
        input["campaignId"] = serde_json::json!("three-pass-study");
        input["campaignJobs"] = serde_json::json!(3);
        input["maxJobAttempts"] = serde_json::json!(1);
        input["campaignPlanSha256"] = serde_json::json!(format!("sha256:{}", "a".repeat(64)));
    }
    let registry = kuzushi_core::modules::ModuleRegistry::with_v2_builtins();
    let descriptor = registry.resolve_tool("campaign:approve-allowance").unwrap();
    crate::app::descriptor_approval_confirm(descriptor, &input).unwrap()
}

fn app_at(columns: u16, rows: u16, work: bool) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_viewport(TerminalViewport { columns, rows });
    app.request_confirm(request(work));
    app
}

fn key(app: &mut ShellApp, code: KeyCode) {
    crate::app::update_and_execute_effects(
        app,
        Msg::Term(TermEvent::Key(KeyEvent::new(code, KeyModifiers::NONE))),
    );
}

fn model(app: &ShellApp) -> AllowanceReviewModel {
    let viewport = app.viewport();
    allowance_review_model(app, viewport.columns, viewport.rows).unwrap()
}

fn rendered(app: &ShellApp) -> String {
    let viewport = app.viewport();
    let mut terminal = Terminal::new(TestBackend::new(viewport.columns, viewport.rows)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    format!("{:?}", terminal.backend().buffer())
}

#[test]
fn allowance_review_pages_every_term_before_approval_at_all_six_sizes() {
    for &(columns, rows) in SIZES {
        for work in [false, true] {
            let mut app = app_at(columns, rows, work);
            let original = model(&app).lines;
            let mut seen = std::collections::BTreeSet::new();
            for _ in 0..original.len() {
                let page = model(&app);
                let screen = rendered(&app);
                assert!(screen.contains("PgUp/PgDn read · Esc cancel"), "{screen}");
                for index in page.offset..(page.offset + page.page_rows).min(page.lines.len()) {
                    assert!(
                        screen.contains(&page.lines[index]),
                        "missing {:?}: {screen}",
                        page.lines[index]
                    );
                    seen.insert(index);
                }
                if page.allows_approval() {
                    break;
                }
                key(&mut app, KeyCode::Char('y'));
                assert!(app.advisory().pending_confirm.is_some());
                key(&mut app, KeyCode::PageDown);
            }
            assert_eq!(seen.len(), original.len());
            assert!(rendered(&app).contains("y approve · n cancel"));
            key(&mut app, KeyCode::Char('y'));
            assert!(app.advisory().pending_confirm.is_none());
            assert!(!app.has_running_work());
        }
    }
}

#[test]
fn allowance_review_cancellation_preserves_draft_cursor_and_origin() {
    let mut app = app_at(40, 12, true);
    app.set_shell_view(crate::ShellView::Report);
    app.set_input_mode(InputMode::Prompt);
    app.set_input("my multiline\ndraft 世界");
    app.set_cursor(4);
    let route = app.router.workbench().clone();
    key(&mut app, KeyCode::PageDown);
    key(&mut app, KeyCode::Char('x'));
    crate::app::update_and_execute_effects(
        &mut app,
        Msg::Term(TermEvent::Paste("y\nnew text".into())),
    );
    key(&mut app, KeyCode::Esc);
    assert!(app.advisory().pending_confirm.is_none());
    assert_eq!(app.shell_view(), crate::ShellView::Report);
    assert_eq!(app.router.workbench(), &route);
    assert_eq!(app.input(), "my multiline\ndraft 世界");
    assert_eq!(app.cursor(), 4);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert!(!app.has_running_work());
}

#[test]
fn allowance_review_reflow_clamps_reading_and_rechecks_approval() {
    let mut app = app_at(160, 48, true);
    assert!(model(&app).allows_approval());
    app.set_viewport(TerminalViewport {
        columns: 40,
        rows: 12,
    });
    assert!(!model(&app).allows_approval());
    key(&mut app, KeyCode::Char('y'));
    assert!(app.advisory().pending_confirm.is_some());
    key(&mut app, KeyCode::End);
    assert!(model(&app).allows_approval());
    app.set_viewport(TerminalViewport {
        columns: 60,
        rows: 20,
    });
    assert!(model(&app).offset <= model(&app).max_offset);
    key(&mut app, KeyCode::Home);
    assert_eq!(model(&app).offset, 0);
    app.request_confirm(request(false));
    assert_eq!(app.advisory().confirm_scroll, 0);
}

#[test]
fn allowance_review_rejects_remembered_approval_and_modified_paging() {
    let mut app = app_at(40, 12, true);
    crate::app::update_and_execute_effects(
        &mut app,
        Msg::Term(TermEvent::Key(KeyEvent::new(
            KeyCode::PageDown,
            KeyModifiers::CONTROL,
        ))),
    );
    assert_eq!(model(&app).offset, 0);
    key(&mut app, KeyCode::End);
    key(&mut app, KeyCode::Char('Y'));
    assert!(app.advisory().pending_confirm.is_some());
    assert!(app.resolve_confirm(true, true).is_none());
}

#[test]
fn allowance_review_plain_is_exhaustive_and_does_not_depend_on_scroll() {
    let mut app = app_at(40, 12, true);
    key(&mut app, KeyCode::End);
    let text = crate::renderer::render_plain_app(&app, 40);
    assert!(text.contains("REVIEW PLAN & ALLOWANCE"));
    for expected in [
        "Total provider calls: 12",
        "Protected review calls: 4",
        "Dollar ceiling: not enforced;",
        "starts no jobs.",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    let joined = text.split_whitespace().collect::<String>();
    assert!(joined.contains(&format!("sha256:{}", "a".repeat(64))));
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains("resize"));
}

#[test]
fn allowance_review_does_not_cover_quit_disclosure_or_other_approvals() {
    let mut app = app_at(40, 12, true);
    app.set_shell_view(crate::ShellView::QuitConfirm);
    assert!(!rendered(&app).contains("REVIEW PLAN & ALLOWANCE"));
    app.advisory_mut().pending_confirm.as_mut().unwrap().kind = ConfirmKind::NetworkEgress;
    assert!(allowance_review_model(&app, 40, 12).is_none());
}

#[test]
fn allowance_review_mouse_reads_terms_without_changing_the_hidden_surface() {
    use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
    let mut app = app_at(40, 12, true);
    app.set_shell_view(crate::ShellView::Workbench);
    let route = app.router.workbench().clone();
    for kind in [
        MouseEventKind::Down(MouseButton::Left),
        MouseEventKind::ScrollDown,
    ] {
        crate::app::update_and_execute_effects(
            &mut app,
            Msg::Term(TermEvent::Mouse(MouseEvent {
                kind,
                column: 20,
                row: 5,
                modifiers: KeyModifiers::NONE,
            })),
        );
    }
    assert_eq!(app.router.workbench(), &route);
    assert_eq!(model(&app).offset, 1);
    assert!(app.advisory().pending_confirm.is_some());
}
