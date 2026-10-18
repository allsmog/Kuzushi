use super::*;
use crate::ui_view_models::scope_review::{scope_detail, scope_source_view, scope_title};

fn detail(app: &ShellApp) -> String {
    scope_detail(app.scope_review().unwrap()).join("\n")
}

fn title(app: &ShellApp) -> String {
    let state = app.scope_review().unwrap();
    scope_title(state, &scope_source_view(app, state))
}

#[test]
fn scope_edits_recompute_default_work_without_approving_or_starting_it() {
    let (root, mut app) = fixture();
    assert!(title(&app).contains("all: 3 jobs"));
    split(&mut app, root.path());
    assert!(title(&app).contains("all: 6 jobs"));
    assert!(detail(&app).contains("2 × 3 default passes = 6 jobs"));
    assert!(detail(&app).contains("Next study (focused): 3 jobs"));
    app.apply_scope_menu(3);
    fill_form(&mut app, &["Owned exclusion"]);
    let update = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), update).unwrap();
    assert!(title(&app).contains("all: 3 jobs"));
    assert!(detail(&app).contains("does not supply discovery work"));
    press(&mut app, KeyCode::Down);
    app.apply_scope_menu(3);
    fill_form(&mut app, &["Second owned exclusion"]);
    let update = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), update).unwrap();
    assert!(title(&app).contains("all: 0 jobs"));
    assert!(detail(&app).contains("No discovery files included"));
    assert!(detail(&app).contains("dollar cost are not estimated here"));
    assert!(app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .record
        .acceptance
        .is_none());
    assert!(app.findings().is_empty());
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn shared_context_is_free_of_discovery_jobs_until_explicitly_enabled() {
    let (root, mut app) = fixture();
    split(&mut app, root.path());
    let update = app.apply_scope_menu(13);
    finish(&mut app, root.path(), update).unwrap();
    assert!(title(&app).contains("all: 6 jobs"));
    let update = app.apply_scope_menu(6);
    finish(&mut app, root.path(), update).unwrap();
    assert!(title(&app).contains("all: 9 jobs"));
    assert!(detail(&app).contains("overlapping boundaries can repeat work"));
    let update = app.apply_scope_menu(6);
    finish(&mut app, root.path(), update).unwrap();
    assert!(title(&app).contains("all: 6 jobs"));
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn marked_preview_agrees_with_the_next_study_and_stays_visible_at_six_sizes() {
    let (root, mut app) = fixture();
    split(&mut app, root.path());
    app.open_scope_acceptance();
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::End);
    let update = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), update).unwrap();
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char(' '));
    assert!(detail(&app).contains("Next study (marked): 6 jobs"));
    for (width, height) in [(40, 11), (60, 19), (80, 23), (96, 88), (120, 35), (160, 47)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text = (0..width)
            .map(|x| buffer[(x, 0)].symbol())
            .collect::<String>();
        assert!(text.contains("all: 6 jobs"), "{width}x{height}: {text}");
        if width == 80 {
            let text = (0..height)
                .map(|y| {
                    (0..width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains("Next study (marked): 6 jobs"), "{text}");
        }
    }
    let update = press(&mut app, KeyCode::Char('p'));
    assert!(update.effects.is_empty());
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study.scope_draft.as_ref().unwrap().job_count(), 6);
    assert_eq!(config.requested_workers, 1);
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}
