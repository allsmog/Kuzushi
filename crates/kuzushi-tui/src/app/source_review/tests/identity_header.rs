use super::*;
use ratatui::{backend::TestBackend, Terminal};

#[test]
fn captured_revision_stays_visible_through_every_verdict_step_and_viewport() {
    let (_root, mut app) = fixture();
    app.set_input("held composer draft");
    app.set_cursor(3);
    app.open_current_source_review();
    let form = app.source_review_form_mut().unwrap();
    form.capture = Some(serde_json::json!({
        "sourceRef":"owned-capture",
        "citedSourceCode":"Owned frozen text.\n",
        "reviewedSource":{"sourceGit":{
            "sha":"c557cdbf94b931ecc250b33d33d793f79036a908", "dirty":true
        }}
    }));
    form.reason
        .insert("Owned multiline reason.\nUncertainty remains.");
    let reason_cursor = form.reason.cursor();
    for mode in [
        SourceReviewMode::Reading,
        SourceReviewMode::Verdict,
        SourceReviewMode::Reason,
        SourceReviewMode::Confirm,
        SourceReviewMode::Saving,
        SourceReviewMode::Saved,
    ] {
        app.source_review_form_mut().unwrap().mode = mode;
        app.source_review_form_mut().unwrap().scroll = 100;
        for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| crate::renderer::render_app(frame, &app))
                .unwrap();
            let rows: Vec<String> = terminal
                .backend()
                .buffer()
                .content
                .chunks(width as usize)
                .take(4)
                .map(|row| row.iter().map(|cell| cell.symbol()).collect())
                .collect();
            let header = rows.join("\n");
            assert!(
                header.contains("SHA c557cdbf94b9 · dirty"),
                "{mode:?} {width}x{height}: {header}"
            );
            assert!(
                header.contains("note.txt:1"),
                "{mode:?} {width}x{height}: {header}"
            );
        }
    }
    let form = app.source_review_form().unwrap();
    assert_eq!(
        form.reason.text(),
        "Owned multiline reason.\nUncertainty remains."
    );
    assert_eq!(form.reason.cursor(), reason_cursor);
    assert_eq!(app.input(), "held composer draft");
    assert_eq!(app.cursor(), 3);
    assert!(form.decision_id.is_none());
}

#[test]
fn unrecorded_git_and_long_unicode_paths_remain_honest_in_header_and_plain_output() {
    use unicode_width::UnicodeWidthStr;
    let (_root, mut app) = fixture();
    app.open_current_source_review();
    let form = app.source_review_form_mut().unwrap();
    form.file = format!("{}note.txt", "目录e\u{301}/".repeat(100));
    form.capture = Some(serde_json::json!({"reviewedSource":{"treeHash":"b".repeat(64)}}));
    for width in [38, 58, 78, 94, 118, 158] {
        let rows = crate::ui_view_models::source_review::source_review_header_lines(form, width);
        assert!(rows.iter().all(|row| row.width() <= width));
        assert!(rows[1].ends_with("note.txt:1"));
        assert_eq!(rows[2], "Content bbbbbbbbbbbb · Git unknown");
    }
    let plain = crate::ui_view_models::source_review::source_review_plain_lines(form).join("\n");
    assert!(plain.contains(&form.file));
    assert!(plain.contains("Git unknown"));
    assert!(!plain.contains(" · clean"));
    assert!(!plain.contains('\u{1b}'));
}
