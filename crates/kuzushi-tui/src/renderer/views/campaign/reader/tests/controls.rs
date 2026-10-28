use super::*;

#[test]
fn paged_reader_separates_primary_actions_from_navigation_at_all_six_sizes() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut app = large_job_reader(width, height);
        app.set_input("held reader draft λ");
        app.router.campaign_mut().notice = Some("Owned source notice\n".repeat(100));
        let screen = draw(&app);
        assert!(
            screen.contains("R report") && screen.contains("a plan/allowance"),
            "{width}x{height}: {screen}"
        );
        assert!(screen.contains("K stop"), "{width}x{height}: {screen}");
        assert!(!screen.contains("▸ try:"), "{screen}");
        if height > 18 {
            let text = primary_controls(&app, width)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                !text.contains("PgUp") && !text.contains("Enter") && !text.contains("q list"),
                "{text}"
            );
            assert!(screen.contains("PgUp/PgDn"), "{width}x{height}: {screen}");
        }
        press(&mut app, KeyCode::Enter);
        assert!(
            draw(&app).contains("q jobs"),
            "{width}x{height}: {}",
            draw(&app)
        );
        press(&mut app, KeyCode::Char('q'));
        assert!(!app.router.campaign().job_detail);
        assert_eq!(app.input(), "held reader draft λ");
    }
}

#[test]
fn prompt_reader_names_navigate_instead_of_advertising_immediate_letter_actions() {
    let mut app = large_job_reader(120, 36);
    app.set_input_mode(crate::InputMode::Prompt);
    app.set_input("draft owns letters R a r K");
    let controls = primary_controls(&app, 120)
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(controls.contains("Esc Navigate"));
    assert!(!controls.contains("R report") && !controls.contains("K stop"));
    assert!(draw(&app).contains("draft owns letters R a r K"));
}

#[test]
fn normal_readers_keep_palette_exit_and_paging_visible_in_both_detail_levels() {
    for (width, height) in [(60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut app = large_job_reader(width, height);
        app.set_input("held navigation draft 😀");
        for job_detail in [false, true] {
            app.router.campaign_mut().job_detail = job_detail;
            let screen = draw(&app);
            for hint in ["Ctrl+G palette", "Ctrl+C exit", "PgUp/PgDn"] {
                assert!(
                    screen.contains(hint),
                    "{width}x{height}, detail {job_detail}: {screen}"
                );
            }
            assert_eq!(app.input(), "held navigation draft 😀");
        }
    }
}
