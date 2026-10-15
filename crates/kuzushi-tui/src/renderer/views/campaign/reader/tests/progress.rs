use super::*;

#[test]
fn short_job_details_keep_the_parent_workload_on_wide_and_narrow_terminals() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut app = large_job_reader(width, height);
        let deck = app.router.campaign_mut();
        deck.campaigns[0].jobs.truncate(3);
        deck.job_detail = true;
        let screen = draw(&app);
        assert!(
            screen.contains("Jobs: 3 · 3 planned"),
            "{width}x{height}: {screen}"
        );
        assert!(screen.contains("q jobs"), "{width}x{height}: {screen}");
        assert_eq!(app.router.campaign().selected_job, 0);
    }
}

#[test]
fn completed_counts_survive_paging_in_prompt_and_navigation_at_every_size() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        for mode in [crate::InputMode::Prompt, crate::InputMode::Navigate] {
            let mut app = large_job_reader(width, height);
            app.set_input_mode(mode);
            app.set_input("private retained draft");
            app.set_cursor(7);
            for job in &mut app.router.campaign_mut().campaigns[0].jobs {
                job.state = "completed".into();
            }
            for offset in [0, 10, usize::MAX] {
                app.router.campaign_mut().read_scroll = offset;
                let screen = draw(&app);
                assert!(
                    screen.contains("Jobs: 27 · 27 completed"),
                    "{width}x{height}: {screen}"
                );
                assert_eq!((app.input(), app.cursor()), ("private retained draft", 7));
                assert_eq!(app.router.campaign().selected_job, 0);
            }
        }
    }
}

#[test]
fn mixed_work_keeps_every_recorded_state_readable_without_claiming_completion() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut app = large_job_reader(width, height);
        for (index, state) in ["completed", "running", "failed", "parked"]
            .iter()
            .enumerate()
        {
            app.router.campaign_mut().campaigns[0].jobs[index].state = (*state).into();
        }
        let mut seen = String::new();
        for _ in 0..40 {
            let screen = draw(&app);
            assert!(screen.contains("Jobs: 27"), "{width}x{height}: {screen}");
            assert!(!screen.contains("27 completed"));
            seen.push_str(&screen);
            press(&mut app, KeyCode::PageDown);
        }
        let text = seen.split_whitespace().collect::<Vec<_>>().join(" ");
        for state in [
            "1 completed",
            "1 running",
            "1 failed",
            "1 parked",
            "23 planned",
        ] {
            assert!(
                text.contains(state),
                "{width}x{height}: missing {state}\n{text}"
            );
        }
    }
}

#[test]
fn list_position_does_not_show_a_selected_campaign_as_the_whole_list() {
    let mut app = large_job_reader(40, 12);
    app.router.campaign_mut().detail = false;
    let heading =
        super::super::super::progress::reader_heading(app.router.campaign(), 0, 3, 20, 40);
    assert_eq!(heading, " rows 1-3/20 · PgUp/PgDn");
    assert!(!heading.contains("Jobs:"));
}
