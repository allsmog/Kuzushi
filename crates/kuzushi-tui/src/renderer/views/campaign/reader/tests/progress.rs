use super::*;

#[test]
fn selected_job_identity_remains_pinned_at_the_beginning_and_end_of_every_size() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut app = large_job_reader(width, height);
        let deck = app.router.campaign_mut();
        deck.campaigns[0].jobs.truncate(3);
        deck.selected_job = 1;
        deck.job_detail = true;
        deck.campaigns[0].jobs[1].display_label = Some("認証コンテキスト · pass 2/3".into());
        for offset in [0, 10, usize::MAX] {
            app.router.campaign_mut().read_scroll = offset;
            let screen = draw(&app);
            assert!(screen.contains("Job:"), "{width}x{height}: {screen}");
            assert!(screen.contains("pass 2/3"), "{width}x{height}: {screen}");
            assert!(
                screen.contains("Jobs: 3 · 3 planned"),
                "{width}x{height}: {screen}"
            );
            assert!(screen.contains("q jobs"), "{width}x{height}: {screen}");
        }
    }
}

#[test]
fn a_recorded_job_without_a_display_label_keeps_its_literal_identity_pinned() {
    let mut app = large_job_reader(40, 12);
    let deck = app.router.campaign_mut();
    deck.job_detail = true;
    deck.campaigns[0].jobs[0].display_label = None;
    deck.campaigns[0].jobs[0].job_id = "held-2".into();
    deck.read_scroll = usize::MAX;
    let screen = draw(&app);
    assert!(screen.contains("Job: held-2"), "{screen}");
}

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

#[test]
fn paged_jobs_keep_the_selected_study_identity_in_prompt_and_navigation_modes() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        for mode in [crate::InputMode::Prompt, crate::InputMode::Navigate] {
            let mut app = large_job_reader(width, height);
            app.set_input_mode(mode);
            app.router.campaign_mut().campaigns[0].campaign_id =
                "study-1793100802429-4da4587e".into();
            for offset in [0, 10, usize::MAX] {
                app.router.campaign_mut().read_scroll = offset;
                let screen = draw(&app);
                assert!(
                    screen.contains("study-1793100802429-4da4587e"),
                    "{width}x{height}: {screen}"
                );
                assert!(screen.contains("Jobs: 27"), "{width}x{height}: {screen}");
            }
        }
    }
}

#[test]
fn paged_job_lists_keep_view_and_current_index_status_after_cancellation() {
    for (width, height) in [(96, 89), (120, 36), (160, 48)] {
        let mut app = large_job_reader(width, height);
        app.domain_mut().context_view_mut().exists = true;
        app.domain_mut().context_view_mut().freshness =
            Some(kuzushi_core::context::ContextSnapshotFreshness::Current);
        app.router.campaign_mut().notice = Some(
            "Stopped by operator: 1 completed, 2 parked. Consumed attempts remain recorded.".into(),
        );
        for offset in [0, 12, usize::MAX] {
            app.router.campaign_mut().read_scroll = offset;
            let screen = draw(&app);
            assert!(screen.contains("Study jobs"), "{width}x{height}: {screen}");
            assert!(
                screen.contains("repo index ready"),
                "{width}x{height}: {screen}"
            );
            assert!(
                screen.contains("Stopped by operator"),
                "{width}x{height}: {screen}"
            );
        }
    }
}

#[test]
fn unread_study_charges_stay_unknown_while_paging_at_every_size() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut app = large_job_reader(width, height);
        app.router.campaign_mut().campaigns[0].jobs[0].state = "completed".into();
        for offset in [0, 12, usize::MAX] {
            app.router.campaign_mut().read_scroll = offset;
            let screen = draw(&app);
            assert!(
                screen.contains("cost unavailable"),
                "{width}x{height}: {screen}"
            );
            assert!(
                !screen.contains("$0.00 spent"),
                "{width}x{height}: {screen}"
            );
        }
    }
}
