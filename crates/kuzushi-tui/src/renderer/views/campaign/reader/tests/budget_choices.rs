use super::*;

#[test]
fn failure_is_shown_once_at_the_top_and_pinned_after_paging() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36)] {
        let mut app = large_job_reader(width, height);
        app.router.campaign_mut().notice = Some(format!(
            "Allowance reached.\n{}",
            "Retained accounting and plan details.\n".repeat(20)
        ));
        app.router.campaign_mut().dispatcher_failure = Some((
            std::path::PathBuf::from("owned"),
            "owned".into(),
            app.router.campaign().notice.clone().unwrap(),
        ));
        let initial = draw(&app);
        assert_eq!(
            initial.matches("Allowance reached.").count(),
            1,
            "{initial}"
        );
        assert!(!initial.contains("Action result"), "{initial}");
        press(&mut app, KeyCode::PageDown);
        let paged = draw(&app);
        assert!(paged.contains("Allowance reached."), "{paged}");
        assert!(paged.contains("Action result"), "{paged}");
    }
}

#[test]
fn report_and_allowance_controls_stay_visible_when_work_stops() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36)] {
        for state in ["parked", "failed", "completed"] {
            let mut app = large_job_reader(width, height);
            let deck = app.router.campaign_mut();
            deck.dispatcher_pid = None;
            for job in &mut deck.campaigns[0].jobs {
                job.state = state.into();
            }
            let screen = draw(&app);
            assert!(screen.contains("R report"), "{width}x{height}: {screen}");
            assert!(screen.contains("a plan/allowance"), "{screen}");
        }
    }
}

#[test]
fn report_shortcut_preserves_prompt_input_and_returns_to_the_same_job() {
    let mut app = large_job_reader(40, 12);
    app.router.campaign_mut().dispatcher_pid = None;
    app.router.campaign_mut().selected_job = 7;
    let jobs = app.router.campaign().campaigns[0].jobs.clone();
    app.set_input_mode(crate::InputMode::Prompt);
    app.set_input("draft ");
    press(&mut app, KeyCode::Char('R'));
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(app.input(), "draft R");
    app.set_input_mode(crate::InputMode::Navigate);
    press(&mut app, KeyCode::Char('R'));
    assert_eq!(app.shell_view(), ShellView::Report);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(app.input_mode(), crate::InputMode::Navigate);
    assert_eq!(app.input(), "draft R");
    assert_eq!(app.router.campaign().selected_job, 7);
    assert_eq!(app.router.campaign().campaigns[0].jobs, jobs);
    assert!(app.router.campaign().dispatcher_pid.is_none());
}

#[test]
fn unchanged_single_worker_plan_does_not_warn_about_parallel_execution() {
    let mut app = large_job_reader(120, 36);
    let campaign = &mut app.router.campaign_mut().campaigns[0];
    campaign.kind = Some(kuzushi_core::capabilities::campaign::SCAN_BATCH_KIND.into());
    campaign.requested_workers = Some(1);
    campaign.effective_workers = Some(1);
    campaign.parallel_safety_reason = Some("unresolved parallel resource claims".into());
    let text = crate::renderer::render_plain_app(&app, 120);
    assert!(text.contains("workers 1 frozen (requested 1)"));
    assert!(!text.contains("parallel safety"));
    app.router.campaign_mut().campaigns[0].requested_workers = Some(3);
    let clamped = crate::renderer::render_plain_app(&app, 120);
    assert!(clamped.contains("workers 1 frozen (requested 3)"));
    assert!(clamped.contains("parallel safety · unresolved parallel resource claims"));
}
