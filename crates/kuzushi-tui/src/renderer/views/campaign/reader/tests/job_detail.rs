use super::*;
use serde_json::json;

fn named_reader(width: u16, height: u16) -> ShellApp {
    let mut app = large_job_reader(width, height);
    for (index, job) in app.router.campaign_mut().campaigns[0]
        .jobs
        .iter_mut()
        .enumerate()
    {
        job.display_label = Some(format!(
            "Boundary {} · pass {}/3",
            index / 3 + 1,
            index % 3 + 1
        ));
        job.input = json!({"tasks":["semgrep"],"threatModelRef":{"modelId":"recorded-context","revisionId":"frozen-r1","sha256":"sha256:owned"},"scanContextRef":null});
    }
    app
}

#[test]
fn inspection_back_next_and_resize_preserve_input_and_exact_recorded_context() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut app = named_reader(width, height);
        app.set_input("private Unicode draft 😀\nsecond line");
        for _ in 0..26 {
            press(&mut app, KeyCode::Char('j'));
        }
        assert!(draw(&app).contains("Boundary 9"));
        let list_text = campaign_lines(&app, Rect::new(0, 0, width, height))
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!list_text.contains('✓'), "{list_text}");
        press(&mut app, KeyCode::Enter);
        assert!(app.router.campaign().job_detail);
        let details = campaign_lines(&app, Rect::new(0, 0, width, height))
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            details.contains("Boundary 9")
                && details.contains("frozen-r1")
                && details.contains("recorded-context")
        );
        let continuous = details.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(details.contains("Model id: recorded-context"), "{details}");
        assert!(details.contains("Revision id: frozen-r1"), "{details}");
        assert!(!details.contains("\"modelId\""), "{details}");
        assert!(
            continuous.contains("explicitly omitted")
                && continuous.contains("Recorded cost: unknown"),
            "{details}"
        );
        assert!(draw(&app).contains("q jobs"), "{}", draw(&app));
        app.reduce_resize(40, 12);
        assert!(draw(&app).contains("q jobs"));
        press(&mut app, KeyCode::Char('k'));
        assert_eq!(app.router.campaign().selected_job, 25);
        assert_eq!(app.router.campaign().read_scroll, 0);
        press(&mut app, KeyCode::Char('q'));
        assert!(!app.router.campaign().job_detail && app.router.campaign().detail);
        assert!(draw(&app).contains("Boundary 9"));
        assert_eq!(app.input(), "private Unicode draft 😀\nsecond line");
        assert!(app.router.campaign().excluded.is_empty());
    }
}

#[test]
fn job_failure_and_unknown_cost_precede_full_input_references() {
    let mut app = named_reader(120, 36);
    let job = &mut app.router.campaign_mut().campaigns[0].jobs[0];
    job.state = "parked".into();
    job.reason = Some("Approved calls exhausted; remaining work is deferred".into());
    job.cost_usd = Some(0.0);
    job.provider_spend_unresolved = true;
    let detail = crate::ui_view_models::campaign_job_detail_lines(job).join("\n");
    assert!(
        detail.find("Approved calls exhausted").unwrap()
            < detail.find("Architecture context").unwrap()
    );
    assert!(detail.contains("Recorded cost: unknown") && !detail.contains("$0.00"));
    assert!(detail.contains("no run recorded"));
    assert!(detail.contains("model: not supplied"));
}

#[test]
fn paged_detail_keeps_full_notices_and_leaves_controls_to_reader_chrome() {
    for (width, height) in [(40, 12), (80, 24), (120, 36)] {
        let mut app = named_reader(width, height);
        press(&mut app, KeyCode::Enter);
        let notice =
            "Owned first notice\nOwned second notice\nOwned third notice\nOwned fourth notice";
        app.router.campaign_mut().notice = Some(notice.into());
        let area = Rect::new(0, 0, width, height);
        let body = super::super::super::campaign_lines::campaign_body_lines(&app, area)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        for line in notice.lines() {
            assert!(body.contains(line), "{width}x{height}: {body}");
        }
        assert!(!body.contains("▸ try:"), "{body}");
        let plain = crate::renderer::render_plain_app(&app, width as usize);
        assert!(plain.contains("> try:"), "{plain}");
        assert!(plain.contains("Study: owned"), "{plain}");
        assert!(
            plain.contains("r refresh") && plain.contains("q jobs"),
            "{plain}"
        );
        for line in notice.lines() {
            assert!(plain.contains(line), "{plain}");
        }
        let screen = draw(&app);
        assert!(
            screen.contains("K stop") && screen.contains("q jobs"),
            "{screen}"
        );
    }
}

#[test]
fn inspection_keeps_active_stop_and_pending_cancellation_visible() {
    let mut app = named_reader(40, 12);
    press(&mut app, KeyCode::Enter);
    assert!(draw(&app).contains("K stop"));
    app.router.campaign_mut().dispatcher_stop_requested = true;
    assert!(draw(&app).contains("Stop requested"));
    assert!(draw(&app).contains("q jobs"));
    app.router.campaign_mut().dispatcher_stop_requested = false;
    app.router.campaign_mut().dispatcher_pid = None;
    assert!(!draw(&app).contains("K stop"));
    assert!(draw(&app).contains("q jobs"));
}

#[test]
fn long_scope_names_cannot_hide_pass_numbers_in_fixed_job_rows() {
    for width in [40, 60, 80, 96, 120, 160] {
        let mut app = named_reader(width, 24);
        app.router.campaign_mut().campaigns[0].jobs[0].display_label = Some(format!(
            "{} · pass 3/3",
            "Long architecture boundary ".repeat(8)
        ));
        let row = selected_job_rows(&app, width);
        assert!(row.contains("pass 3/3"), "{width}: {row}");
    }
}

fn selected_job_rows(app: &ShellApp, width: u16) -> String {
    let lines = campaign_lines(app, Rect::new(0, 0, width, 24));
    assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
    let marker = lines
        .iter()
        .position(|line| line.to_string().starts_with("▸ "))
        .unwrap();
    lines[marker..marker + 2]
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn cancellation_reason_keeps_unstarted_jobs_distinct_from_admitted_attempts() {
    for width in [40, 60, 80, 96, 120, 160] {
        let mut app = named_reader(width, 24);
        for attempts in [0, 1] {
            let job = &mut app.router.campaign_mut().campaigns[0].jobs[0];
            job.state = "parked".into();
            job.reason = Some("canceled".into());
            job.attempts = attempts;
            job.dispatches = Some(attempts);
            let usage = crate::ui_view_models::campaign_job_attempt_summary(job);
            let row = selected_job_rows(&app, width);
            assert!(row.contains("parked: canceled"), "{width}: {row}");
            assert!(row.contains(&usage), "{width}: {row}");
        }
    }
}

#[test]
fn cancellation_labels_require_recorded_state_and_reason() {
    let mut app = named_reader(80, 24);
    let job = &mut app.router.campaign_mut().campaigns[0].jobs[0];
    job.display_label = Some("canceled · pass 1/3".into());
    job.state = "parked".into();
    job.reason = None;
    assert_eq!(
        crate::ui_view_models::campaign_job_state_label(job),
        "parked"
    );
    job.reason = Some("canceled by another actor".into());
    assert_eq!(
        crate::ui_view_models::campaign_job_state_label(job),
        "parked"
    );
    job.state = "pending".into();
    job.reason = Some("canceled".into());
    assert_eq!(
        crate::ui_view_models::campaign_job_state_label(job),
        "pending"
    );
}
