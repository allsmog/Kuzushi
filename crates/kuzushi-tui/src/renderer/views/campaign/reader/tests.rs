use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::V2Config;
use ratatui::{backend::TestBackend, Terminal};
mod budget_choices;
mod controls;
mod job_detail;
mod linked_study;
mod progress;

fn reader(width: u16, height: u16) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Campaign);
    app.set_input_mode(crate::InputMode::Navigate);
    app.set_viewport(crate::TerminalViewport::new(width, height));
    app.router.campaign_mut().notice = Some(
        (0..20)
            .map(|index| format!("observation-{index:02}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    app
}

fn press(app: &mut ShellApp, code: KeyCode) {
    assert!(
        app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE))
            .handled
    );
}

fn draw(app: &ShellApp) -> String {
    let size = app.viewport();
    let mut terminal = Terminal::new(TestBackend::new(size.columns, size.rows)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    buffer
        .content
        .chunks(size.columns as usize)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

fn large_job_reader(width: u16, height: u16) -> ShellApp {
    use serde_json::json;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join(".kuzushi/v3/campaigns/owned");
    std::fs::create_dir_all(&path).unwrap();
    let jobs = (0..27)
        .map(|index| {
            json!({
                "jobId": scope_job_id(index),
                "tool": "sast:scan",
                "input": {"scanScopeRef": {"scopeId": format!("m{:02}", index / 3 + 1)}}
            })
        })
        .collect::<Vec<_>>();
    std::fs::write(
        path.join("plan.json"),
        serde_json::to_vec(&json!({"kind":"scope-study","workers":1,"jobs":jobs})).unwrap(),
    )
    .unwrap();
    let snapshot = kuzushi_core::capabilities::campaign::snapshot::load_campaign_snapshot(
        root.path(),
        "owned",
    )
    .unwrap();
    let mut app = reader(width, height);
    let deck = app.router.campaign_mut();
    deck.notice = None;
    deck.campaigns = vec![snapshot];
    deck.detail = true;
    deck.dispatcher_pid = Some(123);
    app
}

fn scope_job_id(index: usize) -> String {
    let scope = if index < 24 {
        format!("m{:02}", index / 3 + 1)
    } else {
        "integration".into()
    };
    format!("{scope}-trial-{:03}", index % 3 + 1)
}

#[test]
fn large_fixed_job_controls_and_keyboard_selection_remain_visible() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48), (96, 89)] {
        let mut app = large_job_reader(width, height);
        app.set_input_mode(crate::InputMode::Prompt);
        app.set_input("retained campaign draft");
        press(&mut app, KeyCode::Esc);
        press(&mut app, KeyCode::Esc);
        assert!(
            app.reduce_key(KeyEvent::new(KeyCode::Char('7'), KeyModifiers::CONTROL))
                .handled
        );
        assert_eq!(app.input_mode(), crate::InputMode::Navigate);
        assert_eq!(app.input(), "retained campaign draft");
        assert!(
            draw(&app).contains("K stop"),
            "{width}x{height}: {}",
            draw(&app)
        );
        press(&mut app, KeyCode::Char('k'));
        for index in 0..27 {
            assert!(
                draw(&app).contains(&scope_job_id(index)),
                "Selected row hidden at {width}x{height}, job {index}: {}",
                draw(&app)
            );
            if index < 26 {
                press(&mut app, KeyCode::Char('j'));
            }
        }
        assert_eq!(app.input(), "retained campaign draft");
        assert_eq!(app.router.campaign().selected_job, 26);
        let deck = app.router.campaign_mut();
        for job in &mut deck.campaigns[0].jobs {
            job.state = "parked".into();
        }
        assert!(
            draw(&app).contains("work paused"),
            "Paused guidance hidden at {width}x{height}"
        );
        let screen = draw(&app);
        assert!(screen.contains("R report"), "{screen}");
        assert!(screen.contains("a plan/allowance"), "{screen}");
        assert!(!screen.contains("L resume"), "{screen}");
        for job in &mut app.router.campaign_mut().campaigns[0].jobs {
            job.state = "failed".into();
            job.attempts = 1;
        }
        let screen = draw(&app);
        assert!(screen.contains("work ended"), "{width}x{height}: {screen}");
        assert!(
            screen.contains("new work needs a new plan"),
            "{width}x{height}: {screen}"
        );
        assert!(!screen.contains("L resume"), "{width}x{height}: {screen}");
    }
}

#[test]
fn paging_reaches_every_observation_in_the_viewport_matrix() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48), (96, 89)] {
        let mut app = reader(width, height);
        let mut seen = String::new();
        for _ in 0..40 {
            seen.push_str(&draw(&app));
            press(&mut app, KeyCode::PageDown);
        }
        for index in 0..20 {
            assert!(
                seen.contains(&format!("observation-{index:02}")),
                "{width}x{height}: {seen}"
            );
        }
        if height == 12 {
            assert!(seen.contains("PgUp/PgDn"), "{seen}");
        }
    }
}

#[test]
fn dispatcher_failure_precedes_jobs_and_keeps_complete_recovery_readable() {
    let cause = "Frozen supporting context was prepared on different source; prepare and approve a new plan";
    let notice = format!("{cause}\nDispatcher stopped (exit status: 1).\nReview the recorded failure and current source before launching again. Details: campaigns/owned/logs/dispatcher.log");
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48), (96, 89)] {
        let mut app = large_job_reader(width, height);
        app.router.campaign_mut().dispatcher_pid = None;
        app.router.campaign_mut().notice = Some(notice.clone());
        app.router.campaign_mut().dispatcher_failure =
            Some((std::path::PathBuf::new(), "owned".into(), notice.clone()));
        let lines = campaign_lines(&app, Rect::new(0, 0, width, height));
        assert!(lines[0].to_string().contains("Frozen supporting context"));
        let mut seen = draw(&app);
        press(&mut app, KeyCode::PageDown);
        seen.push_str(&draw(&app));
        assert!(
            seen.contains("different source"),
            "{width}x{height}: {seen}"
        );
        for _ in 0..40 {
            press(&mut app, KeyCode::PageDown);
            seen.push_str(&draw(&app));
        }
        for fragment in wrap_text(&notice, usize::from(width.saturating_sub(2))) {
            assert!(
                seen.contains(&fragment),
                "{width}x{height}: missing {fragment:?}"
            );
        }
        assert_eq!(app.router.campaign().selected_job, 0);
        assert_eq!(app.router.campaign().campaigns[0].jobs.len(), 27);
    }
}

#[test]
fn compact_failure_reader_gives_recovery_text_at_least_five_body_rows() {
    let mut app = large_job_reader(40, 12);
    let notice="Frozen context was prepared on different source. Review the recorded failure before launching again.".to_string();
    app.router.campaign_mut().dispatcher_pid = None;
    app.router.campaign_mut().notice = Some(notice.clone());
    app.router.campaign_mut().dispatcher_failure =
        Some((std::path::PathBuf::new(), "owned".into(), notice));
    let scroll = campaign_reader_scroll(&app).unwrap();
    assert!(
        scroll.page_rows >= 5,
        "Only {} body rows remain for recovery",
        scroll.page_rows
    );
    let text = draw(&app);
    assert!(text.contains("different source"), "{text}");
    assert!(text.contains("r refresh"), "{text}");
    assert!(text.contains("Esc compose"), "{text}");
    assert!(text.contains("Ctrl+G commands"), "{text}");
}

#[test]
fn compact_reader_returns_to_composer_and_palette_without_losing_draft_or_position() {
    let mut app = large_job_reader(40, 12);
    app.set_input("retained draft");
    press(&mut app, KeyCode::PageDown);
    let scroll = app.router.campaign().read_scroll;
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.input_mode(), crate::InputMode::Prompt);
    assert!(draw(&app).contains("retained draft"));
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Esc);
    app.reduce_key(KeyEvent::new(KeyCode::Char('7'), KeyModifiers::CONTROL));
    assert_eq!(app.input_mode(), crate::InputMode::Navigate);
    assert!(draw(&app).contains("Esc compose"));
    app.reduce_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL));
    assert_eq!(app.shell_view(), ShellView::CommandPalette);
    assert!(!compact_campaign_reader(&app, Rect::new(0, 0, 40, 12)));
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(app.input(), "retained draft");
    assert_eq!(app.router.campaign().read_scroll, scroll);
}

#[test]
fn compact_reader_yields_to_questions_confirmation_and_study_editors() {
    let area = Rect::new(0, 0, 40, 12);
    let mut app = reader(40, 12);
    app.advisory_mut().pending_confirm = Some(crate::app::PendingConfirm {
        kind: crate::app::ConfirmKind::DescriptorEffect,
        tool: "owned:read".into(),
        target: "owned source".into(),
        rationale: None,
        allowlist: None,
        actor: None,
        remembered: false,
    });
    assert!(!compact_campaign_reader(&app, area));
    assert!(draw(&app).contains("CONFIRM"));
    app.advisory_mut().pending_confirm = None;
    app.set_agent_chat(Some(crate::app::AgentChatView {
        question: "Explain retained evidence".into(),
        answer: Some("Owned source summary".into()),
        ..Default::default()
    }));
    app.open_answers();
    assert!(!compact_campaign_reader(&app, area));
    assert!(draw(&app).contains("ANSWERS"));
    app.router.answers_mut().close();
    let root = tempfile::tempdir().unwrap();
    app.router.campaign_mut().batch_scan_config =
        Some(crate::app::BatchScanConfig::load(root.path(), None));
    assert!(!compact_campaign_reader(&app, area));
    assert!(draw(&app).contains("PLAN A STUDY"));
}

#[test]
fn compact_reader_matches_scroll_geometry_only_during_short_navigation() {
    let mut app = reader(40, 18);
    let short = Rect::new(0, 0, 40, 18);
    assert_eq!(campaign_reader_area(&app, short), short);
    let tall = Rect::new(0, 0, 40, 19);
    assert_eq!(
        campaign_reader_area(&app, tall),
        crate::renderer::workbench_primary_area(&app, tall)
    );
    app.set_input_mode(crate::InputMode::Prompt);
    assert_eq!(
        campaign_reader_area(&app, short),
        crate::renderer::workbench_primary_area(&app, short)
    );
}

#[test]
fn normal_height_keeps_compact_controls_out_of_the_primary_body() {
    let app = large_job_reader(60, 20);
    let body = crate::renderer::workbench_primary_area(&app, Rect::new(0, 0, 60, 20));
    assert!(body.height <= 18);
    assert!(!draw(&app).contains("Esc compose"));
}

#[test]
fn plain_campaign_output_is_exhaustive_from_a_short_navigation_viewport() {
    let mut app = reader(40, 12);
    app.set_input("held plain draft");
    let text = crate::renderer::render_plain_app(&app, 40);
    for index in 0..20 {
        assert!(text.contains(&format!("observation-{index:02}")), "{text}");
    }
    assert!(!text.contains("Esc compose"));
    assert_eq!(app.input(), "held plain draft");
}

#[test]
fn paged_job_lists_leave_commands_to_chrome_and_preserve_the_plain_document() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut app = large_job_reader(width, height);
        app.set_input("Unsubmitted reader draft");
        app.router.campaign_mut().notice = Some(format!(
            "First retained notice\n{}Last retained notice",
            "Retained detail.\n".repeat(usize::from(height))
        ));
        let area = Rect::new(0, 0, width, height);
        let body = super::super::campaign_lines::campaign_body_lines(&app, area)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!body.contains("▸ try:"), "{width}x{height}: {body}");
        assert!(body.contains("First retained notice") && body.contains("Last retained notice"));
        let plain = crate::renderer::render_plain_app(&app, width as usize);
        assert!(plain.contains("> try:"), "{width}x{height}: {plain}");
        assert!(plain.contains("First retained notice") && plain.contains("Last retained notice"));
        let screen = draw(&app);
        assert!(
            screen.contains("K stop") && screen.contains("R report"),
            "{screen}"
        );
        assert!(!screen.contains("▸ try:"), "{width}x{height}: {screen}");
        assert_eq!(app.input(), "Unsubmitted reader draft");
    }
}

#[test]
fn complete_campaign_summary_survives_actual_buffer_paging_at_every_size() {
    let campaign_id = "study-01234567890123456789-owned-immutable-plan";
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let mut app = large_job_reader(width, height);
        let campaign = &mut app.router.campaign_mut().campaigns[0];
        campaign.kind = Some(kuzushi_core::capabilities::campaign::SCAN_BATCH_KIND.into());
        campaign.campaign_id = campaign_id.into();
        campaign.requested_workers = Some(4);
        campaign.effective_workers = Some(1);
        campaign.parallel_safety_reason =
            Some("shared context requires workspace exclusivity".into());
        campaign.job_budget_usd = Some(5.0);
        campaign.provider_spend_unresolved = true;
        let mut screens = String::new();
        let mut body_text = String::new();
        let area = campaign_reader_area(&app, Rect::new(0, 0, width, height));
        for _ in 0..60 {
            let frame = draw(&app);
            for line in frame
                .lines()
                .take(area.height as usize)
                .filter(|line| line.starts_with("  ") || line.starts_with(" ── "))
            {
                body_text.push_str(line);
                body_text.push(' ');
            }
            screens.push_str(&frame);
            screens.push('\n');
            press(&mut app, KeyCode::PageDown);
        }
        let text = body_text.split_whitespace().collect::<Vec<_>>().join(" ");
        for expected in [
            "workers 1 frozen (requested 4)",
            "shared context requires workspace exclusivity",
            "provider cost evidence is incomplete; dollar total is unknown",
            "a running job crossing it is stopped and parked over-budget",
        ] {
            assert!(
                text.contains(expected),
                "{width}x{height}: missing {expected}\n{screens}"
            );
        }
        assert!(
            text.replace(' ', "").contains(campaign_id),
            "{width}x{height}: {screens}"
        );
    }
}

#[test]
fn campaign_overview_fits_terminal_columns_with_a_long_unicode_identity() {
    for width in [40, 60, 80, 96, 120, 160] {
        let mut app = large_job_reader(width, 24);
        app.router.campaign_mut().campaigns[0].campaign_id =
            "study-日本語-αβ-context-and-immutable-source-identity".into();
        for line in campaign_lines(&app, Rect::new(0, 0, width, 24)) {
            assert!(
                line.width() <= width as usize,
                "{width}: {} columns: {line}",
                line.width()
            );
        }
    }
}

#[test]
fn paging_recovers_from_the_tail_and_resize_without_changing_selection_or_draft() {
    let mut app = reader(40, 12);
    app.set_input("held operator draft");
    press(&mut app, KeyCode::Char('G'));
    press(&mut app, KeyCode::PageUp);
    let max = campaign_reader_scroll(&app).unwrap().max_offset;
    assert!(app.router.campaign().read_scroll < max);
    for _ in 0..100 {
        press(&mut app, KeyCode::PageDown);
    }
    assert_eq!(app.router.campaign().read_scroll, max);
    app.set_viewport(crate::TerminalViewport::new(80, 24));
    press(&mut app, KeyCode::PageUp);
    assert!(app.router.campaign().read_scroll < campaign_reader_scroll(&app).unwrap().max_offset);
    assert_eq!(app.router.campaign().selected_job, 0);
    assert_eq!(app.router.campaign().selected_campaign, 0);
    assert_eq!(app.input(), "held operator draft");
}

#[test]
fn blocked_action_remains_visible_while_the_deck_is_paged_without_changing_draft() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48), (96, 89)] {
        let mut app = reader(width, height);
        let history = app.router.campaign().notice.clone().unwrap();
        app.router.campaign_mut().notice = Some(format!(
            "launch failed: allowance exhausted; Review calls stay protected.\n{history}"
        ));
        app.set_input("held operator draft");
        assert!(
            draw(&app).contains("allowance exhausted"),
            "Hidden action result at {width}x{height}"
        );
        for _ in 0..10 {
            press(&mut app, KeyCode::PageDown);
            assert!(draw(&app).contains("allowance exhausted"));
        }
        assert_eq!(app.input(), "held operator draft");
        assert_eq!(app.router.campaign().selected_job, 0);
        assert_eq!(app.router.campaign().selected_campaign, 0);
    }
}

fn recent_history_reader(width: u16, height: u16) -> ShellApp {
    use kuzushi_core::capabilities::campaign::{trend, trend_history::TrendSnapshot};
    let mut app = reader(width, height);
    let deck = app.router.campaign_mut();
    deck.notice = None;
    deck.trend = Some(trend::trend_metrics_with_spend(
        &[],
        trend::WorkspaceCampaignSpend {
            observed_usd: 0.0,
            provider_spend_unresolved: true,
        },
    ));
    deck.trend_history = (0..90)
        .map(|ts_ms| TrendSnapshot {
            ts_ms,
            decided_findings: 3,
            confirmed_findings: 0,
            rejected_false_positives: 1,
            campaign_spend_usd: 0.0,
            provider_spend_unresolved: true,
        })
        .collect();
    app.set_input("held history draft");
    app
}

#[test]
fn recent_history_is_readable_in_every_viewport_without_changing_the_draft() {
    for (width, height) in [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48), (96, 89)] {
        let mut app = recent_history_reader(width, height);
        let mut seen = String::new();
        for _ in 0..12 {
            seen.push_str(&draw(&app));
            seen.push('\n');
            press(&mut app, KeyCode::PageDown);
        }
        let seen = seen.split_whitespace().collect::<Vec<_>>().join(" ");
        for phrase in [
            "HISTORY recent",
            "90 snapshot(s)",
            "spend >=",
            "spent (incomplete)",
        ] {
            assert!(
                seen.contains(phrase),
                "{width}x{height} omitted {phrase}: {seen}"
            );
        }
        press(&mut app, KeyCode::PageUp);
        assert_eq!(app.input(), "held history draft");
        assert_eq!(app.router.campaign().selected_campaign, 0);
        assert_eq!(app.router.campaign().selected_job, 0);
    }
}
