use super::*;

#[test]
fn review_source_evidence_choice_is_explicit_and_never_changes_strategy_or_spending() {
    let (_root, mut app) = fixture();
    let before = app.router.campaign().batch_scan_config.clone().unwrap();
    assert!(app
        .handle_review_study_key(KeyCode::Char('e'))
        .effects
        .is_empty());
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config
        .notice
        .as_deref()
        .unwrap()
        .contains("Use s to choose standard"));
    assert_eq!(
        config.review_plan.as_ref().unwrap().input,
        before.review_plan.unwrap().input
    );
    app.handle_review_study_key(KeyCode::Char('s'));
    app.handle_review_study_key(KeyCode::Char('s'));
    app.handle_review_study_key(KeyCode::Char('e'));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    let input = &config.review_plan.as_ref().unwrap().input;
    assert_eq!(input["strategy"], "standard");
    assert_eq!(input["sourceEvidence"], "cited");
    assert_eq!(
        config.study.max_provider_calls,
        before.study.max_provider_calls
    );
    assert_eq!(
        config.study.protected_review_calls,
        before.study.protected_review_calls
    );
    assert!(config.study.allowance.is_none());
    assert!(!app.has_running_work());
}

#[test]
fn review_source_evidence_view_and_options_preserve_the_draft() {
    let (_root, mut app) = fixture();
    let input = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .review_plan
        .as_ref()
        .unwrap()
        .input
        .clone();
    app.handle_review_study_key(KeyCode::Char('v'));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.review_plan.as_ref().unwrap().show_evidence);
    assert!(crate::ui_view_models::review_study::review_study_lines(
        config,
        app.config().model.as_deref(),
        36
    )
    .join("\n")
    .contains("FROZEN SOURCE INPUT"));
    app.handle_review_study_key(KeyCode::Tab);
    let review = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .review_plan
        .as_ref()
        .unwrap();
    assert!(!review.show_evidence && review.show_options);
    assert_eq!(review.input, input);
    assert!(!app.has_running_work());
}

#[test]
fn review_source_evidence_preparation_retains_omissions_without_model_work() {
    let (root, mut app) = fixture();
    app.handle_review_study_key(KeyCode::Char('s'));
    app.handle_review_study_key(KeyCode::Char('s'));
    app.handle_review_study_key(KeyCode::Char('e'));
    let result = prepare(&mut app, root.path());
    assert_eq!(result["data"]["sourceEvidence"]["includedBytes"], 0);
    assert_eq!(
        result["data"]["sourceEvidence"]["observations"][0]["binding"],
        "recorded_source_unavailable"
    );
    assert!(!root
        .path()
        .join(".kuzushi/v3/campaigns")
        .read_dir()
        .unwrap()
        .flatten()
        .any(|entry| entry.path().join("queue.json").exists()));
    assert!(!app.has_running_work());
}

fn reader_fixture() -> (tempfile::TempDir, ShellApp) {
    use kuzushi_core::findings::{ReviewCapturedFile, ReviewCapturedFileState};
    let (root, mut app) = fixture();
    app.handle_review_study_key(KeyCode::Char('s'));
    app.handle_review_study_key(KeyCode::Char('s'));
    app.handle_review_study_key(KeyCode::Char('e'));
    let output = prepare(&mut app, root.path());
    let mut receipt: kuzushi_core::capabilities::campaign::ReviewStudyReceipt =
        serde_json::from_value(output["data"].clone()).unwrap();
    // Synthetic presentation data; core integration tests authenticate real captures.
    let text = (0..40)
        .map(|index| format!("SOURCE_LINE_{index:02}\n"))
        .collect::<String>();
    let evidence = receipt.source_evidence.as_mut().unwrap();
    evidence.included_bytes = text.len();
    let source = &mut evidence.observations[0];
    source.binding =
        kuzushi_core::capabilities::campaign::ReviewSourceBinding::MatchingRecordedSnapshot;
    source.file = Some(ReviewCapturedFile {
        path: "note.md".into(),
        state: ReviewCapturedFileState::Captured,
        blob_hash: Some(kuzushi_core::content_store::object_hash(
            kuzushi_core::content_store::ObjectKind::Blob,
            text.as_bytes(),
        )),
        byte_count: Some(text.len() as u64),
    });
    source.text = Some(text);
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .review_receipt = Some(receipt);
    app.handle_review_study_key(KeyCode::Char('v'));
    (root, app)
}

fn evidence_screen(app: &ShellApp) -> String {
    let viewport = app.viewport();
    let mut terminal = Terminal::new(TestBackend::new(viewport.columns, viewport.rows)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .chunks(viewport.columns as usize)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn review_source_evidence_reader_reaches_every_line_at_all_sizes_and_in_plain_output() {
    let (_root, mut app) = reader_fixture();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        app.handle_review_study_key(KeyCode::Home);
        let first_page = evidence_screen(&app);
        assert!(first_page.contains("FROZEN SOURCE INPUT"));
        for control in [
            "PgUp/Dn read",
            "Home/End",
            "v plan",
            "Tab input",
            "Esc back",
        ] {
            assert!(first_page.contains(control), "{width}x{height}: {control}");
        }
        assert!(
            first_page.contains("SOURCE_LINE_00"),
            "{width}x{height}: code visible without paging"
        );
        let mut seen = String::new();
        for _ in 0..100 {
            seen.push_str(&evidence_screen(&app));
            app.handle_review_study_key(KeyCode::PageDown);
        }
        for index in 0..40 {
            assert!(
                seen.contains(&format!("SOURCE_LINE_{index:02}")),
                "{width}x{height}: line {index}"
            );
        }
        app.handle_review_study_key(KeyCode::End);
        assert!(evidence_screen(&app).contains("enforced."));
        app.handle_review_study_key(KeyCode::Home);
        assert_eq!(
            app.router
                .campaign()
                .batch_scan_config
                .as_ref()
                .unwrap()
                .review_plan
                .as_ref()
                .unwrap()
                .scroll,
            0
        );
        let plain = crate::renderer::render_plain_app(&app, width as usize);
        assert!(!plain.contains('\u{1b}'));
        for index in 0..40 {
            assert!(plain.contains(&format!("SOURCE_LINE_{index:02}")));
        }
        assert!(!app.has_running_work());
    }
}
