use super::*;

fn diagnostic_fixture() -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = fixture();
    let result = prepare(&mut app, root.path());
    app.cache_tool_snapshot("campaign:context-study", &result);
    let generation = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .context_generation
        .as_mut()
        .unwrap();
    generation.result_error = Some("Labeled rejected context".into());
    generation.rejected_available = true;
    generation.rejected_output = Some(Ok(
        kuzushi_core::capabilities::campaign::RejectedContextOutput {
            run_id: "labeled-failed-run".into(),
            path: root.path().join("line\u{1b}[2Jrejected-context-output.txt"),
            source_identity: "labeled-source".into(),
            model: "openai-codex:gpt-5.5".into(),
            text: format!(
                "LABELED_PRIVATE_DIAGNOSTIC\n\u{1b}[31munsafe control\n{}",
                "Labeled evidence\n".repeat(60)
            ),
        },
    ));
    (root, app)
}

#[test]
fn rejected_output_reader_is_explicit_inert_and_keeps_view_origin_at_all_sizes() {
    let (_root, mut app) = diagnostic_fixture();
    let before = app.context_generation().unwrap().clone();
    assert!(!crate::renderer::render_plain_app(&app, 80).contains("LABELED_PRIVATE_DIAGNOSTIC"));
    {
        let generation = app
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap()
            .context_generation
            .as_mut()
            .unwrap();
        generation.scroll = 3;
        generation.show_options = true;
        generation.show_rejected = true;
        std::mem::swap(&mut generation.scroll, &mut generation.rejected_scroll);
    }
    for code in [
        KeyCode::Enter,
        KeyCode::Char('m'),
        KeyCode::Char('n'),
        KeyCode::Char('t'),
        KeyCode::Char('s'),
        KeyCode::Tab,
    ] {
        assert!(app.handle_context_generation_key(code).effects.is_empty());
        assert!(app.context_generation().unwrap().show_rejected);
    }
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(
            text.contains("REJECTED CONTEXT OUTPUT")
                && text.contains("d / Esc back · PgUp/Dn read"),
            "{width}x{height}"
        );
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    assert!(plain.contains("LABELED_PRIVATE_DIAGNOSTIC"));
    assert!(!plain.contains('\u{1b}'));
    app.handle_context_generation_key(KeyCode::PageDown);
    app.handle_context_generation_key(KeyCode::Esc);
    let generation = app.context_generation().unwrap();
    assert!(!generation.show_rejected && generation.show_options);
    assert_eq!(generation.scroll, 3);
    assert_eq!(generation.receipt, before.receipt);
    assert!(generation.generated.is_none());
}

#[test]
fn retention_toggle_is_visible_only_for_editable_context_and_never_mutates_frozen_work() {
    let (root, mut app) = fixture();
    assert!(app
        .handle_context_generation_key(KeyCode::Char('s'))
        .effects
        .is_empty());
    assert_eq!(
        app.context_generation().unwrap().context_input["saveRejectedOutput"],
        false
    );
    let result = prepare(&mut app, root.path());
    app.cache_tool_snapshot("campaign:context-study", &result);
    let receipt = app.context_generation().unwrap().receipt.clone();
    app.handle_context_generation_key(KeyCode::Char('s'));
    assert_eq!(app.context_generation().unwrap().receipt, receipt);
    assert!(app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .notice
        .as_ref()
        .unwrap()
        .contains("frozen"));
}

#[test]
fn corrupted_diagnostic_input_stays_inspectable_as_an_honest_failure() {
    let (root, mut app) = fixture();
    let result = prepare(&mut app, root.path());
    app.cache_tool_snapshot("campaign:context-study", &result);
    let receipt = app.context_generation().unwrap().receipt.clone().unwrap();
    std::fs::write(
        root.path()
            .join(".kuzushi/v3/campaigns")
            .join(&receipt.campaign_id)
            .join("queue.json"),
        json!({"jobs":{"context-001":{"state":"failed","runId":"damaged-input","attempts":1}}})
            .to_string(),
    )
    .unwrap();
    for (name, label, value) in [
        (
            "input.json",
            "tool input",
            json!({"model":"labeled-foreign-model"}),
        ),
        (
            "rejected-context-output.txt",
            "Labeled diagnostic fixture",
            json!("LABELED_PRIVATE_DIAGNOSTIC"),
        ),
    ] {
        kuzushi_core::run_artifacts::write_run_artifact_json(
            root.path(),
            "damaged-input",
            name,
            label,
            &value,
        )
        .unwrap();
    }
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .context_generation
        .as_mut()
        .unwrap()
        .refresh_result(root.path());
    assert!(app.context_generation().unwrap().rejected_available);
    let ordinary = crate::renderer::render_plain_app(&app, 80);
    assert!(ordinary.contains("Retained diagnostic unavailable"));
    assert!(!ordinary.contains("LABELED_PRIVATE_DIAGNOSTIC"));
    assert!(app
        .handle_context_generation_key(KeyCode::Char('d'))
        .effects
        .is_empty());
    let reader = crate::renderer::render_plain_app(&app, 80);
    assert!(reader.contains("Rejected output unavailable"));
    assert!(!reader.contains("LABELED_PRIVATE_DIAGNOSTIC"));
    assert!(app.context_generation().unwrap().generated.is_none());
}

#[test]
fn file_group_rejection_names_its_result_and_exposes_diagnostic_at_all_sizes() {
    for input in [
        json!({"sourcePaths":[" app /lib.py","app/lib.py"]}),
        json!({"scanScopeRef":{"scopeId":"app"}}),
    ] {
        let (_root, mut app) = diagnostic_fixture();
        app.router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap()
            .context_generation
            .as_mut()
            .unwrap()
            .context_input = input;
        for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| crate::renderer::render_app(frame, &app))
                .unwrap();
            let text = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect::<String>();
            assert!(
                text.contains("CONTEXT JOB RESULT") && text.contains("d output"),
                "{width}x{height}: {text}"
            );
        }
        app.router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap()
            .context_generation
            .as_mut()
            .unwrap()
            .show_rejected = true;
        for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| crate::renderer::render_app(frame, &app))
                .unwrap();
            let text = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect::<String>();
            assert!(
                text.contains("REJECTED CONTEXT OUTPUT") && text.contains("d / Esc back"),
                "{width}x{height}: {text}"
            );
        }
    }
}
