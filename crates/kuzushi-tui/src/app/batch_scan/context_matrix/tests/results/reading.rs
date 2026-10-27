use super::*;

fn reading_fixture() -> (tempfile::TempDir, ShellApp) {
    let (root, mut app) = result_fixture();
    app.reduce_resize(40, 12);
    let mut report = report();
    for (index, row) in report.cases[0].occurrence.rows.iter_mut().enumerate() {
        row.representative_title = format!("ROW_{index:02} owned observation with wrapped detail");
        row.representative_location = format!(" literal 東京/source_{index:02}.rs:7");
        row.representative_fingerprint = format!("owned-identity-{index:02}");
    }
    seed_report(&app, app.target().unwrap(), report);
    (root, app)
}

pub(super) fn page(app: &ShellApp) -> String {
    use ratatui::{backend::TestBackend, Terminal};
    let viewport = app.viewport();
    let mut terminal = Terminal::new(TestBackend::new(viewport.columns, viewport.rows)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    format!("{:?}", terminal.backend().buffer())
}

fn all_pages(app: &mut ShellApp) -> String {
    app.handle_matrix_result_key(KeyCode::Home);
    let mut pages = Vec::new();
    for _ in 0..200 {
        let current = page(app);
        if pages.last() == Some(&current) {
            break;
        }
        pages.push(current);
        app.handle_matrix_result_key(KeyCode::PageDown);
    }
    pages.join("\n")
}

#[test]
fn matrix_result_pages_reach_every_observation_in_every_viewport() {
    let (_root, mut app) = reading_fixture();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        let text = all_pages(&mut app);
        for index in 0..20 {
            assert!(
                text.contains(&format!("ROW_{index:02}")),
                "{width}x{height}: {text}"
            );
        }
    }
}

#[test]
fn matrix_result_page_up_moves_back_from_end() {
    let (_root, mut app) = reading_fixture();
    app.handle_matrix_result_key(KeyCode::End);
    let last = page(&app);
    app.handle_matrix_result_key(KeyCode::PageUp);
    assert_ne!(page(&app), last);
}

#[test]
fn matrix_result_pages_disambiguate_same_title_observations_and_preserve_case_identity() {
    let (_root, mut app) = reading_fixture();
    let mut report = report();
    report.cases[0].occurrence.rows.truncate(2);
    for (index, row) in report.cases[0].occurrence.rows.iter_mut().enumerate() {
        row.representative_title = "Same owned claim".into();
        row.representative_location = format!(" literal 東京/source_{index}.rs:7");
        row.representative_fingerprint = format!("owned-identity-{index}");
    }
    let before = report.clone();
    seed_report(&app, app.target().unwrap(), report);
    let overview = crate::ui_view_models::matrix_result_lines(&app, 160, 300).join("\n");
    assert!(
        overview.find("source_1.rs:7").unwrap() < overview.find("Fingerprint:").unwrap(),
        "All observation summaries must precede their provenance receipts: {overview}"
    );
    let text = all_pages(&mut app);
    for index in 0..2 {
        assert!(text.contains(&format!("source_{index}.rs:7")), "{text}");
        assert!(text.contains(&format!("owned-identity-{index}")), "{text}");
    }
    assert!(text.contains("baseline"), "{text}");
    assert!(text.contains("Context: explicitly omitted"), "{text}");
    assert_eq!(
        app.cached_context_matrix_report(),
        ViewDataState::Ready(Ok(before))
    );
}

fn source_fixture() -> (tempfile::TempDir, ShellApp, String) {
    use kuzushi_core::capabilities::campaign::{capture_batch_equivalence, FrozenContextCase};
    let (root, mut app) = reading_fixture();
    let input = json!({"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":null});
    let equivalence =
        capture_batch_equivalence(root.path(), &input, app.config(), app.registry()).unwrap();
    let source = equivalence.components.workspace_identity.clone();
    let mut report = report();
    report.cases[0].occurrence.equivalence_key = equivalence.sha256.clone();
    let frozen = FrozenContextCase {
        id: report.cases[0].id.clone(),
        label: report.cases[0].label.clone(),
        passes: 10,
        base_input: input,
        equivalence,
        omission_scope_sha256: None,
    };
    app.router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .study
        .matrix
        .receipt
        .as_mut()
        .unwrap()
        .matrix
        .cases = vec![frozen];
    seed_report(&app, app.target().unwrap(), report);
    app.reduce_resize(160, 48);
    (root, app, source)
}

#[test]
fn matrix_result_source_details_keep_recorded_content_after_the_checkout_changes() {
    use kuzushi_core::capabilities::campaign::capture_batch_equivalence;
    let (root, mut app, source) = source_fixture();
    std::fs::write(
        root.path().join("main.rs"),
        "// Owned changed source, never executed.\n",
    )
    .unwrap();
    let changed = capture_batch_equivalence(
        root.path(),
        &json!({"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":null}),
        app.config(),
        app.registry(),
    )
    .unwrap()
    .components
    .workspace_identity;
    assert_ne!(source, changed);
    let text = all_pages(&mut app);
    assert!(text.contains("Recorded source content:"), "{text}");
    assert!(
        text.contains(&source.chars().take(24).collect::<String>()),
        "{text}"
    );
    assert!(
        !text.contains(&changed.chars().take(24).collect::<String>()),
        "{text}"
    );
    assert!(text.contains("Recorded Git SHA: unavailable"), "{text}");
}

#[test]
fn matrix_result_source_details_reject_a_different_plan_case_or_condition_key() {
    for changed in ["plan", "case", "conditions"] {
        let (_root, mut app, source) = source_fixture();
        let receipt = app
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap()
            .study
            .matrix
            .receipt
            .as_mut()
            .unwrap();
        match changed {
            "plan" => receipt.plan_sha256 = "different-plan".into(),
            "case" => receipt.matrix.cases[0].id = "other-case".into(),
            _ => receipt.matrix.cases[0].equivalence.sha256 = "other-conditions".into(),
        }
        let text = all_pages(&mut app);
        let expected = if changed == "plan" {
            "Loading recorded case results"
        } else {
            "Source conditions unavailable."
        };
        assert!(text.contains(expected), "{changed}: {text}");
        assert!(
            !text.contains(&source.chars().take(24).collect::<String>()),
            "{changed}: {text}"
        );
    }
}

#[test]
fn matrix_result_plain_output_reads_all_cases_and_evidence_instead_of_the_study_form() {
    let (_root, mut app) = reading_fixture();
    app.handle_matrix_result_key(KeyCode::End);
    let text = crate::renderer::render_plain_app(&app, 80);
    for expected in [
        "CONTEXT CASES",
        "baseline",
        "candidate",
        "ROW_00",
        "ROW_19",
        "owned-identity-19",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("Next action:"), "{text}");
}

#[test]
fn matrix_result_failure_detail_is_readable_without_reusing_observations_or_starting_work() {
    let (_root, mut app) = reading_fixture();
    let error = (0..20)
        .map(|index| format!("ERROR_{index:02} owned receipt unavailable"))
        .collect::<Vec<_>>()
        .join("\n");
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target().unwrap().into(),
            key: ViewHydrationKey::ContextMatrixReport {
                campaign_id: "matrix-ui".into(),
                plan_sha256: "a".repeat(64),
            },
            value: ViewHydrationValue::ContextMatrixReport(Err(error)),
        });
    let text = all_pages(&mut app);
    for index in 0..20 {
        assert!(text.contains(&format!("ERROR_{index:02}")), "{text}");
    }
    assert!(text.contains("no work starts"), "{text}");
    assert!(!text.contains("ROW_00"), "{text}");
    app.handle_matrix_result_key(KeyCode::End);
    let end = page(&app);
    assert!(app
        .handle_matrix_result_key(KeyCode::PageUp)
        .unwrap()
        .effects
        .is_empty());
    assert_ne!(page(&app), end);
}

#[test]
fn matrix_result_controls_show_read_position_and_only_the_active_selection_keys() {
    let (_root, mut app) = reading_fixture();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        app.handle_matrix_result_key(KeyCode::Home);
        let first = page(&app);
        assert!(first.contains("Read 1-"), "{first}");
        app.handle_matrix_result_key(KeyCode::PageDown);
        app.handle_matrix_result_key(KeyCode::Enter);
        let hints = crate::ui_view_models::matrix_result_controls(&app).join("\n");
        assert!(
            hints.contains("Enter choose") && !hints.contains("PgUp"),
            "{hints}"
        );
        app.handle_matrix_result_key(KeyCode::Esc);
    }
    app.reduce_resize(40, 12);
    app.handle_matrix_result_key(KeyCode::Home);
    let first = crate::ui_view_models::matrix_result_controls(&app)
        .last()
        .unwrap()
        .clone();
    app.handle_matrix_result_key(KeyCode::PageDown);
    assert_ne!(
        crate::ui_view_models::matrix_result_controls(&app)
            .last()
            .unwrap(),
        &first
    );
}
