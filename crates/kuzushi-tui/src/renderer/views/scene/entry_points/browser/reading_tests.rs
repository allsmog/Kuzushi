use super::tests::{buffer_text, render_to_text, sample_model};
use super::*;

fn visible_range(text: &str) -> (usize, usize, usize) {
    let range = text
        .split("rows ")
        .nth(1)
        .expect("visible detail row range");
    let end = range
        .find(|c: char| !c.is_ascii_digit() && c != '-' && c != '/')
        .unwrap_or(range.len());
    let numbers: Vec<usize> = range[..end]
        .split(['-', '/'])
        .map(|value| value.parse().unwrap())
        .collect();
    (numbers[0], numbers[1], numbers[2])
}

#[test]
fn entry_reading_compact_browser_preserves_five_detail_rows_and_warning_presence() {
    let mut model = sample_model();
    model.receipt.warnings =
        vec!["The model receipt has no revision; evidence freshness is unknown.".into()];
    model.entries[0].evidence = "Evidence with a concrete source reference. ".repeat(30);
    let text = render_to_text(
        EntryPointBrowser {
            model: Arc::new(model),
            selection: 0,
            detail_scroll: 0,
        },
        80,
        13,
    );
    let (first, last, _) = visible_range(&text);
    assert!(
        last - first + 1 >= 5,
        "embedded Map must leave a readable detail pane:\n{text}"
    );
    assert!(text.to_lowercase().contains("warning"), "{text}");
    assert!(
        text.contains("PgUp/PgDn"),
        "detail paging must be discoverable:\n{text}"
    );
}

#[test]
fn entry_reading_wide_browser_leads_with_source_evidence_and_retains_full_receipts() {
    let mut model = sample_model();
    model.entries[0].evidence = "source_evidence_marker".into();
    model.receipt.catalog_digest = Some("abcdef01".repeat(8));
    let model = Arc::new(model);
    let initial = render_to_text(
        EntryPointBrowser {
            model: model.clone(),
            selection: 0,
            detail_scroll: 0,
        },
        120,
        26,
    );
    let evidence = initial
        .find("source_evidence_marker")
        .expect("visible source evidence");
    if let Some(receipt) = initial.find("C SHA256") {
        assert!(evidence < receipt, "source evidence must lead:\n{initial}");
    }
    let tail = render_to_text(
        EntryPointBrowser {
            model,
            selection: 0,
            detail_scroll: usize::MAX,
        },
        120,
        26,
    );
    assert!(tail.contains("C SHA256"), "{tail}");
    assert!(tail.contains("TIMESTAMPS MS"), "{tail}");
}

fn shell(width: u16, height: u16, embedded: bool) -> (tempfile::TempDir, crate::ShellApp) {
    let temp = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
    let evidence = (0..40)
        .map(|n| format!("evidence_marker_{n:03} describes one authenticated observation.\n"))
        .collect::<String>();
    let entries: Vec<_> = (0..9).map(|n| serde_json::json!({
        "id":format!("EP-REALISTIC-LONG-ENTRY-IDENTITY-{n}"), "name":format!("public_function_{n}"),
        "kind":"public_library_function", "path":"src/lib.rs", "line":42,
        "trustZone":"library_process", "description":"Library behavior requires downstream validation.",
        "evidence": evidence, "targetElementIds":["N1"]
    })).collect();
    let document = serde_json::json!({
        "systemContext":"A library provides descriptor contracts for a downstream application.",
        "dfd":{"nodes":[{"id":"N1","name":"Library","trustZone":"local","type":"process"},
            {"id":"N2","name":"Consumer","trustZone":"application","type":"process"}],
            "flows":[{"id":"F1","sourceId":"N1","targetId":"N2","description":"descriptors"}],"trustBoundaries":[]},
        "attackSurface":{"entryPoints":entries}, "assets":[],"threats":[],"openQuestions":[]
    });
    kuzushi_core::capabilities::save_persistent_threat_model(workspace.root(), &document, true)
        .unwrap();
    let mut app = crate::ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.hydrate_all_view_data_for_test();
    app.set_viewport(crate::TerminalViewport::new(width, height));
    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Map));
    app.router
        .scene_mut()
        .set_page(crate::scene3d::VizPage::EntryPoints);
    app.set_shell_view(if embedded {
        crate::ShellView::Workbench
    } else {
        crate::ShellView::Scene
    });
    app.set_input_mode(crate::InputMode::Prompt);
    (temp, app)
}

fn draw(app: &crate::ShellApp) -> String {
    let viewport = app.viewport();
    let backend = ratatui::backend::TestBackend::new(viewport.columns, viewport.rows);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    buffer_text(terminal.backend().buffer())
}

fn key(app: &mut crate::ShellApp, code: crossterm::event::KeyCode) {
    crate::app::update_and_execute_effects(
        app,
        crate::app::Msg::Term(crate::app::TermEvent::Key(crossterm::event::KeyEvent::new(
            code,
            crossterm::event::KeyModifiers::empty(),
        ))),
    );
}

#[test]
fn entry_reading_whole_shell_pages_every_row_and_has_no_overscroll_debt() {
    for embedded in [true, false] {
        for (width, height) in [(80, 24), (40, 24), (120, 36)] {
            assert_full_shell_pages(width, height, embedded);
        }
    }
}

#[test]
fn entry_reading_full_shell_at_forty_by_twelve_reaches_every_detail_row() {
    assert_full_shell_pages(40, 12, false);
}

fn assert_full_shell_pages(width: u16, height: u16, embedded: bool) {
    use crossterm::event::KeyCode;
    let (_target, mut app) = shell(width, height, embedded);
    let initial = draw(&app);
    let (first, last, total) = visible_range(&initial);
    if width == 80 && embedded {
        assert!(last - first + 1 >= 5, "{initial}");
    }
    assert_contiguous_pages(&mut app, initial, total);
    for _ in 0..20 {
        key(&mut app, KeyCode::PageDown);
    }
    let end = visible_range(&draw(&app));
    key(&mut app, KeyCode::PageUp);
    let back = visible_range(&draw(&app));
    assert!(back.0 < end.0, "one Page Up must leave the end immediately");
    assert_eq!(app.router.scene().entry_point_selection(), 0);
    assert!(app.input().is_empty());
}

fn assert_contiguous_pages(app: &mut crate::ShellApp, mut text: String, total: usize) {
    let mut seen = vec![false; total];
    for _ in 0..total {
        let (first, last, _) = visible_range(&text);
        seen[first - 1..last].fill(true);
        if last == total {
            break;
        }
        key(app, crossterm::event::KeyCode::PageDown);
        text = draw(app);
        let (next, _, _) = visible_range(&text);
        assert!(next <= last + 1, "skipped rows after {last}:\n{text}");
    }
    assert!(
        seen.iter().all(|seen| *seen),
        "every detail row must be reachable"
    );
}

#[test]
fn entry_reading_receipt_keeps_full_warning_and_digest_at_narrow_width() {
    let mut model = sample_model();
    let digest = "0123456789abcdef".repeat(4);
    model.receipt.tree_hash = Some(digest.clone());
    model.receipt.context_digest = Some(digest.clone());
    model.receipt.warnings =
        vec!["Start of a long warning with critical END_OF_WARNING recovery information.".into()];
    let lines = browser_detail_lines(30, &model, &model.entries[0]);
    let text = lines
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("");
    assert!(text.contains(&digest));
    assert!(text.contains("END_OF_WARNING"));
    assert!(lines.iter().all(|line| line.width() <= 30));
}

#[test]
fn entry_reading_resize_and_zoom_keep_selection_and_page_without_gaps() {
    use crossterm::event::KeyCode;
    let (_target, mut app) = shell(120, 36, true);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::PageDown);
    app.set_viewport(crate::TerminalViewport::new(80, 24));
    let before = visible_range(&draw(&app));
    key(&mut app, KeyCode::PageDown);
    let after = visible_range(&draw(&app));
    assert!(after.0 <= before.1 + 1);
    assert!(after.0 > before.0);
    let offset = app.router.scene().entry_point_detail_scroll();
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Char('z'));
    assert_eq!(app.shell_view(), crate::ShellView::Scene);
    assert_eq!(app.router.scene().entry_point_selection(), 1);
    let zoomed = visible_range(&draw(&app));
    key(&mut app, KeyCode::PageDown);
    assert!(visible_range(&draw(&app)).0 <= zoomed.1 + 1);
    key(&mut app, KeyCode::Char('q'));
    assert_eq!(app.shell_view(), crate::ShellView::Workbench);
    assert_eq!(app.router.scene().entry_point_selection(), 1);
    assert!(app.router.scene().entry_point_detail_scroll() >= offset);
}

#[test]
fn entry_reading_footer_shows_paging_and_typing_keeps_ownership() {
    use crossterm::event::KeyCode;
    let (_target, mut app) = shell(80, 24, true);
    let text = draw(&app);
    let footer = text.lines().rev().nth(1).unwrap();
    assert!(footer.contains("PgUp/PgDn"), "{text}");
    assert!(footer.contains("Tab map view"), "{text}");
    assert!(!footer.contains("Tab complete"), "{text}");
    key(&mut app, KeyCode::Char('j'));
    assert_eq!(app.input(), "j");
    assert_eq!(app.router.scene().entry_point_selection(), 0);
    assert_eq!(app.router.scene().entry_point_detail_scroll(), 0);
    let typed = draw(&app);
    assert!(
        typed.lines().rev().nth(1).unwrap().contains("Tab complete"),
        "{typed}"
    );
}

#[test]
fn entry_reading_pages_the_real_workspace_width_beside_answers() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let (_target, mut app) = shell(160, 36, true);
    app.set_agent_chat(Some(crate::app::AgentChatView {
        question: "Explain this source".into(),
        answer: Some("A saved answer.".into()),
        ..Default::default()
    }));
    app.open_answers();
    crate::app::update_and_execute_effects(
        &mut app,
        crate::app::Msg::Term(crate::app::TermEvent::Key(KeyEvent::new(
            KeyCode::Char('t'),
            KeyModifiers::CONTROL,
        ))),
    );
    let initial = draw(&app);
    assert!(initial.contains("ANSWERS"), "{initial}");
    let (_, last, _) = visible_range(&initial);
    let answer_scroll = app.router.answers().scroll;
    key(&mut app, KeyCode::PageDown);
    let (next, _, _) = visible_range(&draw(&app));
    assert!(next <= last + 1);
    assert!(next > 1);
    assert_eq!(app.router.answers().scroll, answer_scroll);
    key(&mut app, KeyCode::Down);
    assert_eq!(app.router.scene().entry_point_selection(), 1);
    assert_eq!(app.router.scene().entry_point_detail_scroll(), 0);
}
