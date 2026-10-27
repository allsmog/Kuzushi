use super::*;

fn book(count: usize) -> (tempfile::TempDir, ShellApp, FindingStore) {
    let (root, mut app, primary) = fixture();
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    for index in 2..=count {
        let finding = Finding::new_tool(
            "owned-fixture",
            &format!("pair-{index:03}"),
            "hello.txt",
            1,
            None,
            Severity::Info,
            &format!("Labeled greeting {index:03}"),
        );
        let id = store.insert_finding("owned-a", &finding).unwrap();
        store
            .propose_finding_relationship(
                primary.from.finding_id,
                id,
                FindingRelationshipKind::Duplicate,
                &format!("Labeled pair {index:03}"),
                None,
            )
            .unwrap();
    }
    hydrate(&mut app, &store, 0);
    (root, app, store)
}

fn hydrate(app: &mut ShellApp, store: &FindingStore, offset: usize) {
    app.router.relationships.offset = offset;
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target_owned().unwrap(),
            key: ViewHydrationKey::FindingRelationships {
                finding_id: None,
                offset,
            },
            value: ViewHydrationValue::FindingRelationships(Ok(store
                .finding_relationships(None, 50, offset)
                .unwrap())),
        });
}

fn accept_selected(app: &mut ShellApp) -> FindingRelationship {
    let before = app.selected_relationship().unwrap();
    app.begin_relationship_note(FindingRelationshipState::Accepted);
    app.paste_relationship_note("Reviewed this exact pair of greeting observations");
    app.submit_relationship_note();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !app.poll_relationship_write() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    before
}

#[test]
fn own_save_keeps_the_same_pair_after_latest_activity_reorders_the_page() {
    let (_root, mut app, store) = book(2);
    app.router.relationships.cursor = 1;
    let before = accept_selected(&mut app);
    hydrate(&mut app, &store, 0);
    let after = app.selected_relationship().unwrap();
    assert_eq!(after.id, before.id);
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(after.state, FindingRelationshipState::Accepted);
    assert_eq!(app.input(), "preserve operator draft");
    assert_eq!(app.shell_view(), ShellView::Relationships);
}

#[test]
fn explicit_refresh_keeps_the_pair_when_another_review_changes_order() {
    let (_root, mut app, store) = book(2);
    app.router.relationships.cursor = 1;
    let before = app.selected_relationship().unwrap();
    store
        .review_finding_relationship(
            &before.id,
            FindingRelationshipState::Rejected,
            "Separate external review",
            before.revision,
        )
        .unwrap();
    app.refresh_relationships();
    hydrate(&mut app, &store, 0);
    assert_eq!(app.selected_relationship().unwrap().id, before.id);
    assert_eq!(
        app.selected_relationship().unwrap().revision,
        before.revision + 1
    );
}

#[test]
fn saved_pair_outside_the_page_remains_the_only_subsequent_action_target() {
    let (_root, mut app, store) = book(60);
    hydrate(&mut app, &store, 50);
    app.router.relationships.cursor = 9;
    let before = accept_selected(&mut app);
    hydrate(&mut app, &store, 50);
    assert_eq!(app.router.relationships.offset, 50);
    let after = app
        .selected_relationship()
        .expect("saved pair must remain readable");
    assert_eq!(after.id, before.id);
    assert_eq!(after.revision, before.revision + 1);
    app.begin_relationship_note(FindingRelationshipState::Removed);
    assert_eq!(
        app.router.relationships.note.as_ref().unwrap().relationship,
        after
    );
}

fn render(app: &ShellApp, width: u16, height: u16) -> String {
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .chunks(width as usize)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn saved_record_survives_a_late_older_or_empty_cache_but_loading_blocks_actions() {
    let (_root, mut app, store) = book(2);
    app.router.relationships.cursor = 1;
    let before = app.selected_relationship().unwrap();
    let stale = store.finding_relationships(None, 50, 0).unwrap();
    accept_selected(&mut app);
    assert!(app.selected_relationship().is_none());
    app.workbench_cache()
        .borrow_mut()
        .relationship_pages
        .insert((app.target_owned().unwrap(), None, 0), Ok(stale));
    assert_eq!(app.selected_relationship().unwrap().revision, 2);
    assert!(render(&app, 120, 36).contains("newer than this page"));
    app.workbench_cache()
        .borrow_mut()
        .relationship_pages
        .insert(
            (app.target_owned().unwrap(), None, 0),
            Ok(FindingRelationshipPage {
                rows: vec![],
                offset: 0,
                has_more: false,
            }),
        );
    assert_eq!(app.selected_relationship().unwrap().id, before.id);
    assert!(render(&app, 120, 36).contains("outside this page"));
}

#[test]
fn explicit_navigation_and_page_changes_choose_visible_pairs_after_an_off_page_save() {
    let (_root, mut app, store) = book(60);
    hydrate(&mut app, &store, 50);
    app.router.relationships.cursor = 9;
    let before = accept_selected(&mut app);
    hydrate(&mut app, &store, 50);
    let visible = store.finding_relationships(None, 50, 50).unwrap().rows[0].clone();
    app.move_relationship(1);
    assert_eq!(app.selected_relationship().unwrap(), visible);
    app.previous_relationship_page();
    hydrate(&mut app, &store, 0);
    assert_eq!(app.selected_relationship().unwrap().id, before.id);
    assert_eq!(app.router.default_scroll().offset(), 0);
}

#[test]
fn malformed_receipt_keeps_the_exact_note_and_selection_for_inspection() {
    let (_root, mut app, store) = book(2);
    app.router.relationships.cursor = 1;
    app.begin_relationship_note(FindingRelationshipState::Accepted);
    app.paste_relationship_note("Keep this reason");
    let draft = app.router.relationships.note.take().unwrap();
    let before = draft.relationship.clone();
    app.finish_relationship_write(app.target_owned().unwrap(), draft, Ok(vec![]));
    assert_eq!(app.selected_relationship().unwrap(), before);
    assert_eq!(
        app.router.relationships.note.as_ref().unwrap().field.text(),
        "Keep this reason"
    );
    assert!(app
        .router
        .relationships
        .notice
        .as_ref()
        .unwrap()
        .contains("not confirmed"));
    assert!(store.list_all_review_decisions().unwrap().is_empty());
}

#[test]
fn off_page_identity_and_compact_page_controls_remain_visible() {
    let (_root, mut app, store) = book(60);
    app.set_input_mode(InputMode::Navigate);
    let compact = render(&app, 40, 12);
    assert!(compact.contains("n/p pages"), "{compact}");
    assert!(compact.contains("R refresh"), "{compact}");
    hydrate(&mut app, &store, 50);
    app.router.relationships.cursor = 9;
    accept_selected(&mut app);
    hydrate(&mut app, &store, 50);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let screen = render(&app, width, height);
        assert!(screen.contains("outside this page"), "{width}: {screen}");
        assert!(screen.contains("Accepted"), "{width}: {screen}");
    }
}

#[test]
#[ignore = "writes an explicitly owned native fixture through the real store"]
fn prepare_native_relationship_book_fixture() {
    let root = std::path::PathBuf::from(
        std::env::var_os("KUZUSHI_RELATIONSHIP_BOOK_FIXTURE_OUT").expect("owned fixture path"),
    );
    let workspace = kuzushi_core::WorkspaceTarget::new(&root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let ids: Vec<i64> = serde_json::from_slice(
        &std::fs::read(root.join(".kuzushi/relationship-seed.json")).unwrap(),
    )
    .unwrap();
    assert!((2..=61).contains(&ids.len()));
    let records = ids[1..]
        .iter()
        .enumerate()
        .map(|(index, id)| {
            store
                .propose_finding_relationship(
                    ids[0],
                    *id,
                    FindingRelationshipKind::Duplicate,
                    &format!(
                        "Labeled book pair {:03}; synthetic, no defect claim",
                        index + 1
                    ),
                    None,
                )
                .unwrap()
        })
        .collect::<Vec<_>>();
    std::fs::write(
        root.join(".kuzushi/relationship-proposals.json"),
        serde_json::to_vec_pretty(&records).unwrap(),
    )
    .unwrap();
}

#[test]
fn arrow_navigation_uses_the_same_stable_selection_without_consuming_the_composer() {
    let (_root, mut app, _store) = book(3);
    app.set_input_mode(InputMode::Navigate);
    let first = app.selected_relationship().unwrap();
    let update = app.reduce_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    EffectRuntime::execute(&mut app, update.effects);
    assert_ne!(app.selected_relationship().unwrap().id, first.id);
    let update = app.reduce_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
    EffectRuntime::execute(&mut app, update.effects);
    assert_eq!(app.selected_relationship().unwrap().id, first.id);
    assert_eq!(app.input(), "preserve operator draft");
    app.set_input_mode(InputMode::Prompt);
    app.handle_relationship_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(app.selected_relationship().unwrap().id, first.id);
}

#[test]
fn narrow_paging_reaches_every_recorded_endpoint_and_run_without_skipping_rows() {
    let (_root, mut app, store) = book(60);
    app.set_input_mode(InputMode::Navigate);
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    hydrate(&mut app, &store, 50);
    app.router.relationships.cursor = 9;
    let original = accept_selected(&mut app);
    hydrate(&mut app, &store, 50);
    let full = ratatui::layout::Rect::new(0, 0, 40, 12);
    let visible = crate::renderer::workbench_primary_area(&app, full).height as usize;
    let mut body = String::new();
    for _ in 0..10 {
        body.extend(
            render(&app, 40, 12)
                .lines()
                .take(visible)
                .flat_map(str::chars),
        );
        let before = app.router.default_scroll().offset();
        let update = app.reduce_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        EffectRuntime::execute(&mut app, update.effects);
        let step = app.router.default_scroll().offset().saturating_sub(before) as usize;
        assert!(
            step <= visible,
            "page step {step} skips rows in a {visible}-row body"
        );
    }
    assert!(
        body.contains(&original.from.finding_id.to_string()),
        "{body}"
    );
    assert!(body.contains(&original.to.finding_id.to_string()), "{body}");
    assert!(body.contains("Recorded runs:"), "{body}");
    assert!(body.contains("owned-a"), "{body}");
    assert!(body.contains("owned-b"), "{body}");
    assert_eq!(app.input(), "preserve operator draft");
}
