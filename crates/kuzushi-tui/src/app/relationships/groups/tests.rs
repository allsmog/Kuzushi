use super::*;
use kuzushi_core::findings::{
    Finding, FindingRelationshipKind, FindingRelationshipState, FindingStore, Severity,
};

mod source_selection;

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("hello.txt"),
        "Owned source. Never executed.\n",
    )
    .unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("owned", workspace.root(), "completed")
        .unwrap();
    for rule in ["a", "b", "c"] {
        store
            .insert_finding(
                "owned",
                &Finding::new_tool(
                    "owned-fixture",
                    rule,
                    "hello.txt",
                    1,
                    None,
                    Severity::Info,
                    "Labeled group observation",
                ),
            )
            .unwrap();
    }
    let rows = store.list_all_findings().unwrap();
    let proposal = store
        .propose_finding_relationship(
            rows[0].id.unwrap(),
            rows[1].id.unwrap(),
            FindingRelationshipKind::Duplicate,
            "Labeled proposal",
            None,
        )
        .unwrap();
    store
        .review_finding_relationship(
            &proposal.id,
            FindingRelationshipState::Accepted,
            "Reviewed fixture grouping",
            1,
        )
        .unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.refresh_findings_effect(FindingsRefresh {
        announce: false,
        filter: None,
    });
    app.set_shell_view(ShellView::Workbench);
    app.editor_mut().set_input("Retained operator draft");
    app.open_finding_groups();
    app.set_input_mode(InputMode::Navigate);
    hydrate(&mut app);
    (root, app)
}

fn hydrate(app: &mut ShellApp) {
    let request = app.router.relationships.groups.request.clone();
    let target = app.target_owned().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(&target).unwrap();
    let store = FindingStore::open_read_only(workspace.findings_db_path()).unwrap();
    let page = kuzushi_core::findings::read_finding_groups(&store, &workspace, &request).unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target,
            key: ViewHydrationKey::FindingGroups(request),
            value: ViewHydrationValue::FindingGroups(Ok(page)),
        });
}

fn select_pair(app: &mut ShellApp) {
    let ViewDataState::Ready(Ok(page)) = app.finding_groups_page() else {
        panic!("loaded")
    };
    app.router.relationships.groups.cursor = page
        .groups
        .iter()
        .position(|group| group.member_count == 2)
        .unwrap();
    app.router.relationships.groups.request.limit = 1;
    hydrate(app);
    let ViewDataState::Ready(Ok(page)) = app.finding_groups_page() else {
        panic!("loaded")
    };
    if page.groups[0].member_count != 2 {
        app.page_groups(true);
        hydrate(app);
    }
    app.router.relationships.groups.cursor = 0;
    app.open_group_selection();
    hydrate(app);
}

#[test]
fn group_member_open_and_return_preserve_page_selection_scroll_and_composer() {
    let (_root, mut app) = fixture();
    select_pair(&mut app);
    app.page_groups(true);
    hydrate(&mut app);
    let ViewDataState::Ready(Ok(page)) = app.finding_groups_page() else {
        panic!("loaded")
    };
    let member = page.members[0].clone();
    app.router.default_scroll_mut().set(7);
    app.open_group_selection();
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.input_mode(), InputMode::Navigate);
    assert_eq!(
        app.selected_finding().as_ref().unwrap().id,
        Some(member.finding_id)
    );
    app.open_finding_groups();
    assert_eq!(app.router.relationships.groups.request.offset, 1);
    assert_eq!(app.router.default_scroll().offset(), 7);
    assert_eq!(app.input(), "Retained operator draft");
}

#[test]
fn switching_target_cannot_reuse_an_old_group_or_member_selection() {
    let (_root, mut app) = fixture();
    select_pair(&mut app);
    app.router.relationships.groups.return_to_groups = true;
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().into()));
    app.open_finding_groups();
    assert!(app.router.relationships.groups.request.group_id.is_none());
    assert_eq!(app.router.relationships.groups.request.offset, 0);
    assert_eq!(app.input(), "Retained operator draft");
}

#[test]
fn the_real_review_hotkey_returns_to_the_preserved_group_instead_of_typing_a_command() {
    let (_root, mut app) = fixture();
    app.editor_mut().set_input("");
    select_pair(&mut app);
    app.open_group_selection();
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE));
    EffectRuntime::execute(&mut app, update.effects);
    assert_eq!(app.shell_view(), ShellView::Relationships);
    assert!(app.router.relationships.show_groups);
    assert!(app.input().is_empty());
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .is_none_or(|notice| notice.source != "navigate"));
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::SHIFT));
    EffectRuntime::execute(&mut app, update.effects);
    assert!(!app.router.relationships.show_groups);
    assert!(app.router.relationships.finding_id.is_some());
    assert!(app.input().is_empty());
}

#[test]
fn member_headers_keep_selection_and_independent_verdicts_readable_across_viewports() {
    let (_root, mut app) = fixture();
    select_pair(&mut app);
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("GROUP MEMBERS · F-"), "{width}: {text}");
        assert!(text.contains("Enter finding"), "{width}: {text}");
        assert!(!text.contains("Esc prompt"), "{width}: {text}");
    }
}
