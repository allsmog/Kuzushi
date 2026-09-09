use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::{NestedProjectKind, NestedProjectScopeTree, V2Config, WorkspaceTarget};

fn tree(count: usize) -> NestedProjectScopeTree {
    let mut scopes = vec![NestedProjectScope {
        id: "root".into(),
        parent: None,
        kind: NestedProjectKind::Root,
        rel_path: ".".into(),
        inherited_sections: Vec::new(),
    }];
    scopes.extend((0..count).map(|n| NestedProjectScope {
        id: format!("scope-{n:02}"),
        parent: Some("root".into()),
        kind: NestedProjectKind::PackageRoot,
        rel_path: format!("packages/Api-{n:02}"),
        inherited_sections: Vec::new(),
    }));
    NestedProjectScopeTree {
        schema_version: 2,
        root: "root".into(),
        scopes,
    }
}

fn scope_app(target: &std::path::Path, count: usize) -> ShellApp {
    let workspace = WorkspaceTarget::new(target).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    cache_tree(&mut app, count);
    app.open_map_run_config().unwrap();
    app.router.setup_mut().map_run_config_mut().move_cursor(1);
    press(&mut app, KeyCode::Enter);
    assert!(app.map_scope_picker_open());
    app
}

fn cache_tree(app: &mut ShellApp, count: usize) {
    let target = app.target_owned().unwrap();
    app.workbench_cache()
        .borrow_mut()
        .cache_persisted_project_scope_tree(&target, tree(count));
}

fn press(app: &mut ShellApp, code: KeyCode) {
    let update = app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE));
    assert!(update.handled);
    assert!(
        update.effects.is_empty(),
        "scope input must never start work"
    );
}

#[test]
fn scope_search_accepts_uppercase_paste_and_selects_a_stable_identity() {
    let target = tempfile::tempdir().unwrap();
    let mut app = scope_app(target.path(), 50);
    app.set_input("reserved command".to_string());
    app.reduce_key(KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT));
    app.reduce_paste("pi-47");
    assert_eq!(app.map_option_string("scope"), None);
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.map_option_string("scope").as_deref(),
        Some("id:scope-47")
    );
    assert!(!app.map_scope_picker_open());
    assert_eq!(app.input(), "reserved command");
    app.open_map_scope_picker().unwrap();
    let selected = app
        .router
        .setup()
        .map_run_config()
        .scope()
        .unwrap()
        .selected()
        .unwrap();
    assert_eq!(selected.value.as_deref(), Some("id:scope-47"));
}

#[test]
fn empty_search_results_and_cancel_keep_the_saved_scope() {
    let target = tempfile::tempdir().unwrap();
    let mut app = scope_app(target.path(), 2);
    app.reduce_paste("qjkwno-such-scope");
    press(&mut app, KeyCode::Enter);
    assert!(app
        .router
        .setup()
        .map_run_config()
        .error()
        .unwrap()
        .contains("No matching scope"));
    assert_eq!(app.map_option_string("scope"), None);
    press(&mut app, KeyCode::Esc);
    assert!(!app.map_scope_picker_open());
    assert_eq!(
        app.router.setup().editor(),
        Some(crate::app::SetupEditor::ThreatModel)
    );
}

#[test]
fn large_scope_review_is_explicit_and_cancel_does_not_change_the_plan() {
    let target = tempfile::tempdir().unwrap();
    let mut app = scope_app(target.path(), 17);
    app.reduce_paste("all eligible");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.map_option_string("scope"), None);
    assert!(app
        .router
        .setup()
        .map_run_config()
        .error()
        .unwrap()
        .contains("17 builds"));
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.map_option_string("scope"), None);
    app.open_map_scope_picker().unwrap();
    app.reduce_paste("all eligible");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.map_option_string("scope").as_deref(),
        Some(ALL_LEAF_SCOPES)
    );
    assert!(!app.map_run_config_summary().review_required);
}

#[test]
fn changing_scope_evidence_requires_fresh_review_and_removed_leaves_are_refused() {
    let target = tempfile::tempdir().unwrap();
    let mut app = scope_app(target.path(), 17);
    app.reduce_paste("all eligible");
    press(&mut app, KeyCode::Enter);
    cache_tree(&mut app, 18);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.map_option_string("scope"), None);
    assert!(app
        .router
        .setup()
        .map_run_config()
        .error()
        .unwrap()
        .contains("18 builds"));
    press(&mut app, KeyCode::Esc);
    app.open_map_scope_picker().unwrap();
    app.reduce_paste("Api-17");
    cache_tree(&mut app, 1);
    press(&mut app, KeyCode::Enter);
    assert!(app
        .router
        .setup()
        .map_run_config()
        .error()
        .unwrap()
        .contains("no longer eligible"));
    assert_eq!(app.map_option_string("scope"), None);
}

#[test]
fn all_scope_selection_keeps_existing_zero_and_hard_cap_checks() {
    let target = tempfile::tempdir().unwrap();
    for count in [0, 65] {
        let mut app = scope_app(target.path(), count);
        app.reduce_paste("all eligible");
        press(&mut app, KeyCode::Enter);
        let error = app.router.setup().map_run_config().error().unwrap();
        assert!(
            error.contains(if count == 0 {
                "at least one"
            } else {
                "hard cap"
            }),
            "{error}"
        );
        assert!(app.map_scope_picker_open());
        assert_eq!(app.map_option_string("scope"), None);
    }
}
