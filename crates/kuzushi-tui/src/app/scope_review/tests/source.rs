use super::*;
use crate::ui_view_models::scope_review::{scope_source_view, scope_title};
use std::path::Path;

fn git(root: &Path, arguments: &[&str]) -> String {
    let result = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Owned fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().into()
}

fn advance(root: &Path, parent: Option<&str>) -> String {
    let tree = git(root, &["write-tree"]);
    let mut arguments = vec![
        "commit-tree",
        &tree,
        "-m",
        "fixture: record owned source revision",
    ];
    if let Some(parent) = parent {
        arguments.extend(["-p", parent]);
    }
    let revision = git(root, &arguments);
    git(root, &["update-ref", "refs/heads/main", &revision]);
    revision
}

fn wait_for_facts(app: &mut ShellApp) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while app.active_target_facts_loading() && std::time::Instant::now() < deadline {
        app.apply_target_candidate_discovery_results();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        app.active_target_facts().is_some(),
        "repository facts did not arrive"
    );
}

fn accepted_repository() -> (tempfile::TempDir, ShellApp, String) {
    let (root, mut app) = fixture();
    wait_for_facts(&mut app);
    git(root.path(), &["init", "--initial-branch=main"]);
    git(root.path(), &["add", "README.md", "auth/login.rs"]);
    let initial = advance(root.path(), None);
    let update = press(&mut app, KeyCode::Char('c'));
    finish(&mut app, root.path(), update).unwrap();
    wait_for_facts(&mut app);
    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::End);
    let update = press(&mut app, KeyCode::Enter);
    finish(&mut app, root.path(), update).unwrap();
    wait_for_facts(&mut app);
    (root, app, initial)
}

#[test]
fn reopening_reader_compares_real_sha_without_changing_record_or_operator_state() {
    let (root, mut app, initial) = accepted_repository();
    let reference = app
        .scope_review()
        .unwrap()
        .review
        .as_ref()
        .unwrap()
        .reference
        .clone();
    assert_eq!(
        scope_source_view(&app, app.scope_review().unwrap()).label(),
        "Last SHA matches; files unchecked"
    );
    app.set_input("held draft\nwith its next line");
    app.set_cursor(4);
    app.router.scope_review_mut().as_mut().unwrap().scroll = 6;
    let origin = app.shell_view();
    let current = advance(root.path(), Some(&initial));
    assert_ne!(current, initial);
    assert!(app.open_scope_review().is_empty());
    assert_eq!(
        scope_source_view(&app, app.scope_review().unwrap()).label(),
        "Reading repository facts"
    );
    wait_for_facts(&mut app);
    let state = app.scope_review().unwrap();
    let source = scope_source_view(&app, state);
    assert!(source.differs());
    assert_eq!(source.observed_revision.as_deref(), Some(current.as_str()));
    assert!(scope_title(state, &source).contains("SHA DIFFERS"));
    assert_eq!(state.review.as_ref().unwrap().reference, reference);
    assert!(state.review.as_ref().unwrap().record.acceptance.is_some());
    assert_eq!(
        (app.input(), app.cursor(), state.scroll),
        ("held draft\nwith its next line", 4, 6)
    );
    assert_eq!(app.shell_view(), origin);
    assert!(app.findings().is_empty());
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn explicit_refresh_observes_modified_files_without_inferring_content_equality() {
    let (root, mut app, initial) = accepted_repository();
    std::fs::write(
        root.path().join("README.md"),
        "Owned changed text. Never executed.\n",
    )
    .unwrap();
    let update = press(&mut app, KeyCode::Char('r'));
    finish(&mut app, root.path(), update).unwrap();
    wait_for_facts(&mut app);
    let source = scope_source_view(&app, app.scope_review().unwrap());
    assert_eq!(source.observed_revision.as_deref(), Some(initial.as_str()));
    assert_eq!(source.label(), "Last check: working tree modified");
    assert!(!source.differs());
    let text = crate::render_plain_app(&app, 120);
    assert!(text.contains("Last observed Git SHA"));
    assert!(text.contains("Recorded boundary approval: accepted"));
    assert!(text.contains(&initial));
}

#[test]
fn facts_for_another_target_cannot_classify_scope_source() {
    let (root, app, _) = accepted_repository();
    let mut state = app.scope_review().unwrap().clone();
    state.target = root.path().join("another-target");
    let source = scope_source_view(&app, &state);
    assert_eq!(source.observed_revision, None);
    assert_eq!(source.label(), "Source unchecked; facts incomplete");
}

#[test]
fn failed_scope_request_reveals_its_notice_after_paging_without_replacing_draft() {
    let (_root, mut app) = fixture();
    app.set_input("keep operator draft");
    app.set_cursor(4);
    app.router.scope_review_mut().as_mut().unwrap().scroll = 100;
    press(&mut app, KeyCode::Char('r'));
    app.scope_review_failed("pack:scopes", "Git revision changed");
    assert_eq!(app.scope_review().unwrap().scroll, 0);
    assert_eq!((app.input(), app.cursor()), ("keep operator draft", 4));
    let text = crate::render_plain_app(&app, 40);
    assert!(text.contains("Action stopped"));
    assert!(text.contains("r reload"));
}
