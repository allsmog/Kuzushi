use super::*;
use kuzushi_core::{V2Config, WorkspaceTarget};
use std::path::Path;
use std::process::Command;

fn git(root: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn commit(root: &Path, message: &str) -> String {
    git(root, &["add", ".gitignore", "hello.txt"]);
    git(
        root,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            message,
        ],
    );
    git(root, &["rev-parse", "HEAD"])
}

fn owned_repository() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join(".gitignore"),
        "# Local workspace state has its own ignore rules.\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("hello.txt"),
        "Owned inert source. Never executed.\n",
    )
    .unwrap();
    git(root.path(), &["init", "--initial-branch=main"]);
    commit(root.path(), "Owned initial source");
    root
}

fn wait_for_facts(app: &mut ShellApp) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while app.active_target_facts().is_none() && std::time::Instant::now() < deadline {
        app.apply_target_candidate_discovery_results();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        app.active_target_facts().is_some(),
        "target facts did not arrive"
    );
}

#[test]
fn reopening_setup_refreshes_source_revision_without_consuming_operator_state() {
    let root = owned_repository();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.open_setup();
    wait_for_facts(&mut app);
    let initial = app.active_target_facts().unwrap().revision.clone().unwrap();
    std::fs::write(
        root.path().join("hello.txt"),
        "Owned second source. Never executed.\n",
    )
    .unwrap();
    let current = commit(root.path(), "Owned source revision");
    assert_ne!(current, initial);
    app.engagement.planning_picker_mut().selected_mut().clear();
    app.engagement
        .planning_picker_mut()
        .selected_mut()
        .insert(PlanningTaskId::GatherRepoContext);
    app.router.setup_mut().set_cursor(4);
    app.set_input("keep this draft\nwith its second line");
    app.set_cursor(5);
    let selected = app.engagement.planning_picker().selected().clone();

    app.open_setup();

    assert!(app.active_target_facts_loading());
    assert!(app.active_target_facts().is_none());
    wait_for_facts(&mut app);
    let facts = app.active_target_facts().unwrap();
    assert_eq!(facts.revision.as_deref(), Some(current.as_str()));
    assert_eq!(facts.dirty, Some(false));
    assert_eq!(app.input(), "keep this draft\nwith its second line");
    assert_eq!(app.cursor(), 5);
    assert_eq!(app.router.setup().cursor(), 4);
    assert_eq!(app.engagement.planning_picker().selected(), &selected);
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(app.engagement.current_phase(), None);
    assert!(app.engagement.running_tool().is_none());
    assert!(!workspace.root().join(".kuzushi/v3/runs").exists());
}

#[test]
fn reopening_setup_does_not_replace_an_inspection_already_pending() {
    let root = owned_repository();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    wait_for_facts(&mut app);
    let facts = app.active_target_facts().unwrap().clone();
    app.session_mut()
        .begin_active_target_facts(facts.path.clone(), 999);

    app.open_setup();

    assert!(app.active_target_facts_loading());
    assert!(app
        .session_mut()
        .apply_active_target_facts(crate::app::StampedTargetCandidateFacts {
            generation: 999,
            facts,
        }));
    assert!(!app.active_target_facts_loading());
}
