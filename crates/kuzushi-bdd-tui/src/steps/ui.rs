use crate::OnboardingWorld;
use cucumber::{then, when};
use std::time::Duration;

#[when(regex = r#"^I press "([^"]+)"$"#)]
async fn press_key(world: &mut OnboardingWorld, key: String) {
    let session = world.require_session();
    let tmux_key = translate_key(&key);
    session
        .send_keys(&[&tmux_key])
        .expect("tmux send-keys failed");
    std::thread::sleep(Duration::from_millis(250));
}

#[when(regex = r#"^I type command "([^"]+)"$"#)]
async fn type_command(world: &mut OnboardingWorld, command: String) {
    let session = world.require_session();
    session
        .send_keys(&["F2"])
        .expect("tmux navigation-mode entry failed");
    std::thread::sleep(Duration::from_millis(150));
    session
        .send_keys(&["Escape"])
        .expect("tmux prompt-mode return failed");
    std::thread::sleep(Duration::from_millis(150));
    session
        .send_literal(&command)
        .expect("tmux literal command input failed");
    session
        .send_keys(&["Enter"])
        .expect("tmux command submission failed");
    std::thread::sleep(Duration::from_millis(250));
}

#[when(regex = r#"^I type text "([^"]+)"$"#)]
async fn type_text(world: &mut OnboardingWorld, value: String) {
    world
        .require_session()
        .send_literal(&value)
        .expect("tmux literal input failed");
    std::thread::sleep(Duration::from_millis(250));
}

#[when(regex = r#"^I move the cursor to "([^"]+)"$"#)]
async fn move_cursor_to(world: &mut OnboardingWorld, label: String) {
    let session = world.require_session();
    // Up to 10 Down presses to find the row — every planning picker fits.
    for _ in 0..10 {
        let snapshot = session.snapshot().expect("snapshot failed");
        if snapshot
            .lines()
            .any(|line| line.contains("> ") && line.contains(&label))
        {
            return;
        }
        session
            .send_keys(&["Down"])
            .expect("tmux send-keys Down failed");
        std::thread::sleep(Duration::from_millis(120));
    }
    let final_snapshot = session.snapshot().unwrap_or_default();
    panic!("cursor never landed on `{label}` after 10 Down presses:\n{final_snapshot}");
}

#[then(regex = r#"^I see "([^"]+)"$"#)]
async fn see(world: &mut OnboardingWorld, needle: String) {
    let session = world.require_session();
    session
        .wait_for(&needle, Duration::from_secs(5))
        .expect("expected substring never appeared");
}

#[then(regex = r#"^I do not see "([^"]+)"$"#)]
async fn do_not_see(world: &mut OnboardingWorld, needle: String) {
    let session = world.require_session();
    let snapshot = session.snapshot().expect("snapshot failed");
    assert!(
        !snapshot.contains(&needle),
        "unexpected substring `{needle}` in pane:\n{snapshot}"
    );
}

#[then(regex = r#"^the log contains "([^"]+)"$"#)]
async fn log_contains(world: &mut OnboardingWorld, needle: String) {
    let session = world.require_session();
    session
        .wait_for(&needle, Duration::from_secs(5))
        .expect("expected log substring never appeared");
}

#[then(regex = r#"^"([^"]+)" is checked$"#)]
async fn row_checked(world: &mut OnboardingWorld, label: String) {
    let session = world.require_session();
    let snapshot = session.snapshot().expect("snapshot failed");
    let matched = snapshot.lines().any(|line| {
        line.contains(&label)
            && (line.contains("[x]") || line.contains(" RUN ") || line.contains(" REUSE "))
    });
    assert!(
        matched,
        "expected `{label}` row to be checked; pane was:\n{snapshot}"
    );
}

#[then(regex = r#"^"([^"]+)" is unchecked$"#)]
async fn row_unchecked(world: &mut OnboardingWorld, label: String) {
    let session = world.require_session();
    let snapshot = session.snapshot().expect("snapshot failed");
    let matched = snapshot
        .lines()
        .any(|line| line.contains(&label) && (line.contains("[ ]") || line.contains(" SKIP ")));
    assert!(
        matched,
        "expected `{label}` row to be unchecked; pane was:\n{snapshot}"
    );
}

#[then(regex = r#"^the status segment shows "([^"]+)"$"#)]
async fn status_shows(world: &mut OnboardingWorld, segment: String) {
    let session = world.require_session();
    session
        .wait_for_status_segment(&segment, Duration::from_secs(3))
        .expect("status segment never appeared");
}

#[then("the selected target consent is visible")]
async fn selected_target_consent_visible(world: &mut OnboardingWorld) {
    assert_target_identity_line(world, "Enter selects");
}

#[then("the confirmed target is visible")]
async fn confirmed_target_visible(world: &mut OnboardingWorld) {
    assert_target_identity_line(world, "Target confirmed");
}

#[then("the Enter plan summary and controls are visible")]
async fn plan_confirmation_visible(world: &mut OnboardingWorld) {
    let snapshot = world.require_session().snapshot().expect("snapshot failed");
    assert!(
        snapshot.lines().any(|line| line.contains("Enter:")),
        "missing Enter summary:\n{snapshot}"
    );
    assert!(
        snapshot.lines().any(|line| line.contains("Space check")),
        "missing toggle control:\n{snapshot}"
    );
    assert!(
        snapshot.lines().any(|line| line.contains("Enter run")),
        "missing run control:\n{snapshot}"
    );
}

fn assert_target_identity_line(world: &OnboardingWorld, prefix: &str) {
    let session = world.require_session();
    session
        .wait_for(prefix, Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("target identity never appeared: {error:#}"));
    let snapshot = session.snapshot().expect("snapshot failed");
    let name = session
        .target
        .file_name()
        .expect("temp target name")
        .to_string_lossy();
    let line = snapshot
        .lines()
        .find(|line| line.contains(prefix))
        .unwrap_or_else(|| panic!("missing `{prefix}` target line:\n{snapshot}"));
    assert!(
        line.contains(name.as_ref()),
        "target line does not name resolved cwd `{name}`: {line}"
    );
    assert!(
        line.contains('/') && line.contains('·'),
        "target line does not show a resolved path: {line}"
    );
}

fn translate_key(key: &str) -> String {
    match key {
        "Up" | "Down" | "Left" | "Right" | "Enter" | "Tab" | "Escape" | "Esc" | "Space" => {
            if key == "Esc" {
                "Escape".to_string()
            } else if key == "Space" {
                "Space".to_string()
            } else {
                key.to_string()
            }
        }
        other => other.to_string(),
    }
}
