use crate::OnboardingWorld;
use cucumber::{then, when};
use std::time::{Duration, Instant};

#[when(regex = r#"^I press "([^"]+)"$"#)]
async fn press_key(world: &mut OnboardingWorld, key: String) {
    let tmux_key = translate_key(&key);
    let run_focus_capture = {
        let session = world.require_session();
        session
            .send_keys(&[&tmux_key])
            .expect("tmux send-keys failed");
        settle_after_key(session, &tmux_key)
    };
    if let Some(capture) = run_focus_capture {
        world.last_run_focus_capture = Some(capture);
    }
}

#[when(regex = r#"^I press "([^"]+)" then immediately "([^"]+)"$"#)]
async fn press_key_pair_without_delay(world: &mut OnboardingWorld, first: String, second: String) {
    let session = world.require_session();
    let first = translate_key(&first);
    let second = translate_key(&second);
    session
        .send_keys(&[&first, &second])
        .expect("tmux send-keys pair failed");
    std::thread::sleep(Duration::from_millis(250));
}

#[when(regex = r#"^I type command "([^"]+)"$"#)]
async fn type_command(world: &mut OnboardingWorld, command: String) {
    let session = world.require_session();
    session
        .send_keys(&["Escape"])
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

#[then(regex = r#"^one Run Focus capture shows "([^"]+)" and "([^"]+)"$"#)]
async fn run_focus_capture_shows_both(world: &mut OnboardingWorld, left: String, right: String) {
    if world
        .last_run_focus_capture
        .as_deref()
        .is_some_and(|snapshot| run_focus_shows_both(snapshot, &left, &right))
    {
        return;
    }
    let session = world.require_session();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = session.snapshot().expect("snapshot failed");
        if run_focus_shows_both(&snapshot, &left, &right) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Run Focus never showed `{left}` and `{right}` together:\n{snapshot}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[then(
    regex = r#"^one compact Run Focus capture shows plan "([^"]+)" then "([^"]+)" with "([^"]+)" above "([^"]+)" without a shell prompt$"#
)]
async fn compact_run_focus_capture_is_stacked(
    world: &mut OnboardingWorld,
    first_task: String,
    second_task: String,
    upper: String,
    lower: String,
) {
    if last_compact_capture_matches(world, &first_task, &second_task, &upper, &lower) {
        return;
    }
    let mut captured_run_focus = world.last_run_focus_capture.clone();
    let session = world.require_session();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = session.snapshot().expect("snapshot failed");
        if compact_run_focus_matches(&snapshot, &first_task, &second_task, &upper, &lower) {
            return;
        }
        remember_run_focus_capture(&mut captured_run_focus, &snapshot);
        assert!(
            Instant::now() < deadline,
            "compact Run Focus never showed `{first_task}` then `{second_task}` with `{upper}` above `{lower}` and no shell prompt. Last captured Run Focus:\n{}\nFinal frame:\n{snapshot}",
            captured_run_focus.as_deref().unwrap_or("<none>"),
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn remember_run_focus_capture(captured: &mut Option<String>, snapshot: &str) {
    if snapshot.contains("RUN FOCUS") {
        *captured = Some(snapshot.to_string());
    }
}

fn last_compact_capture_matches(
    world: &OnboardingWorld,
    first_task: &str,
    second_task: &str,
    upper: &str,
    lower: &str,
) -> bool {
    world
        .last_run_focus_capture
        .as_deref()
        .is_some_and(|snapshot| {
            compact_run_focus_matches(snapshot, first_task, second_task, upper, lower)
        })
}

fn settle_after_key(session: &crate::tmux_harness::TmuxSession, key: &str) -> Option<String> {
    if key != "Enter" {
        std::thread::sleep(Duration::from_millis(250));
        return None;
    }
    capture_run_focus_during(session, Duration::from_millis(250))
}

fn capture_run_focus_during(
    session: &crate::tmux_harness::TmuxSession,
    duration: Duration,
) -> Option<String> {
    let deadline = Instant::now() + duration;
    let mut capture = None;
    loop {
        capture = run_focus_snapshot(session).or(capture);
        if Instant::now() >= deadline {
            return capture;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run_focus_snapshot(session: &crate::tmux_harness::TmuxSession) -> Option<String> {
    let snapshot = session.snapshot().ok()?;
    snapshot.contains("RUN FOCUS").then_some(snapshot)
}

fn run_focus_shows_both(snapshot: &str, left: &str, right: &str) -> bool {
    snapshot.contains("RUN FOCUS")
        && snapshot
            .lines()
            .any(|line| line.contains(left) && line.contains(right))
}

fn compact_run_focus_matches(
    snapshot: &str,
    first_task: &str,
    second_task: &str,
    upper: &str,
    lower: &str,
) -> bool {
    snapshot.contains("RUN FOCUS")
        && labels_are_stacked(snapshot, upper, lower)
        && labels_are_ordered(snapshot, first_task, second_task)
        && run_focus_is_promptless(snapshot)
}

fn labels_are_stacked(snapshot: &str, upper: &str, lower: &str) -> bool {
    snapshot
        .lines()
        .position(|line| line.contains(upper))
        .zip(snapshot.lines().position(|line| line.contains(lower)))
        .is_some_and(|(upper_row, lower_row)| upper_row < lower_row)
}

fn labels_are_ordered(snapshot: &str, first: &str, second: &str) -> bool {
    snapshot
        .find(first)
        .zip(snapshot.find(second))
        .is_some_and(|(first, second)| first < second)
}

fn run_focus_is_promptless(snapshot: &str) -> bool {
    ![
        "NAVIGATION MODE",
        "command prompt paused",
        "describe what to ",
        "kuzushi>",
    ]
    .iter()
    .any(|marker| snapshot.contains(marker))
}

#[then(regex = r#"^the live terminal is (\d+) by (\d+)$"#)]
async fn live_terminal_has_size(world: &mut OnboardingWorld, width: u16, height: u16) {
    let actual = world
        .require_session()
        .pane_size()
        .expect("tmux pane size query failed");
    assert_eq!(
        actual,
        (width, height),
        "live tmux pane used the wrong size"
    );
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
    let matched = planning_row_is_checked(&snapshot, &label);
    assert!(
        matched,
        "expected `{label}` row to be checked; pane was:\n{snapshot}"
    );
}

#[then(regex = r#"^"([^"]+)" is unchecked$"#)]
async fn row_unchecked(world: &mut OnboardingWorld, label: String) {
    let session = world.require_session();
    let snapshot = session.snapshot().expect("snapshot failed");
    let matched = planning_row_is_unchecked(&snapshot, &label);
    assert!(
        matched,
        "expected `{label}` row to be unchecked; pane was:\n{snapshot}"
    );
}

fn planning_row_is_checked(snapshot: &str, label: &str) -> bool {
    snapshot.lines().any(|line| {
        line.contains(label)
            && (line.contains("[x]") || line.contains(" RUN ") || line.contains(" REUSE "))
    })
}

fn planning_row_is_unchecked(snapshot: &str, label: &str) -> bool {
    snapshot.lines().any(|line| {
        line.contains(label)
            && (line.contains("[ ]") || line.contains(" SKIP ") || line.contains(" BLOCKED "))
    })
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

#[cfg(test)]
mod tests {
    use super::{
        compact_run_focus_matches, planning_row_is_checked, planning_row_is_unchecked,
        remember_run_focus_capture, run_focus_shows_both,
    };

    const STACKED_RUN_FOCUS: &str = "\
RUN FOCUS · MAP\n\
TASKS\n\
context:build\n\
entry-points:extract\n\
OUTPUT\n";

    #[test]
    fn retained_run_focus_requires_both_labels_on_one_row() {
        assert!(run_focus_shows_both(
            "RUN FOCUS\nTASKS · OUTPUT\n",
            "TASKS",
            "OUTPUT"
        ));
        assert!(!run_focus_shows_both(STACKED_RUN_FOCUS, "TASKS", "OUTPUT"));
    }

    #[test]
    fn compact_run_focus_requires_ordered_stacked_promptless_content() {
        assert!(compact_run_focus_matches(
            STACKED_RUN_FOCUS,
            "context:build",
            "entry-points:extract",
            "TASKS",
            "OUTPUT"
        ));
        assert!(!compact_run_focus_matches(
            &format!("{STACKED_RUN_FOCUS}command prompt paused"),
            "context:build",
            "entry-points:extract",
            "TASKS",
            "OUTPUT"
        ));
    }

    #[test]
    fn unavailable_planning_rows_are_not_checked() {
        let snapshot = "  BLOCKED Build code property graph · needs a tool on PATH\n";

        assert!(planning_row_is_unchecked(
            snapshot,
            "Build code property graph"
        ));
        assert!(!planning_row_is_checked(
            snapshot,
            "Build code property graph"
        ));
    }

    #[test]
    fn run_focus_diagnostic_capture_ignores_unrelated_frames() {
        let mut captured = Some("previous Run Focus".to_string());

        remember_run_focus_capture(&mut captured, "SETUP\nTarget ready");
        assert_eq!(captured.as_deref(), Some("previous Run Focus"));

        remember_run_focus_capture(&mut captured, "RUN FOCUS\nTASKS");
        assert_eq!(captured.as_deref(), Some("RUN FOCUS\nTASKS"));
    }
}
