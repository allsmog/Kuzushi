use crate::OnboardingWorld;
use cucumber::{then, when};
use std::time::Duration;

/// Send the bytes emitted by xterm for Shift+Tab. This deliberately avoids
/// tmux's `BTab` key name so the scenario exercises Crossterm's real
/// `ESC [ Z` decoder and modifier shape.
#[when("I send literal xterm BackTab")]
async fn send_literal_xterm_backtab(world: &mut OnboardingWorld) {
    world
        .require_session()
        .send_literal("\u{1b}[Z")
        .expect("literal xterm BackTab delivery failed");
    std::thread::sleep(Duration::from_millis(250));
}

#[then(regex = r#"^an alternate-screen capture shows \"([^\"]+)\"$"#)]
async fn alternate_screen_capture_shows(world: &mut OnboardingWorld, needle: String) {
    let expected = format!("`{needle}` in one live alternate-screen frame");
    world
        .require_session()
        .wait_for_alternate_screen_matching(&expected, Duration::from_secs(5), |snapshot| {
            snapshot.contains(&needle)
        })
        .unwrap_or_else(|error| panic!("alternate-screen capture failed: {error:#}"));
}

#[then(regex = r#"^one alternate-screen row shows \"([^\"]+)\" and \"([^\"]+)\"$"#)]
async fn alternate_screen_row_shows_both(world: &mut OnboardingWorld, left: String, right: String) {
    let expected = format!("one live row containing `{left}` and `{right}`");
    world
        .require_session()
        .wait_for_alternate_screen_matching(&expected, Duration::from_secs(5), |snapshot| {
            snapshot
                .lines()
                .any(|line| line.contains(&left) && line.contains(&right))
        })
        .unwrap_or_else(|error| panic!("alternate-screen row capture failed: {error:#}"));
}
