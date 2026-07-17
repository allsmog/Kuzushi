use crate::OnboardingWorld;
use cucumber::{then, when};
use std::time::Duration;

#[when(regex = r#"^I resize the live terminal to (\d+) by (\d+)$"#)]
async fn resize_live_terminal(world: &mut OnboardingWorld, width: u16, height: u16) {
    let capture = world
        .require_session()
        .resize_to(width, height, Duration::from_secs(5))
        .expect("live tmux resize failed");
    world.last_live_capture = Some(capture);
}

#[then("the same shell process is still running")]
async fn same_shell_process_is_running(world: &mut OnboardingWorld) {
    let expected = world
        .shell_pane_pid
        .expect("scenario did not record the launch pane pid");
    let actual = world
        .require_session()
        .pane_pid()
        .expect("tmux pane pid query failed after resize");
    assert_eq!(actual, expected, "resize replaced the shell pane process");
}

#[then(regex = r#"^the resized live frame shows \"([^\"]+)\"$"#)]
async fn resized_live_frame_shows(world: &mut OnboardingWorld, needle: String) {
    assert!(
        world.last_live_capture.is_some(),
        "scenario did not resize before inspecting the live frame"
    );
    let expected = format!("`{needle}` in the resized live frame");
    let capture = world
        .require_session()
        .wait_for_alternate_screen_matching(&expected, Duration::from_secs(5), |snapshot| {
            snapshot.contains(&needle)
        })
        .unwrap_or_else(|error| panic!("resized live-frame capture failed: {error:#}"));
    world.last_live_capture = Some(capture);
}
