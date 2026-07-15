use crate::OnboardingWorld;
use cucumber::{given, then, when};
use std::time::{Duration, Instant};

/// Point the isolated shell at a deterministic, process-local bridge. The
/// fixture handles the real next-step preflight, requests one operator choice,
/// and returns its final answer only after the selected option is threaded
/// back as a tool result.
#[given("a deterministic operator-question bridge is configured")]
async fn deterministic_operator_question_bridge(world: &mut OnboardingWorld) {
    let bridge = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/operator-question-bridge.sh");
    assert!(
        bridge.is_file(),
        "missing bridge fixture {}",
        bridge.display()
    );
    world.env.insert(
        "KUZUSHI_LANGGRAPH_BRIDGE".to_string(),
        format!("/bin/sh {}", bridge.display()),
    );
    world.env.insert(
        "KUZUSHI_API_KEY_ENV".to_string(),
        "ANTHROPIC_API_KEY".to_string(),
    );
}

#[when(regex = r#"^I submit shell command \"([^\"]+)\"$"#)]
async fn submit_shell_command(world: &mut OnboardingWorld, command: String) {
    let session = world.require_session();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let snapshot = session.snapshot().expect("prompt snapshot failed");
        if shell_prompt_is_ready(&snapshot) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "shell prompt did not become ready before `{command}`:\n{snapshot}"
        );
        session
            .send_keys(&["Escape"])
            .expect("returning to the shell prompt failed");
        std::thread::sleep(Duration::from_millis(300));
    }
    session
        .send_literal(&command)
        .expect("typing shell command failed");
    session
        .send_keys(&["Enter"])
        .expect("submitting shell command failed");
    std::thread::sleep(Duration::from_millis(300));
}

fn shell_prompt_is_ready(snapshot: &str) -> bool {
    snapshot.lines().rev().take(5).any(|line| {
        line.contains("kuzushi>")
            || (line.contains('›') && !line.contains("NAVIGATE") && !line.contains("Run Focus"))
    })
}

#[then("the deterministic operator question card appears")]
async fn deterministic_question_card_appears(world: &mut OnboardingWorld) {
    let session = world.require_session();
    if session
        .wait_for("WAITING INPUT", Duration::from_secs(5))
        .is_ok()
    {
        return;
    }
    session
        .send_keys(&["Escape"])
        .expect("returning to prompt for diagnostics failed");
    session
        .send_literal("logs")
        .expect("typing diagnostic logs command failed");
    session
        .send_keys(&["Enter"])
        .expect("opening diagnostic logs failed");
    std::thread::sleep(Duration::from_millis(300));
    let snapshot = session.snapshot().expect("diagnostic snapshot failed");
    panic!("operator question card did not appear; diagnostic logs:\n{snapshot}");
}
