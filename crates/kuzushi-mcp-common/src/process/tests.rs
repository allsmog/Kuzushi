use super::*;
use std::process::Stdio;

#[test]
fn terminal_controls_are_escaped() {
    assert_eq!(
        sanitize_terminal_text("ok\n\u{1b}[31m\r"),
        "ok\n\\u{1b}[31m\\u{d}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn output_limit_stops_the_process() {
    let mut command = Command::new("sh");
    command
        .args(["-c", "printf 12345; sleep 30"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let error = run_bounded_process(
        &mut command,
        "fixture",
        ProcessLimits {
            timeout: Duration::from_secs(2),
            stdout_bytes: 4,
            stderr_bytes: 16,
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("4-byte capture limit"));
}

#[cfg(unix)]
#[tokio::test]
async fn timeout_stops_the_process() {
    let mut command = Command::new("sh");
    command
        .args(["-c", "sleep 30"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let error = run_bounded_process(
        &mut command,
        "fixture",
        ProcessLimits {
            timeout: Duration::from_millis(50),
            ..ProcessLimits::default()
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("deadline"));
}

#[cfg(unix)]
#[tokio::test]
async fn inherited_pipes_remain_under_the_original_deadline() {
    let mut command = Command::new("sh");
    command
        .args(["-c", "sleep 30 &"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let error = run_bounded_process(
        &mut command,
        "descendant fixture",
        ProcessLimits {
            timeout: Duration::from_millis(100),
            ..ProcessLimits::default()
        },
    )
    .await
    .unwrap_err();

    assert!(error.to_string().contains("output-drain deadline"));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[cfg(windows)]
#[tokio::test]
async fn windows_job_contains_a_basic_child() {
    let mut command = Command::new("cmd");
    command
        .args(["/C", "echo ready"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = run_bounded_process(&mut command, "Windows fixture", ProcessLimits::default())
        .await
        .unwrap();

    assert!(output.status.success());
    assert!(output.stdout.contains("ready"));
}
