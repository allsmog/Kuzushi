use super::*;
use std::process::Stdio;

#[cfg(unix)]
const PARENT_DEATH_FIXTURE_ENV: &str = "KUZUSHI_MCP_PARENT_DEATH_FIXTURE";

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

#[cfg(unix)]
#[test]
fn abrupt_owner_death_kills_the_guarded_process_group() {
    let fixture = tempfile::tempdir().unwrap();
    let pid_path = fixture.path().join("child.pid");
    let mut owner = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("parent_death_owner_helper")
        .arg("--nocapture")
        .env(PARENT_DEATH_FIXTURE_ENV, &pid_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let child_pid = wait_for_fixture_pid(&pid_path, &mut owner);

    owner.kill().unwrap();
    owner.wait().unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while process_is_alive(child_pid) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        !process_is_alive(child_pid),
        "guarded child {child_pid} survived abrupt owner death"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn parent_death_owner_helper() {
    let Some(pid_path) = std::env::var_os(PARENT_DEATH_FIXTURE_ENV) else {
        return;
    };
    let mut command = Command::new("sh");
    command
        .args([
            "-c",
            "printf '%s' \"$$\" > \"$1\"; sleep 30",
            "guarded-child",
        ])
        .arg(pid_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let _ = run_bounded_process(
        &mut command,
        "parent-death fixture",
        ProcessLimits {
            timeout: Duration::from_secs(60),
            ..ProcessLimits::default()
        },
    )
    .await;
}

#[cfg(unix)]
fn wait_for_fixture_pid(path: &std::path::Path, owner: &mut std::process::Child) -> u32 {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Ok(value) = std::fs::read_to_string(path) {
            if let Ok(pid) = value.parse() {
                return pid;
            }
        }
        assert!(
            owner.try_wait().unwrap().is_none(),
            "parent-death helper exited before publishing its child pid"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("parent-death helper did not publish its child pid");
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
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
