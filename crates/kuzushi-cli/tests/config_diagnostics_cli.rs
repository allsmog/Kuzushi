use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

fn deprecated_config(home: &Path) {
    let path = home.join(".kuzushi/v3/config.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "[phases]\nstop_after = \"confirm\"\n").unwrap();
}

fn kuzushi(home: &Path, path: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kuzushi"));
    command
        .env("HOME", home)
        .env("PATH", path)
        .env_remove("KUZUSHI_MODEL")
        .env_remove("KUZUSHI_V2_MODEL");
    command
}

fn assert_warning_and_json(output: Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("global config uses deprecated stop_after = \"confirm\"; use \"prove\""),
        "stderr: {stderr}"
    );
    serde_json::from_slice::<Value>(&output.stdout).expect("stdout stays JSON-only");
}

#[test]
fn scan_json_preserves_config_deprecation_on_stderr() {
    let home = tempfile::tempdir().unwrap();
    let path = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("app.py"), "print('hello')\n").unwrap();
    deprecated_config(home.path());

    let output = kuzushi(home.path(), path.path())
        .arg("scan")
        .arg(target.path())
        .args(["--mode", "standard", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_warning_and_json(output);
}

#[test]
fn run_json_preserves_config_deprecation_on_stderr() {
    let home = tempfile::tempdir().unwrap();
    let path = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    deprecated_config(home.path());

    let output = kuzushi(home.path(), path.path())
        .arg("--target")
        .arg(target.path())
        .args(["run", "config:show", "--input", "{}"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_warning_and_json(output);
}

#[test]
fn plain_shell_preserves_config_deprecation_on_stderr() {
    let home = tempfile::tempdir().unwrap();
    let path = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    deprecated_config(home.path());

    let output = kuzushi(home.path(), path.path())
        .args(["--plain", "--no-session-persistence", "--target"])
        .arg(target.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("global config uses deprecated stop_after = \"confirm\"; use \"prove\""),
        "stderr: {stderr}"
    );
    assert!(!output.stdout.is_empty(), "plain shell summary is preserved");
}
