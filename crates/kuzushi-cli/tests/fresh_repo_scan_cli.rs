use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

fn kuzushi(home: &Path, path: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kuzushi"));
    command
        .env("HOME", home)
        .env("PATH", path)
        .env_remove("KUZUSHI_MODEL")
        .env_remove("KUZUSHI_V2_MODEL")
        .env_remove("KUZUSHI_LANGGRAPH_BRIDGE")
        .env_remove("KUZUSHI_V2_LANGGRAPH_BRIDGE");
    command
}

fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn fresh_repo() -> (tempfile::TempDir, tempfile::TempDir, tempfile::TempDir) {
    let home = tempfile::tempdir().unwrap();
    let path = tempfile::tempdir().unwrap();
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("app.py"), "print('hello')\n").unwrap();
    (home, path, repo)
}

fn latest_run_id(repo: &Path) -> String {
    std::fs::read_to_string(repo.join(".kuzushi/v3/latest"))
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn automatic_standard_scan_skips_missing_optional_binaries_and_completes() {
    let (home, path, repo) = fresh_repo();
    let output = kuzushi(home.path(), path.path())
        .arg("scan")
        .arg(repo.path())
        .args(["--mode", "standard", "--ci"])
        .output()
        .unwrap();
    let text = output_text(&output);

    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("warning: optional auto task semgrep skipped"),
        "{text}"
    );
    assert!(
        text.contains("warning: optional auto task cargo-audit skipped"),
        "{text}"
    );
    assert!(text.contains("exit: 0"), "{text}");

    let run_id = latest_run_id(repo.path());
    let result_path = repo
        .path()
        .join(".kuzushi/v3/runs")
        .join(run_id)
        .join("result.json");
    let result: Value =
        serde_json::from_str(&std::fs::read_to_string(result_path).unwrap()).unwrap();
    let skipped = result
        .pointer("/data/skippedEngines")
        .and_then(Value::as_array)
        .unwrap();
    assert!(skipped.contains(&Value::String("semgrep".to_string())));
    assert!(skipped.contains(&Value::String("cargo-audit".to_string())));
}

#[test]
fn explicitly_requested_missing_semgrep_fails_closed_with_persisted_run_recovery() {
    let (home, path, repo) = fresh_repo();
    let output = kuzushi(home.path(), path.path())
        .arg("scan")
        .arg(repo.path())
        .args(["--tasks", "semgrep", "--ci"])
        .output()
        .unwrap();
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("semgrep preflight failed"), "{text}");
    assert!(!text.contains("task block semgrep"), "{text}");
    let run_id = latest_run_id(repo.path());
    let recovery = format!("kuzushi --target . runs show {run_id}");
    assert!(text.contains(&format!("persisted run {run_id}")), "{text}");
    assert!(text.contains("from the target directory"), "{text}");
    assert!(text.contains(&recovery), "wanted {recovery:?} in:\n{text}");
    let recovered = kuzushi(home.path(), path.path())
        .current_dir(repo.path())
        .args(["--target", ".", "runs", "show", &run_id])
        .output()
        .unwrap();
    assert!(recovered.status.success(), "{}", output_text(&recovered));
    assert!(
        repo.path()
            .join(".kuzushi/v3/runs")
            .join(run_id)
            .join("run.json")
            .exists(),
        "failed scan should retain its canonical run artifact"
    );
}

#[test]
fn explicitly_requested_missing_cargo_audit_fails_closed_for_rust_repo() {
    let (home, path, repo) = fresh_repo();
    std::fs::write(repo.path().join("Cargo.lock"), "version = 3\n").unwrap();
    let output = kuzushi(home.path(), path.path())
        .arg("scan")
        .arg(repo.path())
        .args(["--tasks", "cargo-audit", "--ci"])
        .output()
        .unwrap();
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(
        text.contains("cargo-audit preflight failed")
            && text.contains("cargo-audit executable \"cargo-audit\" is unavailable")
            && text.contains("no Cargo shim or replacement is used"),
        "{text}"
    );
    let run_id = latest_run_id(repo.path());
    assert!(text.contains(&format!("persisted run {run_id}")), "{text}");
}

#[test]
fn explicitly_requested_cargo_audit_requires_a_lockfile() {
    let (home, path, repo) = fresh_repo();
    std::fs::write(
        repo.path().join("Cargo.toml"),
        "[package]\nname = \"fresh\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let output = kuzushi(home.path(), path.path())
        .arg("scan")
        .arg(repo.path())
        .args(["--tasks", "cargo-audit", "--ci"])
        .output()
        .unwrap();
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("target has no Cargo.lock"), "{text}");
    assert!(text.contains("cargo generate-lockfile"), "{text}");
    let run_id = latest_run_id(repo.path());
    assert!(text.contains(&format!("persisted run {run_id}")), "{text}");
}

#[test]
fn automatic_task_filter_still_skips_inapplicable_optional_scanners() {
    let (home, path, repo) = fresh_repo();
    let output = kuzushi(home.path(), path.path())
        .arg("--target")
        .arg(repo.path())
        .args([
            "run",
            "sast:scan",
            "--input",
            r#"{"disabledTasks":["semgrep"]}"#,
        ])
        .output()
        .unwrap();
    let text = output_text(&output);

    assert!(output.status.success(), "{text}");
    let result: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        result.pointer("/data/skippedEngines"),
        Some(&serde_json::json!(["cargo-audit"]))
    );
}

#[test]
fn disabling_every_automatic_task_does_not_restore_the_defaults() {
    let (home, path, repo) = fresh_repo();
    let output = kuzushi(home.path(), path.path())
        .arg("--target")
        .arg(repo.path())
        .args([
            "run",
            "sast:scan",
            "--input",
            r#"{"disabledTasks":["semgrep","dep-hygiene","cargo-audit","secret-scan","license-scan","iac-scan"]}"#,
        ])
        .output()
        .unwrap();
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("selected no scan engines"), "{text}");
    assert!(!text.contains("dep-hygiene:"), "{text}");
    assert!(!text.contains("secret-scan:"), "{text}");
    assert!(!text.contains("iac-scan:"), "{text}");
}

#[test]
fn explicit_tasks_override_the_automatic_task_denylist() {
    let (home, path, repo) = fresh_repo();
    let output = kuzushi(home.path(), path.path())
        .arg("--target")
        .arg(repo.path())
        .args([
            "run",
            "sast:scan",
            "--input",
            r#"{"taskMode":"manual","tasks":["dep-hygiene"],"disabledTasks":["dep-hygiene"]}"#,
        ])
        .output()
        .unwrap();
    let text = output_text(&output);

    assert!(output.status.success(), "{text}");
    let result: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        result.pointer("/data/engines"),
        Some(&serde_json::json!(["dep-hygiene"]))
    );
}

#[test]
fn explicit_empty_task_list_does_not_restore_automatic_defaults() {
    let (home, path, repo) = fresh_repo();
    let output = kuzushi(home.path(), path.path())
        .arg("--target")
        .arg(repo.path())
        .args(["run", "sast:scan", "--input", r#"{"tasks":[]}"#])
        .output()
        .unwrap();
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("selected no scan engines"), "{text}");
    assert!(!text.contains("dep-hygiene:"), "{text}");
    assert!(!text.contains("secret-scan:"), "{text}");
    assert!(!text.contains("iac-scan:"), "{text}");
}

#[test]
fn missing_scan_target_guidance_uses_parser_valid_flag_placement() {
    let home = tempfile::tempdir().unwrap();
    let path = tempfile::tempdir().unwrap();
    let output = kuzushi(home.path(), path.path())
        .args(["scan", "--ci"])
        .output()
        .unwrap();
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("kuzushi scan <path>"), "{text}");
    assert!(text.contains("kuzushi --target <path> scan"), "{text}");
    assert!(!text.contains("kuzushi scan --target"), "{text}");
}

#[test]
fn doctor_explains_that_missing_optional_default_scanners_do_not_block_auto_scan() {
    let (home, path, repo) = fresh_repo();
    let output = kuzushi(home.path(), path.path())
        .arg("--target")
        .arg(repo.path())
        .arg("doctor")
        .output()
        .unwrap();
    let text = output_text(&output);

    assert!(
        text.contains("Semgrep is optional for automatic scans"),
        "{text}"
    );
    assert!(
        text.contains("automatic scans skip this optional task visibly"),
        "{text}"
    );
}
