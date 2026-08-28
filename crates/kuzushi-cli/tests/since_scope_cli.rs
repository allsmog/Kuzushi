//! `kuzushi scan --since <ref>` end to end: it refuses an empty scope instead
//! of widening to the whole target, and a real scope reaches the canonical
//! `sast:scan` input so every engine is narrowed, not just the ones that read
//! `since.txt`.

#![cfg(unix)]

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

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// A PATH holding only `git`, which a git-backed workspace genuinely needs,
/// so optional scanners stay absent and the test does not depend on them.
fn git_only_path() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let git_binary = String::from_utf8(
        Command::new("/usr/bin/env")
            .args(["which", "git"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    assert!(!git_binary.is_empty(), "these tests require git on PATH");
    std::os::unix::fs::symlink(git_binary, dir.path().join("git")).unwrap();
    dir
}

/// Committed repo with `app.py` and `docs/notes.md`, returning HOME, PATH,
/// the repo, and the base revision.
fn committed_repo() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    tempfile::TempDir,
    String,
) {
    let home = tempfile::tempdir().unwrap();
    let path = git_only_path();
    let repo = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(repo.path().join("docs")).unwrap();
    std::fs::write(repo.path().join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(repo.path().join("docs/notes.md"), "notes\n").unwrap();
    git(repo.path(), &["init", "-q"]);
    git(repo.path(), &["config", "user.email", "tests@example.com"]);
    git(repo.path(), &["config", "user.name", "Kuzushi Tests"]);
    git(repo.path(), &["add", "-A"]);
    git(
        repo.path(),
        &["-c", "commit.gpgsign=false", "commit", "-qm", "base"],
    );
    let base = git(repo.path(), &["rev-parse", "HEAD"]);
    (home, path, repo, base)
}

fn run_dirs(repo: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(repo.join(".kuzushi/v3/runs")) else {
        return Vec::new();
    };
    entries
        .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
        .collect()
}

#[test]
fn since_with_no_changed_files_refuses_and_records_no_run() {
    let (home, path, repo, base) = committed_repo();
    let output = kuzushi(home.path(), path.path())
        .arg("scan")
        .arg(repo.path())
        .args(["--since", &base, "--ci"])
        .output()
        .unwrap();
    let text = output_text(&output);

    assert!(
        !output.status.success(),
        "a scan that never ran must not report success: {text}"
    );
    assert!(
        text.contains(&format!(
            "--since {base}: no existing changed files to scan"
        )),
        "{text}"
    );
    assert!(
        text.contains("--include-worktree"),
        "the refusal should name the one thing that could widen it: {text}"
    );
    assert!(
        run_dirs(repo.path()).is_empty(),
        "a refused scan must mint no run artifact, found {:?}",
        run_dirs(repo.path())
    );
    assert!(
        !repo.path().join(".kuzushi/v3/latest").exists(),
        "a refused scan must not advance the latest-run pointer: {text}"
    );
}

#[test]
fn since_intersected_to_nothing_by_paths_refuses_and_records_no_run() {
    let (home, path, repo, base) = committed_repo();
    std::fs::write(repo.path().join("app.py"), "print('changed')\n").unwrap();

    let output = kuzushi(home.path(), path.path())
        .arg("scan")
        .arg(repo.path())
        .args([
            "--since",
            &base,
            "--include-worktree",
            "--paths",
            "docs",
            "--ci",
        ])
        .output()
        .unwrap();
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(
        text.contains(&format!(
            "--since {base}: no existing changed files inside the requested paths scope"
        )),
        "{text}"
    );
    assert!(run_dirs(repo.path()).is_empty(), "{text}");
}

#[test]
fn since_narrows_the_canonical_scan_input_for_every_engine() {
    let (home, path, repo, base) = committed_repo();
    std::fs::write(repo.path().join("app.py"), "print('changed')\n").unwrap();

    let output = kuzushi(home.path(), path.path())
        .arg("scan")
        .arg(repo.path())
        .args([
            "--since",
            &base,
            "--include-worktree",
            "--mode",
            "standard",
            "--ci",
        ])
        .output()
        .unwrap();
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");

    let run_id = std::fs::read_to_string(repo.path().join(".kuzushi/v3/latest"))
        .unwrap()
        .trim()
        .to_string();
    let input: Value = serde_json::from_str(
        &std::fs::read_to_string(
            repo.path()
                .join(".kuzushi/v3/runs")
                .join(&run_id)
                .join("input.json"),
        )
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        input["paths"],
        serde_json::json!(["app.py"]),
        "the resolved since scope must reach the canonical tool input: {input}"
    );
    assert_eq!(input["diffBase"], serde_json::json!(base), "{input}");

    let scope_file = std::fs::read_to_string(repo.path().join(".kuzushi/v3/since.txt")).unwrap();
    assert_eq!(
        scope_file.lines().collect::<Vec<_>>(),
        vec!["app.py"],
        "since.txt must carry the same effective scope"
    );
}
