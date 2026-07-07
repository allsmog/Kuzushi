//! M3 §3.1 — end-to-end bounty flow gate. Drives the shipped
//! `kuzushi` binary against a temp workspace seeded with one finding
//! and asserts the SARIF export materialises with the expected shape.
//!
//! This replaces the historically-flaky `pnpm test:e2e` smoke for
//! the export path. Run with:
//!   cargo test -p kuzushi-cli --test e2e_bounty_flow

use std::path::{Path, PathBuf};
use std::process::Command;

use kuzushi_core::{Finding, FindingStore, Severity, WorkspaceTarget};

/// Path to the freshly-compiled `kuzushi` binary cargo provides to
/// integration tests under this crate. Resolves to
/// `target/debug/kuzushi` (or release equivalent).
fn kuzushi_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kuzushi"))
}

fn seed_workspace_with_one_finding(target: &Path) {
    let workspace = WorkspaceTarget::new(target).expect("workspace target resolves");
    let store = FindingStore::open(workspace.findings_db_path()).expect("findings store opens");
    store
        .record_run_started("e2e-run", workspace.root(), "completed")
        .expect("scan run inserts");
    let finding = Finding::new_tool(
        "e2e",
        "e2e/sql-injection",
        "src/login.rs",
        42,
        Some(48),
        Severity::High,
        "request.body.username flows into raw SQL",
    );
    store
        .insert_finding("e2e-run", &finding)
        .expect("finding inserts");
}

fn run_kuzushi(args: &[&str]) -> std::process::Output {
    let output = Command::new(kuzushi_binary())
        .args(args)
        // Avoid leaking the host operator's config when CI runs the test.
        .env("KUZUSHI_DISABLE_OPERATOR_PERSISTENCE", "1")
        .output()
        .expect("kuzushi binary executes");
    if !output.status.success() {
        eprintln!(
            "kuzushi {:?} exited non-zero: stdout={:?} stderr={:?}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    output
}

#[test]
fn workspace_export_findings_writes_valid_sarif() {
    // Seeds one finding via the library, then invokes the CLI to export
    // SARIF. The test validates the SARIF document end-to-end:
    //   - file exists at the requested path
    //   - JSON parses, version == "2.1.0"
    //   - one `runs[]` entry per tool, results[] non-empty
    //   - severity → level mapping is correct (High → "error")
    //   - region.startLine, locations[].physicalLocation are present
    let workspace_dir = tempfile::tempdir().expect("tempdir");
    seed_workspace_with_one_finding(workspace_dir.path());

    let output_path = workspace_dir.path().join("out.sarif");
    let output = run_kuzushi(&[
        "export",
        "--target",
        workspace_dir.path().to_str().unwrap(),
        "--format",
        "sarif",
        "--out",
        output_path.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "workspace:export-findings must succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output_path.exists(), "SARIF file should be written");

    let body = std::fs::read_to_string(&output_path).expect("SARIF file readable");
    let document: serde_json::Value =
        serde_json::from_str(&body).expect("SARIF body parses as JSON");
    assert_eq!(
        document["version"], "2.1.0",
        "SARIF version pinned to 2.1.0"
    );
    let runs = document["runs"].as_array().expect("runs[] present");
    assert!(!runs.is_empty(), "SARIF should contain at least one run");
    let results = runs[0]["results"]
        .as_array()
        .expect("results[] present in first run");
    assert!(!results.is_empty(), "SARIF results[] should not be empty");
    let first = &results[0];
    assert_eq!(
        first["level"], "error",
        "High severity → SARIF level 'error'"
    );
    assert_eq!(first["ruleId"], "e2e/sql-injection");
    assert!(first["locations"][0]["physicalLocation"]["region"]["startLine"].is_number());
}

#[test]
fn workspace_export_findings_writes_markdown_bundle_directory() {
    let workspace_dir = tempfile::tempdir().expect("tempdir");
    seed_workspace_with_one_finding(workspace_dir.path());

    let output_dir = workspace_dir.path().join("bundle");
    let output = run_kuzushi(&[
        "export",
        "--target",
        workspace_dir.path().to_str().unwrap(),
        "--format",
        "markdown-bundle",
        "--out",
        output_dir.to_str().unwrap(),
    ]);

    assert!(
        output.status.success(),
        "markdown-bundle export must succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output_dir.is_dir(), "bundle output should be a directory");
    assert!(output_dir.join("README.md").is_file());
    assert!(output_dir.join("manifest.json").is_file());
    assert!(
        std::fs::read_dir(output_dir.join("findings"))
            .expect("bundle directory readable")
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().starts_with("F-")),
        "bundle should contain per-finding markdown files"
    );
}

#[test]
fn findings_command_lists_persisted_finding_as_json() {
    // Companion E2E: the `findings` command must require an explicit
    // target (M1 §1.3) and surface the persisted entry. JSON output is
    // exercised so downstream tools can parse the result.
    let workspace_dir = tempfile::tempdir().expect("tempdir");
    seed_workspace_with_one_finding(workspace_dir.path());

    let output = run_kuzushi(&[
        "findings",
        "--target",
        workspace_dir.path().to_str().unwrap(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "findings command must succeed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let document: serde_json::Value =
        serde_json::from_str(&stdout).expect("findings --json produces valid JSON");
    let entries = document["findings"]
        .as_array()
        .expect("findings array present");
    assert!(!entries.is_empty(), "findings array should not be empty");
    assert_eq!(entries[0]["rule_id"], "e2e/sql-injection");
}

#[test]
fn findings_command_without_target_surfaces_actionable_error() {
    // M1 §1.3: dispatch refuses missing targets with an actionable
    // hint. This locks in the contract so future refactors can't
    // silently re-introduce the cwd fallback that bug-bounty work
    // needs to avoid.
    let output = Command::new(kuzushi_binary())
        .arg("findings")
        .env("KUZUSHI_DISABLE_OPERATOR_PERSISTENCE", "1")
        .output()
        .expect("kuzushi runs");
    assert!(
        !output.status.success(),
        "missing target must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // `findings` now shares the single canonical missing-target message with
    // `scan`, `export`, `runs`, etc. (support::require_cli_target).
    assert!(
        stderr.contains("findings needs a target")
            && stderr.contains("Bug-bounty workflows require explicit scope"),
        "expected actionable error, got: {stderr}"
    );
}
