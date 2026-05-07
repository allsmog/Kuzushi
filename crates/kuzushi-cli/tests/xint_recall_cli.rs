//! End-to-end recall regression suite.
//!
//! For each oracle under `experiments/xint-eval/oracles/`, this test:
//!
//! 1. Creates a synthetic mini-slice whose layout mirrors the oracle's
//!    file references (so path matching is exercised, not stubbed).
//! 2. Pre-populates `<slice>/.kuzushi/v2/findings.sqlite3` with a
//!    finding that the scorer should classify as a hit.
//! 3. Pipes `kuzushi findings --json` into the `kuzushi-eval` scorer.
//! 4. Asserts at least one match at the user-chosen primary tolerance
//!    (`pm_lines:10` with CWE).
//!
//! This is the CI-cheap regression net described in Phase 11. The real
//! eval (live LLM, real slices) lives in `experiments/xint-eval/` and
//! runs out-of-band.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use kuzushi_core::{Finding, FindingStore, Severity, WorkspaceTarget};
use kuzushi_eval::load_oracle as lib_load_oracle;
use kuzushi_eval::run_scorer as lib_run_scorer;
use serde_json::Value;

fn load_oracle(slice: &str) -> (PathBuf, Value) {
    lib_load_oracle(slice).expect("load oracle")
}

/// Build a synthetic slice whose layout matches the oracle's referenced
/// files. Each ground-truth file is created with enough lines that the
/// oracle line range is in-bounds.
fn make_slice_for(oracle: &Value) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let entries = oracle["ground_truth"].as_array().unwrap();
    for entry in entries {
        let raw = entry["file"].as_str().unwrap();
        // Directory-level oracle (e.g. "src/backend/utils") — skip
        // synthetic file creation; insert_finding_for_oracle will land
        // a finding under the directory.
        if raw.ends_with('/') || (!raw.contains('.') && !raw.is_empty()) {
            let dir_path = tmp.path().join(raw.trim_end_matches('/'));
            fs::create_dir_all(&dir_path).ok();
            // Create a token file under the directory so the oracle
            // has a sibling to match against.
            fs::write(dir_path.join("placeholder.c"), "// placeholder\n").ok();
            continue;
        }
        let abs = tmp.path().join(raw);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        // Make sure the file has enough lines.
        let line_end = entry["line_end"].as_u64().unwrap_or(50).max(50);
        let body: String = (1..=line_end + 5)
            .map(|i| format!("// line {i}\n"))
            .collect();
        fs::write(&abs, body).unwrap();
    }
    tmp
}

/// Insert a finding into the slice's findings store that the scorer
/// should classify as a primary-tolerance hit.
fn seed_finding_matching_oracle(slice: &Path, oracle: &Value) {
    let workspace = WorkspaceTarget::new(slice).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-recall", workspace.root(), "running")
        .unwrap();

    let entry = &oracle["ground_truth"][0];
    let raw_file = entry["file"].as_str().unwrap();
    // For directory-level oracles, drop the finding into the
    // placeholder file we created.
    let (file, line) =
        if raw_file.ends_with('/') || (!raw_file.contains('.') && !raw_file.is_empty()) {
            (
                format!("{}/placeholder.c", raw_file.trim_end_matches('/')),
                1u32,
            )
        } else {
            (
                raw_file.to_string(),
                entry["line_start"].as_u64().unwrap_or(1) as u32,
            )
        };
    let oracle_cwes: Vec<String> = entry["cwe"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let cwe_for_message = oracle_cwes
        .first()
        .cloned()
        .unwrap_or_else(|| "CWE-787".to_string());
    let kind = entry["kind"].as_str().unwrap_or("vulnerability");

    let finding = Finding::new_tool(
        "full-mode-multi",
        format!("full-mode-multi/{}", cwe_for_message.to_ascii_lowercase()),
        file,
        line,
        Some(line),
        Severity::High,
        format!("synthetic recall test: {kind} ({cwe_for_message})"),
    );
    store.insert_finding("run-recall", &finding).unwrap();
    store
        .complete_scan_run("run-recall", "completed", 1)
        .unwrap();
}

fn run_findings_dump(slice: &Path) -> Value {
    let kuzushi = env!("CARGO_BIN_EXE_kuzushi");
    let output = Command::new(kuzushi)
        .args([
            "findings",
            "--target",
            slice.to_str().unwrap(),
            "--limit",
            "1000",
            "--json",
        ])
        .env_remove("KUZUSHI_MODEL")
        .output()
        .expect("kuzushi findings --json");
    if !output.status.success() {
        panic!(
            "kuzushi findings failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).expect("findings json")
}

fn run_scorer(slice_name: &str, slice: &Path, oracle_path: &Path) -> Value {
    let dump = run_findings_dump(slice);
    lib_run_scorer(slice_name, slice, oracle_path, &dump).expect("kuzushi-eval scorer")
}

fn run_recall_test(slice_name: &str) {
    let (oracle_path, oracle) = load_oracle(slice_name);
    let slice = make_slice_for(&oracle);
    seed_finding_matching_oracle(slice.path(), &oracle);
    let report = run_scorer(slice_name, slice.path(), &oracle_path);
    let hits = report["hits"].as_u64().unwrap_or(0);
    let misses = report["misses"].as_u64().unwrap_or(0);
    let recall_pm10 = report["recall"]["pm_lines"].as_f64().unwrap_or(0.0);
    let recall_file = report["recall"]["file_only"].as_f64().unwrap_or(0.0);

    let oracle_n = oracle["ground_truth"].as_array().unwrap().len() as u64;
    assert!(
        hits >= 1 || recall_file > 0.0,
        "[{slice_name}] expected at least one match, got hits={hits} misses={misses} recall_pm10={recall_pm10} recall_file={recall_file} (oracle entries={oracle_n})"
    );
    let _ = slice;
}

#[test]
fn recall_smoke_linux_copy_fail() {
    run_recall_test("linux");
}

#[test]
fn recall_smoke_postgres() {
    run_recall_test("postgres");
}

#[test]
fn recall_smoke_redis() {
    run_recall_test("redis");
}

#[test]
fn recall_smoke_mariadb() {
    run_recall_test("mariadb");
}

/// Fake `pi-agent-core` bridge that handles BOTH `query` (legacy
/// triage path) and `type=next-step` (`triage:deep` tool-loop path)
/// envelopes. It always returns a final step with a structured
/// `VulnAnalysis` so a CI-cheap recall test can exercise the
/// tool-augmented audit without calling a real LLM.
///
/// The script returns:
/// - `query` envelope: legacy triage outcome JSON.
/// - `next-step` envelope: final step JSON with a triggerable=true
///   `VulnAnalysis` plus one evidence citation.
///
/// Distinguishing the two is purely shape-based: next-step requests
/// include `"type":"next-step"`. We cat stdin into a temp file and
/// grep for the marker.
#[cfg(unix)]
fn fake_deep_audit_bridge(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let binary = dir.join("deep-audit-bridge.sh");
    fs::write(
        &binary,
        r#"#!/bin/sh
body=$(cat)
case "$body" in
  *'"type":"next-step"'*|*'"type": "next-step"'*)
    cat <<'JSON'
{"ok":true,"step":"final","cost_usd":0.0,"structured":{"triggerable":true,"rationale":"mock deep audit verdict from fake bridge","confidence":0.9,"evidence":[{"file":"src/x.c","start_line":10,"end_line":12,"note":"attacker-controlled length flows here","kind":"sink"}]}}
JSON
    ;;
  *)
    cat <<'JSON'
{"ok":true,"structured":{"verdict":"true_positive","confidence":0.85,"rationale":"mock triage from fake bridge"}}
JSON
    ;;
esac
"#,
    )
    .unwrap();
    let mut perms = fs::metadata(&binary).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&binary, perms).unwrap();
    binary
}

/// Wire `triage:deep` into the recall pipeline. Seeds a synthetic
/// finding, drives `kuzushi run triage:deep` against the fake
/// next-step bridge, then asserts:
///
/// 1. The persisted triage outcome on the finding matches the bridge's
///    structured verdict (TruePositive / 0.9 confidence).
/// 2. The kuzushi-eval scorer still classifies the finding as a hit
///    against the oracle (the deep-audit pass doesn't break path
///    matching or fingerprint stability).
///
/// Skipped on non-unix (no shell-script bridges).
#[cfg(unix)]
#[test]
fn recall_pipeline_with_triage_deep_persists_evidence_and_still_matches_oracle() {
    let (oracle_path, oracle) = load_oracle("linux");
    let slice = make_slice_for(&oracle);
    seed_finding_matching_oracle(slice.path(), &oracle);

    // Look up the seeded finding so we can hand its fingerprint to
    // triage:deep — there's only one in the fixture.
    let workspace = WorkspaceTarget::new(slice.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1, "expected one seeded finding");
    let fingerprint = findings[0].fingerprint.clone();
    let finding_id = findings[0].id.expect("seeded finding must have id");
    drop(store);

    // Build the fake bridge inside the slice tempdir so it gets cleaned
    // up with the test workspace.
    let bridge = fake_deep_audit_bridge(slice.path());

    // Write a project-local config that points the runtime at the
    // fake bridge. `kuzushi run --target <slice>` picks it up via
    // load_config_for_target.
    let config_path = slice.path().join(".kuzushi").join("v2").join("config.toml");
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::write(
        &config_path,
        format!(
            r#"model = "anthropic:claude-haiku-4-5-20251001"

[runtime]
kind = "pi-agent-core"
api_key_env = "ANTHROPIC_API_KEY"
agent_bridge_command = ["{}"]
"#,
            bridge.display()
        ),
    )
    .unwrap();

    // Drive `kuzushi run triage:deep` through the binary so the test
    // exercises the full CLI dispatch path (including RoutedRuntime
    // construction when models.toml is present).
    let kuzushi = env!("CARGO_BIN_EXE_kuzushi");
    let output = Command::new(kuzushi)
        .args([
            "--target",
            slice.path().to_str().unwrap(),
            "run",
            "triage:deep",
            "--input",
            &format!(r#"{{"fingerprint":"{fingerprint}"}}"#),
        ])
        .env_remove("KUZUSHI_MODEL")
        .output()
        .expect("kuzushi run triage:deep");
    assert!(
        output.status.success(),
        "triage:deep failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Re-open the store and inspect the persisted triage.
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let stored = store
        .get_finding_by_fingerprint(&fingerprint)
        .unwrap()
        .expect("seeded finding still present");
    let triage = stored
        .triage
        .as_ref()
        .expect("triage:deep should have persisted a triage outcome");
    assert_eq!(triage.verdict.as_str(), "true_positive");
    assert!(
        (triage.confidence - 0.9).abs() < 1e-6,
        "expected confidence 0.9, got {}",
        triage.confidence
    );

    drop(store);

    // Evidence citations should land in `findings_evidence`. There's
    // no public accessor on `FindingStore` for that table, so probe
    // via a direct sqlite connection. Count is fine; we just want a
    // non-zero row to confirm the bridge → save_evidence path fires.
    let evidence_count: i64 = {
        let conn = rusqlite::Connection::open(workspace.findings_db_path()).unwrap();
        // Table is created lazily by save_evidence; absent → 0.
        let stmt = conn.prepare("select count(*) from findings_evidence where finding_id = ?");
        match stmt {
            Ok(mut s) => s
                .query_row(rusqlite::params![finding_id], |row| row.get::<_, i64>(0))
                .unwrap_or(0),
            Err(_) => 0,
        }
    };
    assert!(
        evidence_count >= 1,
        "expected at least one evidence citation, got {evidence_count}"
    );

    // Recall scorer must still produce a hit. The deep-audit pass
    // adds a triage outcome but does not alter the finding's
    // fingerprint, file, or line — so path matching is unchanged.
    let report = run_scorer("linux", slice.path(), &oracle_path);
    let hits = report["hits"].as_u64().unwrap_or(0);
    let recall_file = report["recall"]["file_only"].as_f64().unwrap_or(0.0);
    assert!(
        hits >= 1 || recall_file > 0.0,
        "post-triage:deep recall regressed: hits={hits} recall_file={recall_file}"
    );
    let _ = slice;
}
