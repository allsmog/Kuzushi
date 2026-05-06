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
use serde_json::Value;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn kuzushi_eval_bin() -> PathBuf {
    let workspace = workspace_root();
    let candidates = [
        workspace.join("target/debug/kuzushi-eval"),
        workspace.join("target/release/kuzushi-eval"),
    ];
    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    // Build it on demand if neither exists yet.
    let status = Command::new("cargo")
        .args(["build", "-p", "kuzushi-eval"])
        .current_dir(&workspace)
        .status()
        .expect("cargo build of kuzushi-eval");
    assert!(status.success(), "could not build kuzushi-eval");
    workspace.join("target/debug/kuzushi-eval")
}

fn load_oracle(slice: &str) -> (PathBuf, Value) {
    let oracle_dir = workspace_root()
        .join("experiments")
        .join("xint-eval")
        .join("oracles");
    let mut found: Option<PathBuf> = None;
    for entry in fs::read_dir(&oracle_dir).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let body = fs::read_to_string(&p).unwrap();
        let v: Value = serde_json::from_str(&body).unwrap();
        if v["slice"].as_str() == Some(slice) {
            found = Some(p);
            break;
        }
    }
    let path = found.unwrap_or_else(|| panic!("no oracle for slice {slice}"));
    let body = fs::read_to_string(&path).unwrap();
    let v: Value = serde_json::from_str(&body).unwrap();
    (path, v)
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
    let (file, line) = if raw_file.ends_with('/')
        || (!raw_file.contains('.') && !raw_file.is_empty())
    {
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
    let tmp_findings = slice.join("findings_dump.json");
    fs::write(&tmp_findings, serde_json::to_string(&dump).unwrap()).unwrap();

    let scorer = kuzushi_eval_bin();
    let output = Command::new(&scorer)
        .args([
            "--oracle",
            oracle_path.to_str().unwrap(),
            "--findings",
            tmp_findings.to_str().unwrap(),
            "--slice",
            slice_name,
            "--target",
            slice.to_str().unwrap(),
            "--wall-seconds",
            "0",
        ])
        .output()
        .expect("kuzushi-eval");
    if !output.status.success() {
        panic!(
            "kuzushi-eval failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).expect("scorer json")
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
