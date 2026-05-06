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
#[cfg(unix)]
fn auth_ping_succeeds_when_bridge_returns_ok() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(home.join(".kuzushi/v2")).unwrap();
    let body = r#"
model = "anthropic:claude-haiku-4-5"

[runtime]
api_key_env = "ANTHROPIC_API_KEY"
agent_bridge_command = ["sh", "-c", "cat > /dev/null && printf '%s' '{\"ok\":true,\"auth_mode\":\"oauth-file\",\"model\":\"claude-haiku-4-5\",\"latency_ms\":42,\"input_tokens\":1,\"output_tokens\":8,\"cost_usd\":0.0001}'"]
"#;
    fs::write(home.join(".kuzushi/v2/config.toml"), body).unwrap();

    let kuzushi = env!("CARGO_BIN_EXE_kuzushi");
    let output = Command::new(kuzushi)
        .env("HOME", &home)
        .args(["auth", "ping", "anthropic"])
        .output()
        .expect("kuzushi auth ping");
    assert!(
        output.status.success(),
        "auth ping should succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("auth ping: OK"),
        "missing OK line: {stderr}"
    );
    assert!(
        stderr.contains("round-trip ok"),
        "missing round-trip line: {stderr}"
    );
}

#[test]
#[cfg(unix)]
fn auth_ping_fails_loudly_on_bridge_error_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(home.join(".kuzushi/v2")).unwrap();
    let body = r#"
model = "anthropic:claude-haiku-4-5"

[runtime]
api_key_env = "ANTHROPIC_API_KEY"
agent_bridge_command = ["sh", "-c", "cat > /dev/null && printf '%s' '{\"ok\":false,\"error\":\"401 unauthorized\"}'; exit 1"]
"#;
    fs::write(home.join(".kuzushi/v2/config.toml"), body).unwrap();
    let kuzushi = env!("CARGO_BIN_EXE_kuzushi");
    let output = Command::new(kuzushi)
        .env("HOME", &home)
        .args(["auth", "ping", "anthropic"])
        .output()
        .expect("kuzushi auth ping");
    assert!(!output.status.success(), "auth ping should fail on 401");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("401 unauthorized"),
        "expected error in stderr: {stderr}"
    );
}

#[test]
#[cfg(unix)]
fn smoke_next_step_drives_tool_loop_through_real_dispatcher() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let target = tmp.path().join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("placeholder.c"), "void p(){}\n").unwrap();
    fs::create_dir_all(home.join(".kuzushi/v2")).unwrap();

    // The bridge sees two next-step envelopes:
    //   1. Returns a tool_call asking echo({x: "kuzushi-ok"}).
    //   2. Returns a final containing the phrase.
    let counter = tmp.path().join("counter");
    fs::write(&counter, "0").unwrap();
    let bridge_script = format!(
        r#"#!/usr/bin/env node
import {{ readFileSync, writeFileSync }} from "node:fs";
import process from "node:process";
const counter = "{counter}";
const n = Number(readFileSync(counter, "utf8"));
writeFileSync(counter, String(n + 1));
process.stdin.resume();
process.stdin.on("data", () => {{}});
process.stdin.on("end", () => {{
  if (n === 0) {{
    process.stdout.write(JSON.stringify({{
      ok: true, step: "tool_call",
      call: {{ name: "echo", input: {{ x: "kuzushi-ok" }}, callId: "c1" }},
      cost_usd: 0.001
    }}));
  }} else {{
    process.stdout.write(JSON.stringify({{
      ok: true, step: "final",
      text: "Echoed: kuzushi-ok",
      cost_usd: 0.001
    }}));
  }}
  process.exit(0);
}});
"#,
        counter = counter.display()
    );
    let bridge = tmp.path().join("bridge.mjs");
    fs::write(&bridge, bridge_script).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&bridge, fs::Permissions::from_mode(0o755)).unwrap();
    let cfg = format!(
        r#"
model = "anthropic:claude-haiku-4-5"

[runtime]
api_key_env = "ANTHROPIC_API_KEY"
agent_bridge_command = ["node", "{bridge}"]
"#,
        bridge = bridge.display()
    );
    fs::write(home.join(".kuzushi/v2/config.toml"), cfg).unwrap();

    let kuzushi = env!("CARGO_BIN_EXE_kuzushi");
    let output = Command::new(kuzushi)
        .env("HOME", &home)
        .args([
            "--target",
            target.to_str().unwrap(),
            "run",
            "smoke:next-step",
            "--input",
            r#"{"phrase":"kuzushi-ok"}"#,
        ])
        .output()
        .expect("kuzushi run smoke:next-step");
    assert!(
        output.status.success(),
        "smoke:next-step failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["ok"], serde_json::json!(true));
    assert_eq!(parsed["data"]["echoedPhrase"], serde_json::json!(true));
    assert_eq!(parsed["data"]["stepsUsed"], serde_json::json!(2));
    assert!(parsed["data"]["finalText"]
        .as_str()
        .unwrap()
        .contains("kuzushi-ok"));
}

#[test]
fn full_mode_dry_run_returns_plan_without_calling_model() {
    // Synthetic mini-target with a few C files. Dry-run produces a chunk
    // plan + cost band without any LLM call.
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/a.c"), "void a(){}\n").unwrap();
    fs::write(tmp.path().join("src/b.c"), "void b(){}\n").unwrap();

    let kuzushi = env!("CARGO_BIN_EXE_kuzushi");
    let input = format!(r#"{{"target":"{}","dryRun":true}}"#, tmp.path().display());
    let output = Command::new(kuzushi)
        .args([
            "--target",
            tmp.path().to_str().unwrap(),
            "run",
            "full-mode:hunt",
            "--input",
            &input,
        ])
        .output()
        .expect("kuzushi run full-mode:hunt");
    assert!(
        output.status.success(),
        "full-mode:hunt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["ok"], serde_json::json!(true));
    assert_eq!(parsed["summary"]["dryRun"], serde_json::json!(true));
    assert!(parsed["summary"]["files"].as_u64().unwrap() >= 2);
    assert!(parsed["summary"]["totalTokens"].as_u64().unwrap() > 0);
    let _ = tmp;
}

/// Build a fake bridge shell-script that returns canned single-shot
/// (legacy `query` envelope) responses. Used by the classifier-gate and
/// deep-auditor smoke tests to drive the bridge without LLM credits.
#[cfg(unix)]
fn fake_bridge_query(dir: &Path, payloads: &[&str]) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let counter = dir.join("bridge.counter");
    fs::write(&counter, "0").unwrap();
    let payloads_json = serde_json::to_string(payloads).unwrap();
    let array_path = dir.join("bridge.payloads.json");
    fs::write(&array_path, payloads_json).unwrap();
    let script = format!(
        r#"#!/usr/bin/env node
import {{ readFileSync, writeFileSync }} from "node:fs";
import process from "node:process";
const counter = "{counter}";
const payloads = JSON.parse(readFileSync("{array_path}", "utf8"));
const n = Number(readFileSync(counter, "utf8"));
writeFileSync(counter, String(n + 1));
process.stdin.resume(); // drain stdin
process.stdin.on("data", () => {{}});
process.stdin.on("end", () => {{
  process.stdout.write(payloads[Math.min(n, payloads.length - 1)]);
  process.exit(0);
}});
"#,
        counter = counter.display(),
        array_path = array_path.display(),
    );
    let bridge = dir.join("fake-bridge.mjs");
    fs::write(&bridge, script).unwrap();
    fs::set_permissions(&bridge, fs::Permissions::from_mode(0o755)).unwrap();
    bridge
}

#[cfg(unix)]
fn build_runtime_config_with_fake_bridge(home: &Path, bridge: &Path) {
    let v2 = home.join(".kuzushi/v2");
    fs::create_dir_all(&v2).unwrap();
    let body = format!(
        r#"
model = "anthropic:claude-sonnet-4-6"

[runtime]
api_key_env = "ANTHROPIC_API_KEY"
agent_bridge_command = ["node", "{bridge}"]
"#,
        bridge = bridge.display()
    );
    fs::write(v2.join("config.toml"), body).unwrap();
}

#[test]
#[cfg(unix)]
fn classifier_gate_score_persists_skip_outcome_when_below_threshold() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    let home = tmp.path().join("home");
    fs::create_dir_all(target.join("src")).unwrap();
    fs::write(target.join("src/foo.c"), "void foo(){}\n").unwrap();
    let workspace = WorkspaceTarget::new(&target).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("seed", workspace.root(), "running")
        .unwrap();
    let finding = Finding::new_tool(
        "semgrep",
        "rule",
        "src/foo.c",
        1,
        Some(1),
        Severity::Medium,
        "boring candidate",
    );
    let fp = finding.fingerprint.clone();
    store.insert_finding("seed", &finding).unwrap();
    store.complete_scan_run("seed", "completed", 1).unwrap();

    let bridge = fake_bridge_query(
        tmp.path(),
        &[r#"{"ok":true,"text":"{\"likely\":false,\"score\":0.15,\"reason\":\"boring\"}"}"#],
    );
    build_runtime_config_with_fake_bridge(&home, &bridge);

    let kuzushi = env!("CARGO_BIN_EXE_kuzushi");
    let input = format!(r#"{{"findingFingerprint":"{fp}"}}"#);
    let output = Command::new(kuzushi)
        .env("HOME", &home)
        .args([
            "--target",
            target.to_str().unwrap(),
            "run",
            "classifier-gate:score",
            "--input",
            &input,
        ])
        .output()
        .expect("kuzushi run classifier-gate:score");
    assert!(
        output.status.success(),
        "classifier-gate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["ok"], serde_json::json!(true));
    let score = parsed["data"]["score"].as_f64().unwrap();
    assert!(score < 0.5, "expected low score, got {score}");
    assert_eq!(
        parsed["data"]["shouldDeepAudit"],
        serde_json::json!(false),
        "low score should NOT graduate"
    );

    // The skip outcome should have been persisted.
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = store.get_finding_by_reference(&fp).unwrap().unwrap();
    let triage = finding.triage.expect("classifier wrote a triage row");
    assert!(
        triage.rationale.contains("threshold"),
        "skip outcome rationale missing threshold: {}",
        triage.rationale
    );
    let _ = tmp;
}

#[test]
#[cfg(unix)]
fn deep_audit_run_persists_triage_outcome_with_evidence() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    let home = tmp.path().join("home");
    fs::create_dir_all(target.join("src")).unwrap();
    fs::write(
        target.join("src/foo.c"),
        "void foo(char *p, int n){ char b[64]; memcpy(b,p,n); }\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(&target).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("seed", workspace.root(), "running")
        .unwrap();
    let finding = Finding::new_tool(
        "semgrep",
        "rule",
        "src/foo.c",
        1,
        Some(1),
        Severity::High,
        "OOB write CWE-787 in foo",
    );
    let fp = finding.fingerprint.clone();
    store.insert_finding("seed", &finding).unwrap();
    store.complete_scan_run("seed", "completed", 1).unwrap();

    // The bridge sees one `next-step` envelope and returns a structured
    // final verdict immediately (zero tool calls).
    let bridge = fake_bridge_query(
        tmp.path(),
        &[
            r#"{"ok":true,"step":"final","text":"","structured":{"triggerable":false,"rationale":"length is checked upstream","confidence":0.9,"evidence":[{"file":"src/foo.c","start_line":1,"end_line":1,"note":"trivially safe","kind":"context"}]},"costUsd":0.001}"#,
        ],
    );
    build_runtime_config_with_fake_bridge(&home, &bridge);

    let kuzushi = env!("CARGO_BIN_EXE_kuzushi");
    let input = format!(r#"{{"findingFingerprint":"{fp}"}}"#);
    let output = Command::new(kuzushi)
        .env("HOME", &home)
        .args([
            "--target",
            target.to_str().unwrap(),
            "run",
            "deep-audit:run",
            "--input",
            &input,
        ])
        .output()
        .expect("kuzushi run deep-audit:run");
    assert!(
        output.status.success(),
        "deep-audit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["ok"], serde_json::json!(true));
    assert_eq!(
        parsed["data"]["verdict"],
        serde_json::json!("false_positive")
    );
    assert!(parsed["data"]["evidence"].as_array().unwrap().len() >= 1);

    // Triage row + evidence row should both be persisted.
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = store.get_finding_by_reference(&fp).unwrap().unwrap();
    let triage = finding.triage.expect("deep-audit wrote a triage row");
    assert!(triage.confidence >= 0.5);
    let _ = tmp;
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
