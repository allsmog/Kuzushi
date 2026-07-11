use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kuzushi_core::findings::ReviewDecisionVerdict;
use kuzushi_core::{
    Finding, FindingStore, PatchResult, PatchStatus, PersistedProofVerdict,
    PersistedSandboxBackend, PersistedVerification, Severity, StaticProofState, TriageOutcome,
    TriageVerdict,
};
use serde_json::Value;

fn kuzushi() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kuzushi"))
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate should live under crates/kuzushi-cli")
}

fn stdout(output: std::process::Output) -> String {
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout should be UTF-8")
}

fn native_alias(name: &str) -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let alias_path = temp.path().join(name);
    fs::copy(env!("CARGO_BIN_EXE_kuzushi"), &alias_path).unwrap();
    let permissions = fs::metadata(env!("CARGO_BIN_EXE_kuzushi"))
        .unwrap()
        .permissions();
    fs::set_permissions(&alias_path, permissions).unwrap();
    (temp, alias_path)
}

fn latest_run_dir(root: &Path) -> PathBuf {
    kuzushi_core::run_artifacts::run_dir(root, &latest_run_id(root))
}

fn latest_run_id(root: &Path) -> String {
    fs::read_to_string(kuzushi_core::run_artifacts::latest_run_path(root))
        .unwrap()
        .trim()
        .to_string()
}

fn latest_run_artifact(root: &Path, leaf: &str) -> PathBuf {
    kuzushi_core::run_artifacts::run_artifact_path(root, &latest_run_id(root), leaf)
}

fn assert_failed_run_bundle(root: &Path, kind: &str, tool: &str) -> (PathBuf, Value) {
    let run_dir = latest_run_dir(root);
    let run_json = fs::read_to_string(latest_run_artifact(root, "run.json")).unwrap();
    let failures = fs::read_to_string(latest_run_artifact(root, "failures.json")).unwrap();
    let failure_json: Value = serde_json::from_str(&failures).unwrap();

    assert_canonical_run_files(&run_dir);
    assert!(run_json.contains("\"status\": \"failed\""));
    assert!(run_json.contains(&format!("\"kind\": \"{kind}\"")));
    assert!(run_json.contains(&format!("\"tool\": \"{tool}\"")));
    assert_eq!(failure_json["status"], "failed");
    assert_eq!(failure_json["failures"][0]["tool"], tool);
    (run_dir, failure_json)
}

fn assert_canonical_run_files(run_dir: &Path) {
    for leaf in [
        "run.json",
        "events.jsonl",
        "trace.jsonl",
        "failures.json",
        "report.md",
        "artifacts.json",
    ] {
        assert!(
            run_dir.join(leaf).exists(),
            "latest run missing canonical artifact {leaf}"
        );
    }
}

fn assert_strict_plain(label: &str, output: &str) {
    assert!(
        !output.contains("\x1b["),
        "{label} must not contain ANSI escapes:\n{output}"
    );
    for forbidden in ["┌", "┐", "└", "┘", "─", "│", "╭", "╮", "╰", "╯"] {
        assert!(
            !output.contains(forbidden),
            "{label} must not contain box drawing {forbidden:?}:\n{output}"
        );
    }
    for line in output.lines() {
        assert!(
            line.chars().count() <= 80,
            "{label} must keep lines <= 80 columns; over-wide line:\n{line}"
        );
    }
}

fn plain_shell_script(script: &str) -> String {
    stdout(plain_shell_script_output(script))
}

fn plain_shell_script_output(script: &str) -> std::process::Output {
    let tmp = tempfile::tempdir().unwrap();
    let mut child = kuzushi()
        .env("KUZUSHI_SKIP_ONBOARDING", "1")
        .env("KUZUSHI_AUTO_OPEN_ACTIVITY", "false")
        .args(["--plain", "shell", "--target"])
        .arg(tmp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn rust_cli_help_is_the_documented_primary_surface() {
    let out = stdout(kuzushi().arg("--help").output().unwrap());

    assert!(out.contains("Kuzushi security-native code agent"));
    assert!(out.contains("Usage: kuzushi"));
    assert!(out.contains("--plain"));
    for command in [
        "shell",
        "scan",
        "findings",
        "finding",
        "runs",
        "export",
        "suppress",
        "suppressions",
        "permissions",
        "config",
        "modules",
        "tools",
        "doctor",
        "run",
        "kwp",
    ] {
        assert!(out.contains(command), "missing command {command} in help");
    }
    for removed in ["TypeScript", "Ink", "quickstart", "preset", "sarif"] {
        assert!(
            !out.to_ascii_lowercase()
                .contains(&removed.to_ascii_lowercase()),
            "help should not advertise removed/non-Rust surface {removed:?}:\n{out}"
        );
    }
}

#[test]
fn rust_cli_compact_alias_is_a_native_binary() {
    let (_temp, alias_path) = native_alias("kz");
    let out = stdout(Command::new(alias_path).arg("--help").output().unwrap());

    assert!(out.contains("Kuzushi security-native code agent"));
    assert!(out.contains("Usage: kz"));
    assert!(out.contains("run"));
    assert!(out.contains("shell"));
}

#[test]
fn kwp_help_exposes_the_approval_lifecycle() {
    let output = stdout(kuzushi().args(["kwp", "--help"]).output().unwrap());

    for command in ["approve", "revoke", "inspect", "audit"] {
        assert!(output.contains(command), "missing KWP command {command}");
    }
}

#[test]
fn kwp_audit_json_includes_run_audit_records() {
    let tmp = tempfile::tempdir().unwrap();
    let run_id = "run-kwp-audit";
    let target = kuzushi_core::WorkspaceTarget::new(tmp.path()).unwrap();
    let audit_path =
        kuzushi_core::run_artifacts::run_artifact_path(target.root(), run_id, "kwp-audit.jsonl");
    let anchor_path = kuzushi_core::run_artifacts::run_artifact_path(
        target.root(),
        run_id,
        "kwp-audit.anchor.json",
    );
    let bus_path =
        kuzushi_core::run_artifacts::run_artifact_path(target.root(), run_id, "kwp-bus.jsonl");
    fs::create_dir_all(audit_path.parent().unwrap()).unwrap();
    let audit_body = r#"{"tsMs":1,"runId":"run-kwp-audit","invocationId":"inv-1","moduleId":"dyn","digest":"sha256:abc","event":"fs.write","decision":"allow","detail":null,"prev":null}"#;
    let audit_hash = kuzushi_core::worker_protocol::sha256_digest(audit_body.as_bytes()).0;
    fs::write(
        &audit_path,
        format!(
            "{{\"tsMs\":1,\"runId\":\"run-kwp-audit\",\"invocationId\":\"inv-1\",\"moduleId\":\"dyn\",\"digest\":\"sha256:abc\",\"event\":\"fs.write\",\"decision\":\"allow\",\"detail\":null,\"hash\":\"{audit_hash}\"}}\n"
        ),
    )
    .unwrap();
    fs::write(
        &anchor_path,
        format!("{{\"recordCount\":1,\"lastHash\":\"{audit_hash}\"}}"),
    )
    .unwrap();
    fs::write(
        &bus_path,
        r#"{"tsMs":2,"runId":"run-kwp-audit","invocationId":"inv-1","moduleId":"dyn","digest":"sha256:abc","topic":"topic.allowed","payload":{"ok":true}}
"#,
    )
    .unwrap();

    let output = stdout(
        kuzushi()
            .args(["kwp", "audit", "--lockfile"])
            .arg(tmp.path().join("kuzushi.lock"))
            .args(["--target"])
            .arg(tmp.path())
            .args(["--run-id", run_id, "--json"])
            .output()
            .unwrap(),
    );
    let body: Value = serde_json::from_str(&output).unwrap();

    assert_eq!(body["runAudit"]["recordCount"], 1);
    assert_eq!(body["runAudit"]["records"][0]["event"], "fs.write");
    assert_eq!(body["runAudit"]["integrity"]["ok"], true);
    assert_eq!(body["runAudit"]["path"], audit_path.display().to_string());
    assert_eq!(body["runAudit"]["bus"]["recordCount"], 1);
    assert_eq!(
        body["runAudit"]["bus"]["records"][0]["topic"],
        "topic.allowed"
    );
    assert_eq!(body["runAudit"]["bus"]["records"][0]["payload"]["ok"], true);
}

#[test]
fn kwp_audit_requires_target_and_run_id_together() {
    let output = kuzushi()
        .args(["kwp", "audit", "--run-id", "run-1"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--run-id requires --target"));
}

#[test]
fn auth_ping_rejects_legacy_codex_provider_selector() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();

    let output = kuzushi()
        .env("HOME", &home)
        .args(["auth", "ping"])
        .arg(format!("openai-{}", "codex"))
        .args(["--model", "openai:gpt-5.5"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "legacy selector should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported auth ping provider"),
        "{stderr}"
    );
    assert!(stderr.contains("Supported: openai, anthropic"), "{stderr}");
}

#[test]
fn cli_run_dot_is_rejected_as_shell_only_shorthand() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let output = kuzushi()
        .current_dir(tmp.path())
        .env("HOME", &home)
        .args(["run", "."])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "terminal `kuzushi run .` must not silently dispatch"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("`kuzushi run .` is shell-only"), "{stderr}");
    assert!(stderr.contains("use <module>"), "{stderr}");
    assert!(stderr.contains("context:build"), "{stderr}");
    let _ = assert_failed_run_bundle(tmp.path(), "run", ".");
    let run_json = fs::read_to_string(latest_run_artifact(tmp.path(), "run.json")).unwrap();
    let failures = fs::read_to_string(latest_run_artifact(tmp.path(), "failures.json")).unwrap();

    assert!(run_json.contains("\"tool\": \".\""));
    assert!(failures.contains("`kuzushi run .` is shell-only"));
}

#[test]
fn cli_run_missing_explicit_target_does_not_write_artifacts_under_cwd() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();

    let output = kuzushi()
        .current_dir(tmp.path())
        .env("HOME", &home)
        .args(["--target", "missing-target"])
        .args(["run", "context:build", "--input", "{}"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "missing run target should fail");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Target path does not exist"));
    assert!(
        !tmp.path().join(".kuzushi").exists(),
        "an unresolved explicit target must not redirect artifacts into cwd"
    );
}

#[test]
fn cli_run_workspace_status_reports_recorded_artifacts() {
    let tmp = tempfile::tempdir().unwrap();
    let out = stdout(
        kuzushi()
            .args(["--target"])
            .arg(tmp.path())
            .args(["run", "workspace:status"])
            .output()
            .unwrap(),
    );
    let parsed: Value = serde_json::from_str(&out).unwrap();
    let artifacts = parsed["artifacts"].as_array().unwrap();

    assert!(artifacts.iter().any(|artifact| {
        artifact["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("run.json"))
    }));
    assert!(artifacts.iter().any(|artifact| {
        artifact["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("result.json"))
    }));
    assert!(tmp.path().join(".kuzushi/v3/latest").exists());
    assert_canonical_run_files(&latest_run_dir(tmp.path()));
}

#[test]
fn runs_list_has_empty_state_and_permissions_has_json_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let runs = stdout(
        kuzushi()
            .args(["runs", "list", "--target"])
            .arg(tmp.path())
            .output()
            .unwrap(),
    );
    assert!(runs.contains("no run artifacts found"), "{runs}");
    assert!(runs.contains("kuzushi scan"), "{runs}");

    let permissions = stdout(
        kuzushi()
            .args(["permissions", "--target"])
            .arg(tmp.path())
            .arg("--json")
            .output()
            .unwrap(),
    );
    let parsed: Value = serde_json::from_str(&permissions).unwrap();
    assert_eq!(
        parsed["policy"]["modelFallback"],
        "forbidden without explicit operator consent"
    );
    assert_eq!(
        parsed["policy"]["headlessRun"],
        "explicit tool name required; no focused-module shorthand"
    );
}

#[test]
fn workspace_commands_refuse_targetless_cwd_without_creating_state() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let cases = [
        ("runs", vec!["runs", "list"]),
        ("pr-comment", vec!["pr-comment"]),
        ("doctor", vec!["doctor"]),
        ("scan", vec!["scan"]),
        ("workspace run", vec!["run", "context:build"]),
    ];

    for (label, args) in cases {
        let cwd = tmp.path().join(label.replace(' ', "-"));
        fs::create_dir_all(&cwd).unwrap();
        let output = kuzushi()
            .current_dir(&cwd)
            .env("HOME", &home)
            .args(args)
            .output()
            .unwrap();

        assert!(!output.status.success(), "{label} should require a target");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("target") && stderr.contains("explicit"),
            "{label}: {stderr}"
        );
        assert!(
            !cwd.join(".kuzushi").exists(),
            "{label} must not turn cwd into a workspace"
        );
    }
}

#[test]
fn suppress_command_records_expiring_evidence_backed_suppression() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::write(
        tmp.path().join("src/server.js"),
        "const express = require('express');\nres.send(req.query.name);\n",
    )
    .unwrap();
    let store = FindingStore::open(tmp.path().join(".kuzushi/v3/index.sqlite3")).unwrap();
    store
        .record_run_started("scan-test", tmp.path(), "complete")
        .unwrap();
    let finding = Finding::new_tool(
        "semgrep",
        "javascript.express.xss",
        "src/server.js",
        2,
        Some(2),
        Severity::High,
        "CWE-79 reflected XSS reaches response",
    )
    .with_static_proof_state(StaticProofState::StaticallyRejected);
    store.insert_finding("scan-test", &finding).unwrap();
    drop(store);

    let out = stdout(
        kuzushi()
            .arg("suppress")
            .arg(&finding.fingerprint)
            .args(["--target"])
            .arg(tmp.path())
            .args([
                "--reason",
                "operator confirmed escaping upstream",
                "--author",
                "security@example.test",
                "--days",
                "7",
                "--json",
            ])
            .output()
            .unwrap(),
    );
    let parsed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["reason"], "operator confirmed escaping upstream");
    assert_eq!(parsed["author"], "security@example.test");
    assert_eq!(parsed["scope"]["filePath"], "src/server.js");
    assert!(tmp
        .path()
        .join(".kuzushi/v3/whitebox-suppressions.json")
        .exists());
    let store = FindingStore::open(tmp.path().join(".kuzushi/v3/index.sqlite3")).unwrap();
    let finding_id = store
        .get_finding_by_fingerprint(&finding.fingerprint)
        .unwrap()
        .expect("finding after suppress")
        .id
        .expect("persisted finding id");
    let decision = store
        .latest_review_decision_for_finding_identity(finding_id)
        .unwrap()
        .expect("suppressed review decision");
    assert_eq!(decision.decision.verdict, ReviewDecisionVerdict::Suppressed);
    assert_eq!(decision.triage_verdict, None);
}

#[test]
fn plain_flag_forces_line_oriented_shell_output() {
    let tmp = tempfile::tempdir().unwrap();
    let out = stdout(
        kuzushi()
            // Skip first-run onboarding so the shell lands on the workbench
            // this test exercises, not the no-model-configured model picker.
            .env("KUZUSHI_SKIP_ONBOARDING", "1")
            .args(["--plain", "shell", "--target"])
            .arg(tmp.path())
            .output()
            .unwrap(),
    );

    assert!(out.contains("KUZUSHI PLAIN SESSION SUMMARY"));
    assert!(out.contains("status: idle"));
    assert!(out.contains(&format!(
        "target: {}",
        tmp.path().canonicalize().unwrap().display()
    )));
    assert!(out.contains("commands: 0"));
    assert!(out.contains("Next: printf 'findings\\n' | kuzushi --plain --target <path>"));
    assert!(!out.contains("mode:shell"));
    assert_strict_plain("--plain shell", &out);
}

#[test]
fn plain_env_aliases_are_line_oriented_for_screen_reader_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let out = stdout(
        kuzushi()
            .env("KUZUSHI_SCREEN_READER", "1")
            // Skip first-run onboarding so the shell lands on the workbench
            // this test exercises, not the no-model-configured model picker.
            .env("KUZUSHI_SKIP_ONBOARDING", "1")
            .args(["shell", "--target"])
            .arg(tmp.path())
            .output()
            .unwrap(),
    );

    assert!(out.contains("KUZUSHI PLAIN SESSION SUMMARY"));
    assert!(out.contains("status: idle"));
    assert!(out.contains(&format!(
        "target: {}",
        tmp.path().canonicalize().unwrap().display()
    )));
    assert!(out.contains("commands: 0"));
    assert!(!out.contains("mode:shell"));
    assert_strict_plain("KUZUSHI_SCREEN_READER shell", &out);
}

#[test]
fn plain_scripted_shell_prints_unknown_command_feedback() {
    let output = plain_shell_script_output("/nope\n");
    assert!(!output.status.success(), "invalid scripted input must fail");
    let out = String::from_utf8(output.stdout).expect("stdout should be UTF-8");

    assert!(out.contains("COMMAND RESULT"));
    assert!(out.contains("command: /nope"));
    assert!(out.contains("> /nope"));
    assert!(out.contains("error: unknown command \"/nope\". Next: /help"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("plain scripted session failed"));
    assert_strict_plain("--plain shell /nope", &out);
}

#[test]
fn plain_scripted_shell_prints_quit_acknowledgement() {
    let out = plain_shell_script("/quit\n");

    assert!(out.contains("command: /quit"));
    assert!(out.contains("> /quit"));
    assert!(out.contains("system: exit requested; closing shell"));
    assert_strict_plain("--plain shell /quit", &out);
}

#[test]
fn plain_scripted_shell_prints_help_then_quit_result_blocks() {
    let out = plain_shell_script("/help\n/quit\n");

    assert_eq!(out.matches("COMMAND RESULT").count(), 2);
    assert!(out.contains("command: /help"));
    assert!(out.contains("command: /quit"));
    assert!(out.contains("HELP"));
    assert!(out.contains("system: exit requested; closing shell"));
    assert_strict_plain("--plain shell /help /quit", &out);
}

#[test]
fn plain_scripted_shell_prints_result_for_unchanged_view_command() {
    let out = plain_shell_script("/back\n");

    assert!(out.contains("COMMAND RESULT"));
    assert!(out.contains("command: /back"));
    assert!(out.contains("> /back"));
    assert!(out.contains("KUZUSHI"));
    assert_strict_plain("--plain shell /back", &out);
}

#[test]
fn modules_and_tools_list_visible_executable_rust_surfaces() {
    let modules_raw = stdout(kuzushi().args(["modules", "--json"]).output().unwrap());
    let tools_raw = stdout(kuzushi().args(["tools", "--json"]).output().unwrap());
    let modules: Vec<Value> = serde_json::from_str(&modules_raw).unwrap();
    let tools: Vec<Value> = serde_json::from_str(&tools_raw).unwrap();

    let module_ids = modules
        .iter()
        .filter_map(|module| module.get("id").and_then(Value::as_str))
        .collect::<Vec<_>>();
    for expected in [
        "context",
        "sast",
        "semgrep",
        "codeql",
        "agentic-sast",
        "findings",
        "secret-scan",
        "dep-hygiene",
        "iac-scan",
    ] {
        assert!(
            module_ids.contains(&expected),
            "missing visible module {expected}; modules={module_ids:?}"
        );
    }
    for hidden in [
        "context-lite",
        "exploit-chain",
        "module-recommender",
        "pipeline",
        "systems-hunt",
    ] {
        assert!(
            !module_ids.contains(&hidden),
            "hidden module {hidden} must not be listed"
        );
    }

    let tool_names = tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    for expected in [
        "context:build",
        "sast:scan",
        "semgrep:scan",
        "codeql:scan",
        "agentic-sast:scan",
        "findings:list",
        "secret-scan:scan",
        "dep-hygiene:check",
        "iac-scan:scan",
        "triage:run",
        "verify:finding",
        "patch:finding",
    ] {
        assert!(
            tool_names.contains(&expected),
            "missing executable tool {expected}; tools={tool_names:?}"
        );
    }
    assert!(
        !tool_names.contains(&"module-recommender:recommend"),
        "exact-only compatibility tools must stay out of discovery"
    );
}

#[test]
fn findings_empty_state_names_next_scan_command() {
    let tmp = tempfile::tempdir().unwrap();
    let out = stdout(
        kuzushi()
            .args(["findings", "--target"])
            .arg(tmp.path())
            .output()
            .unwrap(),
    );

    assert!(out.contains("no findings found"));
    assert!(out.contains("Next: kuzushi scan"));
    assert!(out.contains(&tmp.path().display().to_string()));
}

#[test]
fn finding_detail_resolves_alias_and_outputs_json_report() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join(".kuzushi/v3/index.sqlite3");
    let store = FindingStore::open(&db_path).unwrap();
    store
        .record_run_started("run-detail", tmp.path(), "completed")
        .unwrap();
    let finding = Finding::new_semgrep(
        "demo.detail",
        "src/app.js",
        7,
        Some(8),
        Severity::High,
        "Request query data reaches an HTML response without escaping",
    )
    .with_static_proof_state(StaticProofState::SourceSinkLinked);
    let fingerprint = finding.fingerprint.clone();
    let finding_id = store.insert_finding("run-detail", &finding).unwrap();
    store
        .record_auto_triage(
            finding_id,
            &TriageOutcome {
                verdict: TriageVerdict::TruePositive,
                confidence: 0.88,
                rationale: "source and sink are linked".to_string(),
                cost_usd: 0.01,
            },
        )
        .unwrap();
    store
        .save_verification(
            finding_id,
            &PersistedVerification {
                proof_level: 4,
                proof_verdict: PersistedProofVerdict::Exploited,
                backend: PersistedSandboxBackend::Plain,
                language: Some("javascript".to_string()),
                harness_path: None,
                crash_evidence: Some("payload executed".to_string()),
                duration_ms: 42,
                cost_usd: 0.0,
                notes: vec!["fixture confirmed".to_string()],
                verification_run_id: None,
                verified_scan_id: None,
                created_at: String::new(),
            },
        )
        .unwrap();
    store
        .insert_patch_result(&PatchResult {
            patch_run_id: "patch-1".to_string(),
            fingerprint: fingerprint.clone(),
            repo: tmp.path().display().to_string(),
            diff: None,
            status: PatchStatus::BuildFailed,
            iterations: 1,
            build_command: None,
            test_command: Some("pnpm test".to_string()),
            worktree_path: None,
            cost_usd: Some(0.0),
            validator_log: None,
            history: Vec::new(),
            created_at: None,
            updated_at: None,
        })
        .unwrap();

    let plain = stdout(
        kuzushi()
            .args(["finding", "F-0001", "--target"])
            .arg(tmp.path())
            .output()
            .unwrap(),
    );
    assert!(plain.contains("Finding F-0001"));
    assert!(plain.contains("Proof state: source_sink_linked"));
    assert!(plain.contains("Runtime validation: runtime_verified"));
    assert!(plain.contains("Patch result:"));
    assert!(plain.contains("Next action: patch"));

    let prefix = &fingerprint[..8];
    let raw = stdout(
        kuzushi()
            .args(["finding", prefix, "--target"])
            .arg(tmp.path())
            .arg("--json")
            .output()
            .unwrap(),
    );
    let report: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(report["alias"], "F-0001");
    assert_eq!(report["finding"]["fingerprint"], fingerprint);
    assert!(report["proofState"]
        .as_str()
        .unwrap()
        .starts_with("source_sink_linked"));
    assert!(report["runtimeValidation"]
        .as_str()
        .unwrap()
        .starts_with("runtime_verified"));
    assert_eq!(report["nextAction"], "patch");
    assert_eq!(report["patchResults"].as_array().unwrap().len(), 1);
}

#[test]
fn scan_mode_whitebox_static_is_static_only_and_json_visible() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{"dependencies":{"lodash":"latest"}}"#,
    )
    .unwrap();
    let raw = stdout(
        kuzushi()
            .args([
                "scan",
                "--mode",
                "whitebox-static",
                "--tasks",
                "dep-hygiene",
                "--json",
            ])
            .arg(tmp.path())
            .output()
            .unwrap(),
    );
    let report: Value = serde_json::from_str(&raw).unwrap();

    assert_eq!(report["mode"], "whitebox-static");
    assert_eq!(report["whiteboxStatic"]["enabled"], true);
    assert_eq!(report["whiteboxStatic"]["verify"], false);
    assert_eq!(report["whiteboxStatic"]["autoPatch"], false);
    assert_eq!(report["whiteboxStatic"]["dynamicAnalysis"], false);
    assert_eq!(report["whiteboxStatic"]["pocExecution"], false);
    assert_eq!(report["whiteboxStatic"]["executionProofStates"], false);
    assert_eq!(report["findingsCount"], 1);
}

#[test]
fn npm_wrapper_help_reaches_the_rust_binary() {
    let output = Command::new("node")
        .current_dir(repo_root())
        .env("KUZUSHI_NATIVE_BIN", env!("CARGO_BIN_EXE_kuzushi"))
        .args(["bin/kuzushi-rs.mjs", "--help"])
        .output()
        .unwrap();
    let out = stdout(output);

    assert!(out.contains("Kuzushi security-native code agent"));
    assert!(out.contains("Usage: kuzushi"));
    assert!(out.contains("modules"));
    assert!(out.contains("tools"));
    assert!(!out.contains("TypeScript"));
}

#[test]
fn npm_wrapper_kz_alias_reaches_the_compact_rust_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let alias_path = tmp.path().join("kz");
    fs::copy(repo_root().join("bin/kuzushi-rs.mjs"), &alias_path).unwrap();

    let output = Command::new("node")
        .env("KUZUSHI_NATIVE_BIN", env!("CARGO_BIN_EXE_kuzushi"))
        .arg(alias_path)
        .arg("--help")
        .output()
        .unwrap();
    let out = stdout(output);

    assert!(out.contains("Kuzushi security-native code agent"));
    assert!(out.contains("Usage: kz"));
    assert!(out.contains("modules"));
    assert!(out.contains("tools"));
    assert!(!out.contains("Usage: kuzushi"));
}

#[test]
fn demo_scans_offline_fixture_and_persists_findings() {
    // P0.6: the first-wow path must work with no API key, no model, and no
    // external scanner binaries.
    let output = kuzushi().arg("demo").output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "demo must succeed offline: {stderr}"
    );
    assert!(stderr.contains("vendored vulnerable fixture"), "{stderr}");
    assert!(stderr.contains("kuzushi finding F-0001"), "{stderr}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(combined.contains("finding(s)"), "{combined}");
    assert!(
        !combined.contains("completed: 0 finding(s)"),
        "demo fixture must fire findings: {combined}"
    );
}

#[test]
fn npm_wrapper_kz_alias_accepts_the_single_kuzushi_binary_override() {
    // The npm package ships one binary per platform: `kz` resolves to the
    // `kuzushi` binary and argv0 names the usage line.
    let tmp = tempfile::tempdir().unwrap();
    let alias_path = tmp.path().join("kz");
    fs::copy(repo_root().join("bin/kuzushi-rs.mjs"), &alias_path).unwrap();

    let output = Command::new("node")
        .env("KUZUSHI_NATIVE_BIN", env!("CARGO_BIN_EXE_kuzushi"))
        .arg(alias_path)
        .arg("--help")
        .output()
        .unwrap();
    let out = stdout(output);

    assert!(out.contains("Kuzushi security-native code agent"));
    assert!(
        out.contains("Usage: kz"),
        "argv0 must name the alias: {out}"
    );
    assert!(!out.contains("Usage: kuzushi"));
}

#[test]
fn npm_wrapper_rejects_unrelated_native_override_name() {
    let tmp = tempfile::tempdir().unwrap();
    let unrelated = tmp.path().join("not-kuzushi");
    fs::copy(repo_root().join("bin/kuzushi-rs.mjs"), &unrelated).unwrap();

    let output = Command::new("node")
        .current_dir(repo_root())
        .env("KUZUSHI_NATIVE_BIN", &unrelated)
        .args(["bin/kuzushi-rs.mjs", "--help"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "unrelated-named override should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("KUZUSHI_NATIVE_BIN must point to a kuzushi or kz binary"),
        "{stderr}"
    );
}

#[test]
fn npm_wrapper_rejects_non_file_native_override() {
    let tmp = tempfile::tempdir().unwrap();
    let fake_binary = tmp.path().join("kuzushi");
    fs::create_dir_all(&fake_binary).unwrap();

    let output = Command::new("node")
        .current_dir(repo_root())
        .env("KUZUSHI_NATIVE_BIN", &fake_binary)
        .args(["bin/kuzushi-rs.mjs", "--help"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "directory override should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("KUZUSHI_NATIVE_BIN must point to a file"),
        "{stderr}"
    );
}

#[test]
fn npm_wrapper_skips_non_file_fallback_candidate() {
    let tmp = tempfile::tempdir().unwrap();
    let bin_dir = tmp.path().join("bin");
    let fake_binary = tmp.path().join("target/release/kuzushi");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&fake_binary).unwrap();
    let wrapper = bin_dir.join("kuzushi-rs.mjs");
    fs::copy(repo_root().join("bin/kuzushi-rs.mjs"), &wrapper).unwrap();

    let output = Command::new("node")
        .arg(wrapper)
        .arg("--help")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "directory fallback candidate should not be spawned"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Could not find the Kuzushi native binary"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("EACCES") && !stderr.contains("spawn"),
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn npm_wrapper_owns_cli_name_environment() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let bin_dir = tmp.path().join("bin");
    let native_dir = tmp.path().join("target/release");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&native_dir).unwrap();
    let wrapper = bin_dir.join("kuzushi-rs.mjs");
    let fake_binary = native_dir.join("kuzushi");
    fs::copy(repo_root().join("bin/kuzushi-rs.mjs"), &wrapper).unwrap();
    fs::write(
        &fake_binary,
        "#!/usr/bin/env node\nprocess.stdout.write(process.env.KUZUSHI_CLI_NAME || '');\n",
    )
    .unwrap();
    fs::set_permissions(&fake_binary, fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new("node")
        .env("KUZUSHI_CLI_NAME", "kz")
        .arg(wrapper)
        .output()
        .unwrap();
    let out = stdout(output);

    assert_eq!(out, "kuzushi");
}

#[test]
fn npm_package_runtime_surface_is_rust_only() {
    let package_raw = fs::read_to_string(repo_root().join("package.json")).unwrap();
    let package: Value = serde_json::from_str(&package_raw).unwrap();
    let bin = package.get("bin").and_then(Value::as_object).unwrap();

    assert_eq!(bin.len(), 2, "package should expose Kuzushi Rust CLI bins");
    assert_eq!(
        bin.get("kuzushi").and_then(Value::as_str),
        Some("./bin/kuzushi-rs.mjs")
    );
    assert_eq!(
        bin.get("kz").and_then(Value::as_str),
        Some("./bin/kuzushi-rs.mjs")
    );
    assert!(!bin.contains_key("kuzushi-ts"));

    let files = package
        .get("files")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(files.contains(&"native"));
    assert!(files.contains(&"NOTICE"));
    assert!(files.contains(&"UPSTREAM_CODEX.md"));
    assert!(files.contains(&"LICENSES"));
    for removed in [
        "!dist/cli",
        "!dist/cli.d.ts",
        "!dist/cli.js",
        "!dist/cli.js.map",
    ] {
        assert!(
            files.contains(&removed),
            "package files should exclude old TS CLI artifact {removed}"
        );
    }

    let dependencies = package
        .get("dependencies")
        .and_then(Value::as_object)
        .unwrap();
    for runtime_dep in ["ink", "react", "@types/react"] {
        assert!(
            !dependencies.contains_key(runtime_dep),
            "{runtime_dep} must not be a production dependency of normal CLI execution"
        );
    }

    let wrapper = fs::read_to_string(repo_root().join("bin/kuzushi-rs.mjs")).unwrap();
    assert!(wrapper.contains("native"));
    assert!(wrapper.contains("KUZUSHI_NATIVE_BIN"));
    for removed in ["ink", "react", "src/cli.ts", "dist/cli.js"] {
        assert!(
            !wrapper.to_ascii_lowercase().contains(removed),
            "wrapper must not reference legacy runtime surface {removed}"
        );
    }
}

#[test]
fn legacy_ink_shell_is_deleted_from_source_cli() {
    for removed_path in [
        "src/cli/commands/shell.ts",
        "src/copilot/shell.ts",
        "src/ui/App.tsx",
        "src/ui/components",
        "src/ui/primitives",
        "reference/ts-runtime-island",
    ] {
        let path = repo_root().join(removed_path);
        assert!(
            !path.exists(),
            "{removed_path} must not exist after TS runtime retirement"
        );
    }
}

#[test]
fn doctor_checks_rust_preflight_without_printing_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let secret = "sk-kuzushi-doctor-secret-value";
    let output = kuzushi()
        .current_dir(repo_root())
        .args(["doctor", "--target"])
        .arg(tmp.path())
        .env("KUZUSHI_MODEL", "openai:gpt-4.1")
        .env("OPENAI_API_KEY", secret)
        .output()
        .unwrap();
    let out = stdout(output);

    for expected in [
        "Kuzushi doctor",
        "target",
        "config",
        "state",
        "findings-db",
        "semgrep",
        "codeql",
        "joern",
        "nmap",
        "model",
        "auth-env",
        "LangGraph bridge",
        "Summary:",
    ] {
        assert!(out.contains(expected), "missing {expected:?} in:\n{out}");
    }
    assert!(out.contains("OPENAI_API_KEY is set; value is hidden"));
    assert!(
        !out.contains(secret),
        "doctor output must not print credential values:\n{out}"
    );
    assert!(
        !tmp.path()
            .join(".kuzushi/v3")
            .join(format!(".doctor-write-test-{}", std::process::id()))
            .exists(),
        "doctor write probe should be removed"
    );
}

#[test]
fn doctor_json_reports_named_preflight_checks() {
    let tmp = tempfile::tempdir().unwrap();
    let raw = stdout(
        kuzushi()
            .current_dir(repo_root())
            .args(["doctor", "--target"])
            .arg(tmp.path())
            .arg("--json")
            .env("KUZUSHI_MODEL", "openai:gpt-4.1")
            .env("OPENAI_API_KEY", "hidden-json-secret")
            .output()
            .unwrap(),
    );
    let report: Value = serde_json::from_str(&raw).unwrap();
    let names = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|check| check["name"].as_str())
        .collect::<Vec<_>>();

    for expected in [
        "config",
        "state",
        "findings-db",
        "semgrep",
        "codeql",
        "joern",
        "nmap",
        "model",
        "auth-env",
        "LangGraph bridge",
    ] {
        assert!(
            names.contains(&expected),
            "missing {expected:?}; names={names:?}; raw={raw}"
        );
    }
    assert!(!raw.contains("hidden-json-secret"));
}

#[test]
fn failed_run_writes_failure_handoff_context() {
    let tmp = tempfile::tempdir().unwrap();
    let output = kuzushi()
        .args(["--target"])
        .arg(tmp.path())
        .args(["run", "context:build", "--input", r#"{"enrichment":true}"#])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "enrichment request should fail explicitly"
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "failed");
    assert_eq!(body["fallback_context"]["failedStage"], "context:build");
    assert!(body["fallback_context"]["fallbackPrompt"]
        .as_str()
        .is_some_and(|prompt| prompt.contains("context:build")));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("validated"));

    let runs_root = tmp.path().join(".kuzushi/v3/runs");
    let run_dir = fs::read_dir(&runs_root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let failures = fs::read_to_string(run_dir.join("failures.json")).unwrap();
    let events = fs::read_to_string(run_dir.join("events.jsonl")).unwrap();
    let artifacts = fs::read_to_string(run_dir.join("artifacts.json")).unwrap();

    assert_canonical_run_files(&run_dir);
    assert!(failures.contains("context:build did not complete successfully"));
    assert!(failures.contains("artifact-review-only"));
    assert!(!failures.contains("validated"));
    assert!(failures.contains("input.json"));
    assert!(artifacts.contains("input.json"));
    assert!(artifacts.contains("failures.json"));
    assert!(events.contains("\"status\":\"failed\""));
}

#[test]
fn targetless_run_writes_artifacts_under_current_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let out = stdout(
        kuzushi()
            .current_dir(tmp.path())
            .args(["run", "config:show", "--input", "{}"])
            .output()
            .unwrap(),
    );
    let body: Value = serde_json::from_str(&out).unwrap();

    assert_eq!(body["ok"], true);
    assert_eq!(body["status"], "completed");
    let run_dir = latest_run_dir(tmp.path());
    let run_json = fs::read_to_string(latest_run_artifact(tmp.path(), "run.json")).unwrap();
    let result = fs::read_to_string(run_dir.join("result.json")).unwrap();
    let failures = fs::read_to_string(latest_run_artifact(tmp.path(), "failures.json")).unwrap();

    assert_canonical_run_files(&run_dir);
    assert!(run_json.contains("\"kind\": \"run\""));
    assert!(run_json.contains("\"tool\": \"config:show\""));
    assert!(result.contains("\"status\": \"completed\""));
    assert!(failures.contains("\"status\": \"completed\""));
}

#[test]
fn malformed_run_input_writes_failed_artifact_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();

    let output = kuzushi()
        .current_dir(tmp.path())
        .env("HOME", &home)
        .args(["run", "config:show", "--input", "{not-json"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "malformed input should fail");
    let (run_dir, failure_json) = assert_failed_run_bundle(tmp.path(), "run", "config:show");
    let input = fs::read_to_string(run_dir.join("input.json")).unwrap();
    let report = fs::read_to_string(latest_run_artifact(tmp.path(), "report.md")).unwrap();

    assert!(input.contains("rawInput"));
    assert_eq!(failure_json["failures"][0]["error"], "--input must be JSON");
    assert!(report.contains("Status: failed"));
}

#[test]
fn malformed_run_option_writes_failed_artifact_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();

    let output = kuzushi()
        .current_dir(tmp.path())
        .env("HOME", &home)
        .args(["run", "config:show", "--input", "{}"])
        .args(["--option", "missing-equals"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "malformed --option should fail");
    let (run_dir, failure_json) = assert_failed_run_bundle(tmp.path(), "run", "config:show");
    let input = fs::read_to_string(run_dir.join("input.json")).unwrap();

    assert_eq!(
        failure_json["failures"][0]["error"],
        "--option must be key=value, got \"missing-equals\""
    );
    assert!(input.contains("{}"));
}

#[test]
fn unknown_run_tool_writes_failed_artifact_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();

    let output = kuzushi()
        .current_dir(tmp.path())
        .env("HOME", &home)
        .args(["run", "missing:tool", "--input", "{}"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "unknown run tool should fail");
    let (run_dir, failure_json) = assert_failed_run_bundle(tmp.path(), "run", "missing:tool");
    let input = fs::read_to_string(run_dir.join("input.json")).unwrap();

    assert!(failure_json["failures"][0]["error"]
        .as_str()
        .is_some_and(|error| error.contains("unknown tool \"missing:tool\"")));
    assert!(input.contains("{}"));
}

#[test]
fn runtime_backed_run_missing_model_writes_failed_artifact_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let home = tmp.path().join("home");
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(&home).unwrap();
    seed_untriaged_finding(&repo);

    let output = kuzushi()
        .env("HOME", &home)
        .args(["--target"])
        .arg(&repo)
        .args(["run", "triage:run", "--input", "{}"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "runtime-backed run without model should fail"
    );
    let stdout: Value = serde_json::from_slice(&output.stdout).unwrap();
    let (_, failure_json) = assert_failed_run_bundle(&repo, "run", "triage:run");

    assert_eq!(stdout["status"], "failed");
    assert_eq!(stdout["fallback_context"]["failedStage"], "triage:run");
    assert!(failure_json["failures"][0]["error"]
        .as_str()
        .is_some_and(|error| error.contains("requires an explicit model")));
}

fn seed_untriaged_finding(repo: &Path) {
    let store = FindingStore::open(repo.join(".kuzushi/v3/index.sqlite3")).unwrap();
    store
        .record_run_started("run-1", repo, "completed")
        .unwrap();
    let finding = Finding::new_semgrep(
        "demo.sql",
        "src/db.ts",
        42,
        Some(42),
        Severity::High,
        "SQL injection in search",
    );
    store.insert_finding("run-1", &finding).unwrap();
}

#[test]
fn invalid_config_writes_failed_run_artifact_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
    fs::write(home.join(".kuzushi/v3/config.toml"), r#"model = "gpt-5.5""#).unwrap();

    let output = kuzushi()
        .current_dir(tmp.path())
        .env("HOME", &home)
        .args(["run", "config:show", "--input", "{}"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "invalid config should fail");
    let (run_dir, failure_json) = assert_failed_run_bundle(tmp.path(), "run", "config:show");
    let input = fs::read_to_string(run_dir.join("input.json")).unwrap();

    assert!(failure_json.to_string().contains("provider:model"));
    assert!(input.contains("rawInput"));
}

#[test]
fn scan_invalid_config_writes_failed_run_artifact_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let home = tmp.path().join("home");
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
    fs::write(home.join(".kuzushi/v3/config.toml"), r#"model = "gpt-5.5""#).unwrap();

    let output = kuzushi()
        .env("HOME", &home)
        .arg("scan")
        .arg(&repo)
        .output()
        .unwrap();

    assert!(!output.status.success(), "invalid scan config should fail");
    let (_, failure_json) = assert_failed_run_bundle(&repo, "scan", "sast:scan");

    assert!(failure_json.to_string().contains("provider:model"));
}

#[test]
fn scan_missing_explicit_target_does_not_write_artifacts_under_cwd() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();

    let output = kuzushi()
        .current_dir(tmp.path())
        .env("HOME", &home)
        .arg("scan")
        .arg("missing-target")
        .output()
        .unwrap();

    assert!(!output.status.success(), "missing scan target should fail");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Target path does not exist"));
    assert!(
        !tmp.path().join(".kuzushi").exists(),
        "an unresolved explicit target must not redirect artifacts into cwd"
    );
}

#[test]
fn scan_invalid_since_writes_failed_run_artifact_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let home = tmp.path().join("home");
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(&home).unwrap();

    let output = kuzushi()
        .env("HOME", &home)
        .arg("scan")
        .arg(&repo)
        .args(["--since", "missing-ref"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "invalid scan --since should fail");
    let (_, failure_json) = assert_failed_run_bundle(&repo, "scan", "sast:scan");

    assert_eq!(
        failure_json["failures"][0]["error"],
        "--since \"missing-ref\" failed"
    );
}

#[test]
fn scan_invalid_budget_writes_failed_run_artifact_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let home = tmp.path().join("home");
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(&home).unwrap();

    let output = kuzushi()
        .env("HOME", &home)
        .arg("scan")
        .arg(&repo)
        .args(["--budget", "unknown=10"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "invalid scan --budget should fail"
    );
    let (_, failure_json) = assert_failed_run_bundle(&repo, "scan", "sast:scan");

    assert!(failure_json["failures"][0]["error"]
        .as_str()
        .is_some_and(|error| error.contains("invalid --budget spec")));
}

#[test]
fn scan_secret_scan_success_writes_canonical_run_artifact_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let home = tmp.path().join("home");
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::create_dir_all(&home).unwrap();
    fs::write(repo.join("src/app.js"), "const status = 'ok';\n").unwrap();

    let output = kuzushi()
        .env("HOME", &home)
        .arg("scan")
        .arg(&repo)
        .args(["--tasks", "secret-scan", "--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let run_dir = latest_run_dir(&repo);
    let run_json = fs::read_to_string(latest_run_artifact(&repo, "run.json")).unwrap();
    let failures = fs::read_to_string(latest_run_artifact(&repo, "failures.json")).unwrap();

    assert_canonical_run_files(&run_dir);
    assert!(run_json.contains("\"status\": \"completed\""));
    assert!(run_json.contains("\"kind\": \"scan\""));
    assert!(run_json.contains("\"tool\": \"sast:scan\""));
    assert!(failures.contains("\"status\": \"completed\""));
}

#[test]
fn sast_scan_missing_cargo_audit_writes_failure_handoff_context() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let home = tmp.path().join("home");
    let fake_path = tmp.path().join("bin");
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&fake_path).unwrap();
    fs::write(repo.join("Cargo.lock"), "# lockfile present\n").unwrap();

    let output = kuzushi()
        .env("HOME", &home)
        .env("PATH", &fake_path)
        .args(["--target"])
        .arg(&repo)
        .args([
            "run",
            "sast:scan",
            "--input",
            r#"{"tasks":["cargo-audit"],"triage":false}"#,
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "cargo-audit should fail closed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cargo-audit: `cargo audit` was not found"),
        "stderr: {stderr}"
    );
    let run_dir = fs::read_dir(repo.join(".kuzushi/v3/runs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let failures = fs::read_to_string(run_dir.join("failures.json")).unwrap();
    let artifacts = fs::read_to_string(run_dir.join("artifacts.json")).unwrap();

    assert!(failures.contains("sast:scan did not complete successfully"));
    assert!(failures.contains("cargo-audit"));
    assert!(failures.contains("artifact-review-only"));
    assert!(artifacts.contains("failures.json"));
}

#[test]
fn scan_missing_cargo_audit_writes_failed_artifact_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let home = tmp.path().join("home");
    let fake_path = tmp.path().join("bin");
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&fake_path).unwrap();
    fs::write(repo.join("Cargo.lock"), "# lockfile present\n").unwrap();

    let output = kuzushi()
        .env("HOME", &home)
        .env("PATH", &fake_path)
        .arg("scan")
        .arg(&repo)
        .args(["--tasks", "cargo-audit", "--json"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "cargo-audit scan should fail closed"
    );
    let (_, failure_json) = assert_failed_run_bundle(&repo, "scan", "sast:scan");

    assert!(failure_json["failures"][0]["error"]
        .as_str()
        .is_some_and(|error| error.contains("cargo-audit")));
}
