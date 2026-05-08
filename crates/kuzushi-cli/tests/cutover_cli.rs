use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

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
    let tmp = tempfile::tempdir().unwrap();
    let mut child = kuzushi()
        .args(["--plain", "shell", "--target"])
        .arg(tmp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    stdout(child.wait_with_output().unwrap())
}

#[test]
fn rust_cli_help_is_the_documented_primary_surface() {
    let out = stdout(kuzushi().arg("--help").output().unwrap());

    assert!(out.contains("Kuzushi security-native code agent"));
    assert!(out.contains("Usage: kuzushi"));
    assert!(out.contains("--plain"));
    for command in [
        "shell", "scan", "findings", "finding", "config", "modules", "tools", "doctor", "run",
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
fn cli_run_dot_is_rejected_as_shell_only_shorthand() {
    let output = kuzushi().args(["run", "."]).output().unwrap();

    assert!(
        !output.status.success(),
        "terminal `kuzushi run .` must not silently dispatch"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("`kuzushi run .` is shell-only"), "{stderr}");
    assert!(stderr.contains("use <module>"), "{stderr}");
    assert!(stderr.contains("context:build"), "{stderr}");
}

#[test]
fn plain_flag_forces_line_oriented_shell_output() {
    let tmp = tempfile::tempdir().unwrap();
    let out = stdout(
        kuzushi()
            .args(["--plain", "shell", "--target"])
            .arg(tmp.path())
            .output()
            .unwrap(),
    );

    assert!(out.contains("KUZUSHI"));
    assert!(out.contains("mode:shell"));
    assert!(out.contains("First finding"));
    assert_strict_plain("--plain shell", &out);
}

#[test]
fn plain_env_aliases_are_line_oriented_for_screen_reader_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let out = stdout(
        kuzushi()
            .env("KUZUSHI_SCREEN_READER", "1")
            .args(["shell", "--target"])
            .arg(tmp.path())
            .output()
            .unwrap(),
    );

    assert!(out.contains("KUZUSHI"));
    assert!(out.contains("mode:shell"));
    assert_strict_plain("KUZUSHI_SCREEN_READER shell", &out);
}

#[test]
fn plain_scripted_shell_prints_unknown_command_feedback() {
    let out = plain_shell_script("/nope\n");

    assert!(out.contains("COMMAND RESULT"));
    assert!(out.contains("command: /nope"));
    assert!(out.contains("> /nope"));
    assert!(out.contains("error: unknown command \"/nope\". Next: /help"));
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
        "recon",
        "vendor-assessment",
        "prompt-armor",
    ] {
        assert!(
            module_ids.contains(&expected),
            "missing visible module {expected}; modules={module_ids:?}"
        );
    }
    for hidden in ["context-lite", "pipeline", "systems-hunt"] {
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
        "recon:http-fingerprint",
        "triage:run",
        "verify:finding",
        "patch:finding",
    ] {
        assert!(
            tool_names.contains(&expected),
            "missing executable tool {expected}; tools={tool_names:?}"
        );
    }
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
    let db_path = tmp.path().join(".kuzushi/v2/findings.sqlite3");
    let store = FindingStore::open(&db_path).unwrap();
    store
        .insert_scan_run("run-detail", tmp.path(), "completed")
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
        .save_triage(
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
    assert!(plain.contains("Runtime validation: execution_confirmed"));
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
    assert_eq!(
        report["proofState"]
            .as_str()
            .unwrap()
            .starts_with("source_sink_linked"),
        true
    );
    assert_eq!(
        report["runtimeValidation"]
            .as_str()
            .unwrap()
            .starts_with("execution_confirmed"),
        true
    );
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
fn npm_package_runtime_surface_is_rust_only() {
    let package_raw = fs::read_to_string(repo_root().join("package.json")).unwrap();
    let package: Value = serde_json::from_str(&package_raw).unwrap();
    let bin = package.get("bin").and_then(Value::as_object).unwrap();

    assert_eq!(bin.len(), 1, "package should expose only the Rust CLI bin");
    assert_eq!(
        bin.get("kuzushi").and_then(Value::as_str),
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

    let migration_status =
        fs::read_to_string(repo_root().join("docs/rust-migration-status.md")).unwrap();
    assert!(migration_status.contains("src/cli.ts shell"));
    assert!(migration_status.contains("fails with a Rust replacement message"));
    assert!(migration_status.contains("retired TS runtime island was deleted"));
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
        "model",
        "auth-env",
        "pi-agent-core bridge",
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
            .join(".kuzushi/v2")
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
        "model",
        "auth-env",
        "pi-agent-core bridge",
    ] {
        assert!(
            names.contains(&expected),
            "missing {expected:?}; names={names:?}; raw={raw}"
        );
    }
    assert!(!raw.contains("hidden-json-secret"));
}
