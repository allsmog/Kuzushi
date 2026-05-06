use std::fs;
use std::path::Path;
use std::process::Command;

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
}

#[test]
fn rust_cli_help_is_the_documented_primary_surface() {
    let out = stdout(kuzushi().arg("--help").output().unwrap());

    assert!(out.contains("Kuzushi security copilot"));
    assert!(out.contains("Usage: kuzushi"));
    assert!(out.contains("--plain"));
    for command in [
        "shell", "scan", "findings", "config", "modules", "tools", "doctor", "run",
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
fn plain_flag_forces_line_oriented_shell_output() {
    let tmp = tempfile::tempdir().unwrap();
    let out = stdout(
        kuzushi()
            .args(["--plain", "shell", "--target"])
            .arg(tmp.path())
            .output()
            .unwrap(),
    );

    assert!(out.contains("kuzushi shell"));
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

    assert!(out.contains("kuzushi shell"));
    assert!(out.contains("mode:shell"));
    assert_strict_plain("KUZUSHI_SCREEN_READER shell", &out);
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
fn npm_wrapper_help_reaches_the_rust_binary() {
    let output = Command::new("node")
        .current_dir(repo_root())
        .env("KUZUSHI_NATIVE_BIN", env!("CARGO_BIN_EXE_kuzushi"))
        .args(["bin/kuzushi-rs.mjs", "--help"])
        .output()
        .unwrap();
    let out = stdout(output);

    assert!(out.contains("Kuzushi security copilot"));
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
fn legacy_ink_shell_is_reference_only_in_source_cli() {
    let shell_source = fs::read_to_string(repo_root().join("src/cli/commands/shell.ts")).unwrap();

    assert!(shell_source.contains("reference-only"));
    for forbidden in [
        "copilot/shell",
        "startShell",
        "configureAgentRuntime",
        "loadConfig",
        "from \"ink\"",
        "from \"react\"",
    ] {
        assert!(
            !shell_source.contains(forbidden),
            "source CLI shell must not import legacy runtime surface {forbidden}"
        );
    }

    let ui_readme = fs::read_to_string(repo_root().join("src/ui/README.md")).unwrap();
    assert!(ui_readme.contains("reference-only"));
    assert!(ui_readme.contains("crates/kuzushi-tui"));
    assert!(ui_readme.contains("bin/kuzushi-rs.mjs"));

    let migration_status =
        fs::read_to_string(repo_root().join("docs/rust-migration-status.md")).unwrap();
    assert!(migration_status.contains("src/cli.ts shell"));
    assert!(migration_status.contains("fails with a Rust replacement message"));
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
