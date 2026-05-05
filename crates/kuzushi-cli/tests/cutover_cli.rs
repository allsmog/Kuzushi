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

#[test]
fn rust_cli_help_is_the_documented_primary_surface() {
    let out = stdout(kuzushi().arg("--help").output().unwrap());

    assert!(out.contains("Kuzushi security copilot"));
    assert!(out.contains("Usage: kuzushi"));
    for command in [
        "shell", "scan", "findings", "config", "modules", "tools", "run",
    ] {
        assert!(out.contains(command), "missing command {command} in help");
    }
    for removed in [
        "TypeScript",
        "Ink",
        "doctor",
        "quickstart",
        "preset",
        "sarif",
    ] {
        assert!(
            !out.to_ascii_lowercase()
                .contains(&removed.to_ascii_lowercase()),
            "help should not advertise removed/non-Rust surface {removed:?}:\n{out}"
        );
    }
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
