use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::bridge_payloads::{
    BridgeRequest, BridgeResponse, NextStepBridgeRequest, NextStepBridgeResponse,
};

pub(crate) fn run_next_step_bridge(
    command: &[String],
    request: &NextStepBridgeRequest,
) -> Result<NextStepBridgeResponse> {
    run_json_bridge(command, request, "next-step bridge", &[])
}

pub(crate) fn run_next_step_preflight_bridge(
    command: &[String],
    request: &NextStepBridgeRequest,
) -> Result<NextStepBridgeResponse> {
    run_json_bridge(command, request, "next-step preflight bridge", &[])
}

pub(crate) fn run_bridge(command: &[String], request: &BridgeRequest) -> Result<BridgeResponse> {
    let extra_env = mcp_artifact_env_for_attachments(&request.tool_policy.mcps_attached);
    run_json_bridge(command, request, "pi-agent-core bridge", &extra_env)
}

/// Build `KUZUSHI_MCP_<NAME>_ARTIFACT=<path>` env pairs from the
/// per-call attachment plan. Constants (treesitter) skip — they don't
/// need an artifact env. Server names with `-` are uppercased and
/// translated to `_` so `entry-points` becomes
/// `KUZUSHI_MCP_ENTRY_POINTS_ARTIFACT`.
fn mcp_artifact_env_for_attachments(
    attachments: &[kuzushi_core::McpAttachment],
) -> Vec<(String, String)> {
    attachments
        .iter()
        .filter(|attachment| !attachment.artifact_path.is_empty())
        .map(|attachment| {
            let env = format!(
                "KUZUSHI_MCP_{}_ARTIFACT",
                attachment.name.to_uppercase().replace('-', "_")
            );
            (env, attachment.artifact_path.clone())
        })
        .collect()
}

pub(crate) fn public_bridge_error(message: &str) -> String {
    message
        .replace("auth login openai-codex", "auth login openai")
        .replace("openai-codex", "OpenAI OAuth")
}

fn run_json_bridge<T, R>(
    command: &[String],
    request: &T,
    label: &str,
    extra_env: &[(String, String)],
) -> Result<R>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (env, path) in mcp_binary_env_defaults() {
        cmd.env(env, path);
    }
    for (env, value) in extra_env {
        cmd.env(env, value);
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("could not start {label} {}", command[0]))?;

    write_bridge_request(&mut child, request, label)?;
    let output = child
        .wait_with_output()
        .with_context(|| format!("could not read {label} output"))?;
    if !output.status.success() {
        if !output.stdout.is_empty() {
            if let Ok(response) = serde_json::from_slice::<R>(&output.stdout) {
                return Ok(response);
            }
        }
        anyhow::bail!(
            "{label} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice::<R>(&output.stdout).with_context(|| {
        format!(
            "could not parse {label} JSON: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn write_bridge_request<T: Serialize>(
    child: &mut std::process::Child,
    request: &T,
    label: &str,
) -> Result<()> {
    let stdin = child
        .stdin
        .as_mut()
        .with_context(|| format!("could not open {label} stdin"))?;
    let body =
        serde_json::to_vec(request).with_context(|| format!("could not encode {label} request"))?;
    match stdin.write_all(&body) {
        Ok(()) => Ok(()),
        // `BrokenPipe` here means the bridge subprocess closed its stdin
        // (or exited entirely) before we finished writing the request.
        // That's a *normal* outcome for bridges that decided to short-
        // circuit — e.g. they emit an error JSON and exit 1 without ever
        // reading stdin, which is exactly what
        // `tests::next_step_bridge_surfaces_error_payload` and
        // `tests::bridge_failure_json_is_returned_as_actionable_error`
        // do. Before this carve-out the EPIPE propagated as a raw
        // `broken pipe` IO error with no label, and the tests's
        // assertions failed under parallel load because the unrelated
        // OS error obscured the actual bridge response. Drop EPIPE
        // here and let `wait_with_output` collect the bridge's already-
        // emitted stdout.
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(err).with_context(|| format!("could not write {label} stdin request body")),
    }
}

pub fn default_bridge_command(source_root: &Path) -> Vec<String> {
    if let Some(command) = bridge_command_at(source_root) {
        return command;
    }

    // The caller's cwd (`source_root`) is the natural lookup spot when
    // kuzushi is invoked from inside the Kuzushi repo. When kuzushi is
    // invoked against an external target the cwd is the *target*, not
    // the Kuzushi tree, so fall back to the script that lives next to
    // the kuzushi executable.
    if let Some(exe_bridge) = bridge_next_to_executable() {
        return vec!["node".to_string(), exe_bridge.display().to_string()];
    }

    vec![
        "node".to_string(),
        "scripts/pi-agent-core-bridge.mjs".to_string(),
    ]
}

fn bridge_command_at(source_root: &Path) -> Option<Vec<String>> {
    let bridge = source_root.join("scripts").join("pi-agent-core-bridge.mjs");
    bridge
        .exists()
        .then(|| vec!["node".to_string(), bridge.display().to_string()])
}

fn bridge_next_to_executable() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    bridge_near_executable(&exe)
}

/// When kuzushi is invoked from `target/debug` or an installed layout, its
/// sibling `kuzushi-mcp-*` binaries are not on `PATH`, so the bridge's
/// `spawn("kuzushi-mcp-treesitter", …)` fails with ENOENT and any tool
/// requesting `toolPolicy.mcps=true` (e.g. `taint-iris-next:hunt`) silently
/// degrades to a no-MCP run before the LLM is ever called. Pre-populate the
/// per-binary `KUZUSHI_MCP_*_BIN` overrides with absolute sibling paths
/// when an operator hasn't already set them, so the bridge picks the
/// matching binary by default.
fn mcp_binary_env_defaults() -> Vec<(&'static str, PathBuf)> {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(_) => return Vec::new(),
    };
    let Some(dir) = exe.parent() else {
        return Vec::new();
    };
    const CANDIDATES: &[(&str, &str)] = &[
        ("KUZUSHI_MCP_TREESITTER_BIN", "kuzushi-mcp-treesitter"),
        ("KUZUSHI_MCP_JOERN_BIN", "kuzushi-mcp-joern"),
        ("KUZUSHI_MCP_CODEQL_BIN", "kuzushi-mcp-codeql"),
        ("KUZUSHI_MCP_CLANG_BIN", "kuzushi-mcp-clang"),
        ("KUZUSHI_MCP_GTAGS_BIN", "kuzushi-mcp-gtags"),
        ("KUZUSHI_MCP_REVNG_BIN", "kuzushi-mcp-revng"),
        ("KUZUSHI_MCP_CONTEXT_BIN", "kuzushi-mcp-context"),
        ("KUZUSHI_MCP_ENTRY_POINTS_BIN", "kuzushi-mcp-entry-points"),
        ("KUZUSHI_MCP_THREAT_MODEL_BIN", "kuzushi-mcp-threat-model"),
        ("KUZUSHI_MCP_THREAT_INTEL_BIN", "kuzushi-mcp-threat-intel"),
        ("KUZUSHI_MCP_X_RAY_BIN", "kuzushi-mcp-x-ray"),
    ];
    CANDIDATES
        .iter()
        .filter_map(|(env_var, binary_name)| {
            if std::env::var_os(env_var).is_some() {
                return None;
            }
            let candidate = dir.join(binary_name);
            candidate.is_file().then_some((*env_var, candidate))
        })
        .collect()
}

fn bridge_near_executable(exe: &Path) -> Option<PathBuf> {
    // Walk up to 6 ancestors so we cover the layouts kuzushi ships in:
    //   target/release/kuzushi          -> ../../scripts/...   (2 hops)
    //   target/debug/kuzushi            -> ../../scripts/...   (2 hops)
    //   native/<plat>-<arch>/kuzushi    -> ../../scripts/...   (2 hops)
    //   bin/kuzushi (npm package)       -> ../scripts/...      (1 hop)
    //   share/kuzushi/bin/kuzushi       -> ../../scripts/...   (2 hops)
    // 6 keeps the search bounded and well clear of `/`.
    let mut dir = exe.parent();
    for _ in 0..6 {
        let Some(parent) = dir else { return None };
        let candidate = parent.join("scripts").join("pi-agent-core-bridge.mjs");
        if candidate.exists() {
            return Some(candidate);
        }
        dir = parent.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{bridge_near_executable, default_bridge_command, public_bridge_error};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn default_bridge_command_finds_bridge_in_source_root() {
        let tmp = tempdir().unwrap();
        let scripts = tmp.path().join("scripts");
        fs::create_dir_all(&scripts).unwrap();
        let bridge = scripts.join("pi-agent-core-bridge.mjs");
        fs::write(&bridge, "/* test */").unwrap();

        let cmd = default_bridge_command(tmp.path());
        assert_eq!(cmd[0], "node");
        assert_eq!(cmd[1], bridge.display().to_string());
    }

    #[test]
    fn bridge_near_executable_walks_up_to_find_scripts_dir() {
        let tmp = tempdir().unwrap();
        let release = tmp.path().join("target").join("release");
        fs::create_dir_all(&release).unwrap();
        let exe = release.join("kuzushi");
        fs::write(&exe, b"#!/bin/sh\n").unwrap();
        let scripts = tmp.path().join("scripts");
        fs::create_dir_all(&scripts).unwrap();
        let bridge = scripts.join("pi-agent-core-bridge.mjs");
        fs::write(&bridge, "/* test */").unwrap();

        let resolved = bridge_near_executable(&exe).expect("walks up to <root>/scripts");
        assert_eq!(resolved, bridge);
    }

    #[test]
    fn bridge_near_executable_returns_none_when_absent() {
        let tmp = tempdir().unwrap();
        let exe = tmp.path().join("kuzushi");
        fs::write(&exe, b"#!/bin/sh\n").unwrap();
        assert!(bridge_near_executable(&exe).is_none());
    }

    #[test]
    fn mcp_binary_env_defaults_finds_sibling_mcp_binaries() {
        use super::mcp_binary_env_defaults;
        // Sanity-check against the real test-runner's executable directory:
        // since both kuzushi-mcp-* and the test binary live under
        // target/<profile>/, mcp_binary_env_defaults() should return paths
        // for whichever sibling binaries are present.
        let exe = std::env::current_exe().expect("test exe");
        let dir = exe.parent().expect("test exe has parent");
        // Materialise a fake sibling so the test asserts the path-shape
        // logic even on machines that haven't built every MCP server.
        let fake = dir.join("kuzushi-mcp-treesitter-test-fake");
        std::fs::write(&fake, b"#!/bin/sh\n").ok();

        // Override env to remove any inherited setting so the helper's
        // skip-if-already-set logic is exercised.
        // SAFETY: tests are single-threaded for this var; we restore after.
        let prior = std::env::var_os("KUZUSHI_MCP_TREESITTER_BIN");
        // SAFETY: the helper only reads env, and we restore after the assertion.
        unsafe {
            std::env::remove_var("KUZUSHI_MCP_TREESITTER_BIN");
        }

        let defaults = mcp_binary_env_defaults();

        // Find at least one entry pointing into the executable directory
        // (we don't pin a specific name because which sibling MCPs are
        // built varies by machine; the fake one we materialised guarantees
        // at least the "shape" test passes).
        assert!(
            defaults.iter().all(|(_, path)| path.parent() == Some(dir)),
            "every default path must be a sibling of the test exe: {defaults:?}"
        );

        // Skip-if-set: set the env var and confirm the entry disappears.
        unsafe {
            std::env::set_var("KUZUSHI_MCP_TREESITTER_BIN", "/operator/override");
        }
        let with_override = mcp_binary_env_defaults();
        assert!(
            with_override
                .iter()
                .all(|(env_var, _)| *env_var != "KUZUSHI_MCP_TREESITTER_BIN"),
            "operator override should win: {with_override:?}"
        );

        // Restore prior env so we don't leak state.
        unsafe {
            match prior {
                Some(v) => std::env::set_var("KUZUSHI_MCP_TREESITTER_BIN", v),
                None => std::env::remove_var("KUZUSHI_MCP_TREESITTER_BIN"),
            }
        }
        let _ = std::fs::remove_file(&fake);
    }

    #[test]
    fn public_bridge_error_rewrites_internal_provider_tokens() {
        let error = "next-step: no OpenAI credentials for openai-codex. Set up kuzushi auth login openai-codex";

        let public = public_bridge_error(error);

        assert!(public.contains("OpenAI OAuth"));
        assert!(public.contains("kuzushi auth login openai"));
        assert!(!public.contains("openai-codex"));
    }
}
