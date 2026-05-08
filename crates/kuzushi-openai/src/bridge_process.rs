use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::{BridgeRequest, BridgeResponse, NextStepBridgeRequest, NextStepBridgeResponse};

pub(crate) fn run_next_step_bridge(
    command: &[String],
    request: &NextStepBridgeRequest,
) -> Result<NextStepBridgeResponse> {
    run_json_bridge(command, request, "next-step bridge")
}

pub(crate) fn run_bridge(command: &[String], request: &BridgeRequest) -> Result<BridgeResponse> {
    run_json_bridge(command, request, "pi-agent-core bridge")
}

fn run_json_bridge<T, R>(command: &[String], request: &T, label: &str) -> Result<R>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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
    stdin.write_all(&body)?;
    Ok(())
}

pub fn default_bridge_command(source_root: &Path) -> Vec<String> {
    if let Some(path) = locate_bridge_script(source_root) {
        return vec!["node".to_string(), path.display().to_string()];
    }

    vec![
        "node".to_string(),
        "scripts/pi-agent-core-bridge.mjs".to_string(),
    ]
}

/// Resolve the absolute path to `scripts/pi-agent-core-bridge.mjs`.
///
/// Resolution order — first hit wins:
///   1. `KUZUSHI_BRIDGE_PATH` env var (explicit override).
///   2. `<source_root>/scripts/pi-agent-core-bridge.mjs` — works when the
///      caller still has access to the repo root.
///   3. Walk up from `current_exe()` looking for the script. This covers the
///      common case where the user has changed cwd into a target repo before
///      running `kuzushi`, since the binary still knows where it lives.
///
/// Returning `None` lets callers fall back to a relative path (preserves the
/// historical behavior for code that always launches kuzushi from its repo
/// root, including some test setups).
fn locate_bridge_script(source_root: &Path) -> Option<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("KUZUSHI_BRIDGE_PATH") {
        let candidate = std::path::PathBuf::from(path);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    let candidate = source_root.join("scripts").join("pi-agent-core-bridge.mjs");
    if candidate.exists() {
        return Some(candidate);
    }
    bridge_relative_to_exe()
}

fn bridge_relative_to_exe() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?.to_path_buf();
    for _ in 0..6 {
        let candidate = dir.join("scripts").join("pi-agent-core-bridge.mjs");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}
