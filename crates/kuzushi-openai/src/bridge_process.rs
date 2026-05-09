use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{Read, Write};
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

    // Drain bridge stderr on a background thread. Without this, anything
    // node writes to its own stderr stays buffered in the OS pipe until
    // the bridge exits — which makes `KUZUSHI_BRIDGE_VERBOSE=1` and the
    // [mcp:*] tool-call traces invisible during the run. When set, we
    // forward each stderr line to the parent's stderr verbatim; when
    // unset we still drain (otherwise heavy MCP traffic would fill the
    // pipe and stall the child) but throw the bytes away.
    let stderr_thread = child.stderr.take().map(|mut stderr| {
        let verbose = std::env::var("KUZUSHI_BRIDGE_VERBOSE")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match stderr.read(&mut buf) {
                    Ok(0) => return,
                    Ok(n) => {
                        if verbose {
                            let _ = std::io::stderr().write_all(&buf[..n]);
                        }
                    }
                    Err(_) => return,
                }
            }
        })
    });

    write_bridge_request(&mut child, request, label)?;
    let output = child
        .wait_with_output()
        .with_context(|| format!("could not read {label} output"))?;
    if let Some(handle) = stderr_thread {
        let _ = handle.join();
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize)]
    struct EchoRequest {
        marker: String,
    }

    #[derive(Deserialize, Debug)]
    struct EchoResponse {
        ok: bool,
        echoed: Value,
    }

    use serde_json::Value;

    fn fake_bridge_node(script: &str) -> Vec<String> {
        vec!["node".to_string(), "-e".to_string(), script.to_string()]
    }

    #[test]
    fn round_trips_request_and_response() {
        // Tiny node "bridge" that reads one JSON object from stdin and
        // echoes it back wrapped in an `ok:true` envelope.
        let script = r#"
            let buf = "";
            process.stdin.on("data", (d) => { buf += d.toString(); });
            process.stdin.on("end", () => {
                process.stdout.write(JSON.stringify({ ok: true, echoed: JSON.parse(buf) }));
            });
        "#;
        let response: EchoResponse =
            run_json_bridge(&fake_bridge_node(script), &EchoRequest { marker: "abc".into() }, "fake bridge")
                .expect("round-trip succeeded");
        assert!(response.ok);
        assert_eq!(response.echoed["marker"], Value::String("abc".into()));
    }

    #[test]
    fn does_not_deadlock_when_bridge_emits_heavy_stderr() {
        // Without a stderr drain thread, anything past ~64KB on stderr
        // would block the child's writes and we'd hang. Writing 256KB
        // before stdout proves the drain works.
        let script = r#"
            const heavy = "x".repeat(256 * 1024);
            process.stderr.write(heavy);
            let buf = "";
            process.stdin.on("data", (d) => { buf += d.toString(); });
            process.stdin.on("end", () => {
                process.stdout.write(JSON.stringify({ ok: true, echoed: JSON.parse(buf) }));
            });
        "#;
        let response: EchoResponse =
            run_json_bridge(&fake_bridge_node(script), &EchoRequest { marker: "heavy".into() }, "fake bridge heavy")
                .expect("round-trip with heavy stderr succeeded");
        assert!(response.ok);
        assert_eq!(response.echoed["marker"], Value::String("heavy".into()));
    }
}
